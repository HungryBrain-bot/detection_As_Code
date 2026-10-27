"""Turn the open LLM datasets into LLMAppLog_CL rows (ADR 008).

No public dataset of recorded LLM-application logs exists, in any
format. What exists are research datasets of prompts, attack texts and
recorded agent runs. Each converter below rebuilds them as the rows an
app instrumented with OpenTelemetry GenAI spans would have produced
(llm_log_inventory.yaml, source otel-genai), so the rules' queries run
on real text. What is real and what is written here:

- jailbreakhub-csv (verazuo/jailbreak_llms, "Do Anything Now", CCS 2024):
  prompts people shared on Reddit, Discord and prompt sites, labelled
  jailbreak or regular by the authors. Real text; never sent through an
  app we observed. One `chat` row per prompt: InputText is the prompt,
  OutputText is empty (no model answer is in the data), time from
  created_at, else date, else BASE_TIME (218 rows have neither).
- agentdojo-run (ethz-spylab/agentdojo): recorded benchmark runs, a real
  model (here claude-3-7-sonnet-20250219) calling simulated tools, with
  and without prompt injections planted in tool data. Real model and
  tool messages; the tools and their data are simulated. One `chat` row
  per user turn and per assistant turn, one `execute_tool` row per tool
  call (InputText = arguments the model chose, OutputText = the tool's
  result, matched by tool_call_id). The runs carry no timestamps: each
  run starts at BASE_TIME plus 10 minutes per run (in file order) and
  each message is one second after the previous one. Synthetic.
- bipia-email (microsoft/BIPIA): BIPIA's attack texts and email contexts,
  combined here by appending an attack text to the end of an email
  (BIPIA's own prompt builder was not run). One `retrieval` row per
  email (OutputText = the email), for every clean email and for each
  attack text inserted into one email (attack i into email i mod 50).
  Constructed, not recorded.

ConversationId starts with `<dataset>:<label>:` so the harness can score
matches per label (tests/datasets.yaml `score_by`). The label is the
dataset's own ground truth, except for AgentDojo, where a run with an
attack counts as `injected` only if the injection text actually
appears in a tool result of that run (otherwise `injection-not-reached`:
the model never called the tool that carries it).
"""

import csv
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

TABLE = "LLMAppLog_CL"
BASE_TIME = datetime(2026, 10, 20, tzinfo=timezone.utc)
FORMATS = ("jailbreakhub-csv", "agentdojo-run", "bipia-email")


def _row(**values) -> dict:
    row = {"Type": TABLE, "LogSource": "otel-genai"}
    row.update({k: v for k, v in values.items() if v is not None})
    return row


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def jailbreakhub(folder: Path) -> list[dict]:
    csv.field_size_limit(1 << 30)
    rows = []
    for path in sorted(folder.glob("*.csv")):
        with open(path, encoding="utf-8", newline="") as fh:
            for index, record in enumerate(csv.DictReader(fh)):
                label = "jailbreak" if record["jailbreak"] == "True" else "regular"
                if record.get("created_at"):
                    when = datetime.fromisoformat(record["created_at"])
                elif record.get("date"):
                    when = datetime.fromisoformat(f"{record['date']}T00:00:00+00:00")
                else:
                    when = BASE_TIME  # 218 awesome-chatgpt-prompts rows carry no date
                rows.append(_row(
                    TimeGenerated=_iso(when),
                    AppName=f"jailbreakhub-{record['platform']}",
                    OperationName="chat",
                    ConversationId=f"jailbreakhub:{label}:{path.stem}:{index}",
                    InputText=record["prompt"],
                    OutputText="",
                ))
    return rows


def _collapse(text: str) -> str:
    """Whitespace collapsed and quote marks dropped: tool results are YAML, which re-wraps
    lines and doubles apostrophes ("user''s") in quoted strings."""
    return re.sub(r"\s+", " ", re.sub(r"['\"]", "", text or "")).strip()


def _injection_reached(run: dict) -> bool:
    """Does any tool result contain (a 60-character middle part of) an injection text?"""
    results = [_collapse(m.get("content") or "") for m in run["messages"] if m["role"] == "tool"]
    for text in (run.get("injections") or {}).values():
        text = _collapse(text)
        probe = text[len(text) // 2 - 30: len(text) // 2 + 30] if len(text) > 60 else text
        if any(probe in result for result in results):
            return True
    return False


def agentdojo(folder: Path) -> list[dict]:
    rows = []
    for run_index, path in enumerate(sorted(folder.glob("*.json"))):
        run = json.loads(path.read_text(encoding="utf-8"))
        if run.get("attack_type") in (None, "none"):
            label = "benign"
        else:
            label = "injected" if _injection_reached(run) else "injection-not-reached"
        conversation = (f"agentdojo:{label}:{run['suite_name']}/{run['user_task_id']}/"
                        f"{run.get('attack_type') or 'none'}/{run.get('injection_task_id') or 'none'}")
        start = BASE_TIME + timedelta(minutes=10 * run_index)
        common = {"AppName": f"agentdojo-{run['suite_name']}", "AgentName": run["pipeline_name"],
                  "ProviderName": "anthropic", "RequestModel": run["pipeline_name"],
                  "ConversationId": conversation}
        tool_rows = {}
        for step, message in enumerate(run["messages"]):
            when = _iso(start + timedelta(seconds=step))
            role = message["role"]
            if role == "user":
                rows.append(_row(TimeGenerated=when, OperationName="chat", InputText=message["content"],
                                 OutputText="", **common))
            elif role == "assistant":
                rows.append(_row(TimeGenerated=when, OperationName="chat", InputText="",
                                 OutputText=message.get("content") or "", **common))
                for call in message.get("tool_calls") or []:
                    row = _row(TimeGenerated=when, OperationName="execute_tool", ToolName=call["function"],
                               ToolCallId=call["id"], ToolType="function",
                               InputText=json.dumps(call.get("args") or {}, sort_keys=True), OutputText="",
                               **common)
                    tool_rows[call["id"]] = row
                    rows.append(row)
            elif role == "tool":
                row = tool_rows.get(message.get("tool_call_id"))
                if row is not None:
                    row["OutputText"] = message.get("content") or ""
                    if message.get("error"):
                        row["ErrorType"] = "tool_error"
    return rows


def bipia(folder: Path) -> list[dict]:
    attacks_file = next(folder.glob("*text_attack_test.json"))
    emails_file = next(folder.glob("*test.jsonl"))
    attacks = [(category, i, text) for category, texts in json.loads(attacks_file.read_text(encoding="utf-8")).items()
               for i, text in enumerate(texts)]
    emails = [json.loads(line)["context"] for line in emails_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = []
    for j, email in enumerate(emails):
        rows.append(_row(TimeGenerated=_iso(BASE_TIME + timedelta(seconds=j)), AppName="bipia-email-qa",
                         OperationName="retrieval", ConversationId=f"bipia:clean:{j}", InputText="",
                         OutputText=email))
    for n, (category, i, text) in enumerate(attacks):
        slug = re.sub(r"[^a-z]+", "-", category.lower()).strip("-")
        rows.append(_row(TimeGenerated=_iso(BASE_TIME + timedelta(minutes=5, seconds=n)), AppName="bipia-email-qa",
                         OperationName="retrieval", ConversationId=f"bipia:injected:{slug}-{i}",
                         InputText="", OutputText=f"{emails[n % len(emails)]}\n{text}"))
    return rows


CONVERTERS = {"jailbreakhub-csv": jailbreakhub, "agentdojo-run": agentdojo, "bipia-email": bipia}


def convert(fmt: str, folder: Path) -> list[dict]:
    return CONVERTERS[fmt](folder)
