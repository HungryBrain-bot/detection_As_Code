# Future: question answering over the attack docs (RAG), with evaluation

Status: parked, design note only. Not built and not scheduled. Requested
by the owner on 2026-10-27 as a future item to showcase a retrieval-
augmented generation (RAG) system with its own evaluation.

## Idea
Ask questions in plain language about attacks and tactics ("how does a
SAM hive dump work?", "which rules cover credential access?") from a
CLI or a FastAPI endpoint, answered from this repo's own docs. Later,
the same for the rules each customer has, from `customers/<id>/` and
the coverage output.

## Scope, if it is built
- Corpus: `detections/**/attack.md` first; later each rule's `README.md`,
  `rule.yaml` metadata, and per-customer applicability and gate status.
- Every answer cites the doc (path and section) it came from. An answer
  with no retrieved source is refused, not guessed.
- Interfaces: a CLI command and a FastAPI endpoint over the same
  retrieval and answer functions.
- Evaluation defined before any code: a small fixed question set with
  the expected source docs, measuring retrieval hit rate (did the right
  doc come back) and groundedness (is every claim in the answer in the
  retrieved text). Results recorded like engine evidence: date, model,
  counts.

## Dependency
Only worth building once enough attack docs and rules exist to make
retrieval non-trivial. With four attack docs (A1-A4) a keyword search
answers most questions; revisit after the identity and LLM tracks
(B1-C3) are built.

## Not decided
Embedding model, vector store, LLM provider, and whether per-customer
questions need access control between customers.
