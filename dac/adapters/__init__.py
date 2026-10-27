"""SIEM adapters, keyed by the name used in rule.yaml and log_sources.yaml."""

from .base import DeployError, MissingCredentials, Request, Response, SiemAdapter, Transport
from .secops import SecOpsAdapter
from .sentinel import SentinelAdapter
from .splunk import SplunkAdapter

ADAPTERS: dict[str, type[SiemAdapter]] = {
    "sentinel": SentinelAdapter,
    "splunk": SplunkAdapter,
    "secops": SecOpsAdapter,
}


def get_adapter(name: str, **kwargs) -> SiemAdapter:
    try:
        return ADAPTERS[name](**kwargs)
    except KeyError:
        raise ValueError(f"unknown SIEM {name!r}; known: {', '.join(ADAPTERS)}") from None


__all__ = ["ADAPTERS", "get_adapter", "SiemAdapter", "Transport", "Request", "Response",
           "MissingCredentials", "DeployError"]
