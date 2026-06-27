"""Data models for the enumerator."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Risk(StrEnum):
    """A priori risk of calling a method."""

    READ = "read"
    WRITE = "write"
    DANGEROUS = "dangerous"
    ACTIVE = "active"


class ProbeStatus(StrEnum):
    """Outcome of probing one (service, method)."""

    AVAILABLE = "available"
    # found in the device's own RPC/validator files via SSH; not HTTP-called
    DISCOVERED = "discovered"
    ABSENT = "absent"
    NEEDS_PARAMS = "needs_params"
    AUTH_ERROR = "auth_error"
    TOKEN_ERROR = "token_error"
    OTHER = "other"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True)
class ProbeResult:
    """Classification of a single probe envelope."""

    status: ProbeStatus
    error_code: int | None = None
    message: str | None = None


@dataclass
class MethodReport:
    """One probed (service, method) with its outcome."""

    service: str
    method: str
    status: ProbeStatus
    error_code: int | None
    risk: Risk
    discovered_by: str
    params: list[str] | None
    schema: object
    value: object
    covered_by: str | None


@dataclass
class DeviceReport:
    """Full per-device enumeration."""

    device: dict[str, Any]
    methods: list[MethodReport]


@dataclass
class SshSurface:
    """What SSH ground-truth recon found on a device."""

    services: list[str] = field(default_factory=list)
    methods: dict[str, list[str]] = field(default_factory=dict)
    params: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    accounts: list[dict[str, str]] = field(default_factory=list)
    features: list[str] = field(default_factory=list)
    ubus: list[str] = field(default_factory=list)
    no_auth: dict[str, list[str]] = field(default_factory=dict)


Caller = Callable[[str, str, "dict[str, Any] | None"], Awaitable["dict[str, Any]"]]
