"""SSH ground-truth discovery: pure parsers + paramiko I/O."""

import asyncio
import re
import shlex

import paramiko

from .catalog import is_read_method
from .models import SshSurface

_LUA_FUNC = re.compile(r"function\s+M\.([A-Za-z0-9_]+)")
_LUA_ASSIGN = re.compile(r"M\.([A-Za-z0-9_]+)\s*=\s*function")
# .so/bytecode `strings` yield noise-tolerant method-name CANDIDATES; internal
# helpers (e.g. `check_string_length`) that aren't real RPC methods are filtered
# downstream by the HTTP probe (they classify ABSENT).  `check_` is kept because
# `check_config` is a real method on several services (wg-client, ovpn-client).
_VERB_PREFIXES = (
    "get_",
    "set_",
    "add_",
    "remove_",
    "del_",
    "list_",
    "check_",
    "start",
    "stop",
    "generate_",
    "export_",
    "clear_",
    "connect",
    "disconnect",
    "scan",
    "status",
    "info",
    "dump",
)
_VALIDATOR_ENTRY = re.compile(r'\[\s*["\']([A-Za-z0-9_]+)["\']\s*\]\s*=\s*\{([^}]*)\}')
_PARAM = re.compile(r'["\']([A-Za-z0-9_]+)["\']')


def _canonical_service(name: str) -> str:
    """The wire service name is the handler filename minus any .so suffix."""
    return name[:-3] if name.endswith(".so") else name


def _looks_like_method(token: str) -> bool:
    return any(token.startswith(p) for p in _VERB_PREFIXES)


def parse_handlers(listing: list[str], sources: dict[str, str]) -> dict[str, list[str]]:
    """Extract service -> method candidates from handler dir + source/strings."""
    out: dict[str, set[str]] = {}
    for name in listing:
        if name.endswith(".lua"):
            continue
        service = _canonical_service(name)
        text = sources.get(name, "")
        methods = set(_LUA_FUNC.findall(text)) | set(_LUA_ASSIGN.findall(text))
        if not methods:  # .so / bytecode strings dump
            methods = {t for t in text.split() if _looks_like_method(t)}
        out.setdefault(service, set()).update(methods)
    return {s: sorted(m) for s, m in out.items() if m}


def parse_validators(sources: dict[str, str]) -> dict[str, dict[str, list[str]]]:
    """Extract service -> {method: [params]} from gl-validator.d files."""
    out: dict[str, dict[str, list[str]]] = {}
    for service, text in sources.items():
        methods: dict[str, list[str]] = {}
        for method, body in _VALIDATOR_ENTRY.findall(text):
            methods[method] = _PARAM.findall(body)
        if methods:
            out[service] = methods
    return out


def parse_account_acl(rows: list[tuple[str, str]]) -> tuple[list[dict[str, str]], bool]:
    """Accounts + whether a root-acl account exists (=> full access)."""
    accounts = [{"username": u, "acl": a} for u, a in rows]
    root_full = any(a == "root" for _u, a in rows)
    return accounts, root_full


REMOTE_RECON = r"""
echo '@@HANDLERS@@'; ls -1 /usr/lib/oui-httpd/rpc/ 2>/dev/null
echo '@@UBUS@@'; ubus list 2>/dev/null
echo '@@ACCOUNTS@@'; sqlite3 /etc/oui/oui.db 'SELECT username||"|"||acl FROM account;' 2>/dev/null
echo '@@FEATURES@@'; ls -1 /usr/share/oui/menu.d/ 2>/dev/null | sed 's/.json$//'
echo '@@END@@'
"""


class SshUnavailable(RuntimeError):
    """SSH could not be used (unreachable, auth failed, or paramiko missing)."""


def _section(blob: str, tag: str) -> list[str]:
    body = blob.split(f"@@{tag}@@", 1)
    if len(body) < 2:
        return []
    rest = body[1]
    rest = re.split(r"@@[A-Z]+@@", rest, maxsplit=1)[0]
    return [ln.strip() for ln in rest.splitlines() if ln.strip()]


async def ssh_discover(  # pylint: disable=too-many-arguments,too-many-locals
    host: str,
    *,
    username: str = "root",
    password: str | None = None,
    key_filename: str | None = None,
    port: int = 22,
    timeout: float = 12.0,
) -> SshSurface:
    """Read-only SSH recon -> SshSurface. Raises SshUnavailable on failure."""

    def _run() -> tuple[str, dict[str, str], dict[str, str]]:  # pylint: disable=too-many-locals
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=timeout,
                look_for_keys=bool(key_filename),
                allow_agent=False,
            )
        except Exception as exc:  # pylint: disable=broad-except
            raise SshUnavailable(f"SSH connect failed: {type(exc).__name__}: {exc}") from exc
        try:
            _in, out, _err = client.exec_command(REMOTE_RECON, timeout=timeout)
            recon = out.read().decode(errors="replace")
            handler_names = _section(recon, "HANDLERS")
            handler_sources: dict[str, str] = {}
            for name in handler_names:
                qpath = shlex.quote(f"/usr/lib/oui-httpd/rpc/{name}")
                cmd = (
                    f"if grep -q 'function M\\.' {qpath} 2>/dev/null;"
                    f" then cat {qpath};"
                    f" else strings {qpath} 2>/dev/null; fi"
                )
                _i, o, _e = client.exec_command(cmd, timeout=timeout)
                handler_sources[name] = o.read().decode(errors="replace")
            validator_sources: dict[str, str] = {}
            _i, vo, _e = client.exec_command(
                "ls -1 /usr/share/gl-validator.d/ 2>/dev/null", timeout=timeout
            )
            for vf in [
                x.strip() for x in vo.read().decode(errors="replace").splitlines() if x.strip()
            ]:
                _i2, vc, _e2 = client.exec_command(
                    f"cat {shlex.quote(f'/usr/share/gl-validator.d/{vf}')}", timeout=timeout
                )
                validator_sources[vf[:-4] if vf.endswith(".lua") else vf] = vc.read().decode(
                    errors="replace"
                )
            return recon, handler_sources, validator_sources
        finally:
            client.close()

    recon, handler_sources, validator_sources = await asyncio.to_thread(_run)

    handlers = parse_handlers(_section(recon, "HANDLERS"), handler_sources)
    validators = parse_validators(validator_sources)
    for service, methods in validators.items():
        handlers.setdefault(service, [])
        handlers[service] = sorted(set(handlers[service]) | set(methods))
    accounts, _root_full = parse_account_acl(
        [tuple(row.split("|", 1)) for row in _section(recon, "ACCOUNTS") if "|" in row]  # type: ignore[misc]
    )
    return SshSurface(
        services=sorted(handlers),
        methods=handlers,
        params=validators,
        accounts=accounts,
        features=_section(recon, "FEATURES"),
        ubus=_section(recon, "UBUS"),
    )


__all__ = [
    "parse_handlers",
    "parse_validators",
    "parse_account_acl",
    "is_read_method",
    "SshUnavailable",
    "ssh_discover",
    "REMOTE_RECON",
]
