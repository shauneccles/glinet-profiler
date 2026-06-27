"""Catalog integrity + verb helpers + coverage."""
# pylint: disable=missing-function-docstring,redefined-outer-name

from glinet_profiler.enumerator.catalog import (
    CATALOG,
    DESTRUCTIVE_METHODS,
    MUTATING_VERBS,
    is_read_method,
    risk_of,
)
from glinet_profiler.enumerator.coverage import covered_by
from glinet_profiler.enumerator.models import Risk


def test_catalog_nonempty_and_well_typed():
    assert len(CATALOG) >= 30
    for service, methods in CATALOG.items():
        assert service and isinstance(methods, dict) and methods
        for method, risk in methods.items():
            assert isinstance(risk, Risk), f"{service}.{method} not a Risk"


def test_no_read_tagged_method_is_actually_mutating():
    for service, methods in CATALOG.items():
        for method, risk in methods.items():
            if risk is Risk.READ:
                assert is_read_method(method), f"{service}.{method} tagged READ but looks mutating"


def test_known_services_present():
    for s in ("system", "wifi", "clients", "firewall", "wg-server", "flow_statistics", "tor"):
        assert s in CATALOG


def test_is_read_method():
    assert is_read_method("get_config")
    assert is_read_method("check_config")
    assert not is_read_method("set_config")
    assert not is_read_method("start")
    assert not is_read_method("reboot")


def test_risk_of():
    assert risk_of("get_status") is Risk.READ
    assert risk_of("set_config") is Risk.WRITE
    assert risk_of("reboot") is Risk.DANGEROUS
    assert "reboot" in DESTRUCTIVE_METHODS
    assert "set_config" in set(MUTATING_VERBS) or risk_of("set_config") is Risk.WRITE


def test_coverage_lookup():
    assert covered_by("system", "get_info") == "router_info"
    assert covered_by("clients", "get_list") == "list_all_clients"
    assert covered_by("nonexistent", "get_x") is None


def test_multiword_and_noun_reads_are_read():
    for s, m in (
        ("system", "disk_info"),
        ("network", "routes"),
        ("network", "routes6"),
        ("ui", "load_locales"),
    ):
        assert is_read_method(m), f"{s}.{m} should be a read"
        assert CATALOG[s][m] is Risk.READ
    # mutating first-token methods are still not reads despite a read word later
    assert not is_read_method("set_info")
    assert not is_read_method("clear_statistics")
