"""Report renderer tests."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import json

from glinet_profiler.enumerator.models import DeviceReport, MethodReport, ProbeStatus, Risk
from glinet_profiler.enumerator.report import summary_lines, to_json, to_markdown


def _report():
    return DeviceReport(
        device={"model": "GL-MT6000", "firmware_version": "4.8.0"},
        methods=[
            MethodReport(
                "system",
                "get_info",
                ProbeStatus.AVAILABLE,
                None,
                Risk.READ,
                "catalog",
                None,
                {"model": "str"},
                {"model": "GL-MT6000"},
                "router_info",
            ),
            MethodReport(
                "firewall",
                "get_rule_list",
                ProbeStatus.AVAILABLE,
                None,
                Risk.READ,
                "catalog",
                None,
                {"res": "list"},
                {"res": []},
                None,
            ),
            MethodReport(
                "modem",
                "get_info",
                ProbeStatus.ABSENT,
                -32601,
                Risk.READ,
                "catalog",
                None,
                None,
                None,
                None,
            ),
        ],
    )


def test_to_json_round_trips_and_nests_by_service():
    data = json.loads(to_json(_report()))
    assert data["device"]["model"] == "GL-MT6000"
    assert data["services"]["firewall"]["get_rule_list"]["status"] == "available"
    assert data["services"]["system"]["get_info"]["covered_by"] == "router_info"


def test_markdown_has_header_and_not_wrapped_section():
    md = to_markdown(_report())
    assert "GL-MT6000" in md
    assert "not yet wrapped" in md.lower()
    assert "firewall" in md and "get_rule_list" in md  # available + uncovered -> listed


def test_summary_counts():
    lines = summary_lines(_report())
    text = "\n".join(lines)
    assert "available" in text.lower()
    assert "firewall.get_rule_list" in text  # the uncovered available one
