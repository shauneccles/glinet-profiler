"""Structural smoke checks for the launcher UI."""
# pylint: disable=missing-function-docstring

from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "src" / "glinet_profiler" / "web"


def test_index_has_form_controls():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    for needle in (
        'id="form"',
        'id="host"',
        'id="username"',
        'id="password"',
        'id="ssh"',
        'id="dangerous"',
        'id="destructive"',
        'id="status"',
        'id="result"',
        'id="banner"',
        'id="actions"',
        'id="download"',
        'id="submit"',
        'id="progress"',
        'id="progress-msg"',
        'id="progress-count"',
        "app.js",
        "style.css",
    ):
        assert needle in html, needle


def test_app_js_uses_token_and_endpoint():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert "api/enumerate" in js
    assert "X-Profiler-Token" in js
    assert "submit_url" in js  # opens the server-built prefilled issue URL


def test_app_js_streams_progress():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert "getReader" in js  # reads the NDJSON stream incrementally
    assert "setProgress" in js  # updates the live progress panel
    assert '"progress"' in js or "'progress'" in js  # handles progress events


def test_app_js_sends_danger_flags_with_confirm():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert "dangerous:" in js and "include_destructive:" in js  # POSTed to the server
    assert "confirm(" in js  # a destructive/dangerous run is confirmed first
