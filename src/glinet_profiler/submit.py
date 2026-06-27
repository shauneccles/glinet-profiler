"""Build the 'submit a profile' URL pointing at the registry's issue form."""

import urllib.parse
from typing import Any

# The registry repo that receives profile submissions (update on extraction).
REGISTRY_REPO = "shauneccles/glinet-profiler"


def prefilled_issue_url(profile: dict[str, Any], *, repo: str = REGISTRY_REPO) -> str:
    """Return the issue-form URL (auto-labels + has the attachment field); prefills the title."""
    model = profile.get("model", "unknown")
    firmware = profile.get("firmware_version", "unknown")
    query = urllib.parse.urlencode(
        {"template": "profile-submission.yml", "title": f"Add profile: {model} ({firmware})"}
    )
    return f"https://github.com/{repo}/issues/new?{query}"
