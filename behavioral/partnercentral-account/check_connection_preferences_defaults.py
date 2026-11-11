"""connection-preferences-defaults."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "connection-preferences-defaults"
GROUP = "state"
SERVICES = ["partnercentral-account"]

_ACCESS_TYPES = {"ALLOW_ALL", "DENY_ALL", "ALLOW_BY_DEFAULT_DENY_SOME"}
# Real AWS leaves the account-id segment empty: this is an account-implicit control-plane
# singleton addressed by the caller's own credentials, not by a 12-digit account id in the ARN.
_ARN_RE = re.compile(
    r"^arn:[a-zA-Z0-9-]+:partnercentral:[a-z0-9-]*::catalog/[a-zA-Z]+/connection-preferences$"
)


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the runner's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetConnectionPreferences is an account-level singleton that always exists and returns
    a well-formed AccessType/Revision/Arn even for an account with no registered Partner. Two
    independent reads of the same singleton must agree (it must not advance or drift on a read)."""
    pca = _pca_client(ctx)
    resp = pca.get_connection_preferences(Catalog="AWS")

    assert resp["AccessType"] in _ACCESS_TYPES, resp["AccessType"]
    assert isinstance(resp["Revision"], int) and resp["Revision"] >= 0
    assert _ARN_RE.match(resp["Arn"]), resp["Arn"]
    assert resp["Catalog"] == "AWS"
    if "ExcludedParticipantIds" in resp:
        excluded = resp["ExcludedParticipantIds"]
        assert isinstance(excluded, list) and all(isinstance(pid, str) for pid in excluded), excluded

    again = pca.get_connection_preferences(Catalog="AWS")
    assert again["AccessType"] == resp["AccessType"], (again["AccessType"], resp["AccessType"])
    assert again["Revision"] == resp["Revision"], (again["Revision"], resp["Revision"])
    assert again["Arn"] == resp["Arn"], (again["Arn"], resp["Arn"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

