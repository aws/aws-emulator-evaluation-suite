"""list-partners-and-connections-smoke."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "list-partners-and-connections-smoke"
GROUP = "control-plane"
SERVICES = ["partnercentral-account"]

_PARTNER_ID_RE = re.compile(r"^partner-[A-Za-z0-9]{13}$")
_CONNECTION_ID_RE = re.compile(r"^pac-[A-Za-z0-9]{13}$")


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the runner's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPartners and ListConnections return well-formed collections for the account's AWS
    catalog: correct top-level keys, and any returned summary's identifier matches the
    service's own ID format."""
    pca = _pca_client(ctx)

    partners = pca.list_partners(Catalog="AWS")
    assert "PartnerSummaryList" in partners, f"expected PartnerSummaryList key, got keys {list(partners)}"
    for summary in partners["PartnerSummaryList"]:
        assert _PARTNER_ID_RE.match(summary["Id"]), summary["Id"]
        assert summary["Catalog"] == "AWS", f"expected Catalog 'AWS', got {summary['Catalog']!r}"

    connections = pca.list_connections(Catalog="AWS")
    assert "ConnectionSummaries" in connections, f"expected ConnectionSummaries key, got keys {list(connections)}"
    for summary in connections["ConnectionSummaries"]:
        assert _CONNECTION_ID_RE.match(summary["Id"]), summary["Id"]
        assert summary["Catalog"] == "AWS", f"expected Catalog 'AWS', got {summary['Catalog']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

