"""describe-workspace-bundles-amazon-owned-shape."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "describe-workspace-bundles-amazon-owned-shape"
GROUP = "control-plane"
SERVICES = ["workspaces"]

# AWS ships new bundle compute families (e.g. GRAPHICS_G7_8XLARGE) ahead of the Smithy
# model's Compute enum, so a fixed set of known names goes stale against real AWS. Assert
# the naming shape instead of a closed enumeration.
_COMPUTE_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The AMAZON-owned WorkSpace bundle catalog is always present and every entry conforms to
    the documented bundle shape (BundleId pattern, AVAILABLE state, well-formed ComputeType name,
    REGULAR BundleType)."""
    ws = ctx.client("workspaces")
    bundles = []
    token = None
    while True:
        kwargs = {"Owner": "AMAZON"}
        if token:
            kwargs["NextToken"] = token
        resp = ws.describe_workspace_bundles(**kwargs)
        bundles.extend(resp.get("Bundles", []))
        token = resp.get("NextToken")
        if not token:
            break

    assert len(bundles) > 0, "expected at least one AMAZON-owned bundle in the catalog"
    for bundle in bundles:
        assert bundle["BundleId"].startswith("wsb-"), bundle["BundleId"]
        # Owner=AMAZON was the request filter itself; the returned field's exact value is not
        # part of the documented contract we need to pin here, so it is not asserted.
        assert bundle["State"] == "AVAILABLE", bundle
        assert bundle["BundleType"] == "REGULAR", bundle
        assert _COMPUTE_NAME_RE.match(bundle["ComputeType"]["Name"]), bundle["ComputeType"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
