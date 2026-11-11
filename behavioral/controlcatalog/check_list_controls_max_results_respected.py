"""list-controls-max-results-respected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-controls-max-results-respected"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListControls never returns more items than the requested MaxResults, and hands back a NextToken."""
    cc = ctx.client("controlcatalog")

    page = cc.list_controls(MaxResults=3)
    controls = page.get("Controls", [])
    # The catalog has far more than 3 controls, so a bounded first page must be exactly full,
    # not merely within bound — a target that silently returns nothing must not pass.
    assert len(controls) == 3, f"expected exactly 3 controls in a MaxResults=3 page, got {len(controls)}"
    assert page.get("NextToken"), "expected a NextToken when more results exist beyond a MaxResults=3 page"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
