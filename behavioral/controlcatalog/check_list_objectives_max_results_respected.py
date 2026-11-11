"""list-objectives-max-results-respected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-objectives-max-results-respected"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListObjectives never returns more items than the requested MaxResults."""
    cc = ctx.client("controlcatalog")

    page = cc.list_objectives(MaxResults=2)
    objectives = page["Objectives"]
    # The catalog has far more than 2 objectives, so a bounded first page must be exactly full,
    # not merely within bound — a target that silently returns fewer (or zero) must not pass.
    assert len(objectives) == 2, f"expected exactly 2 objectives in a MaxResults=2 page, got {len(objectives)}"
    assert page.get("NextToken"), "expected a NextToken when more results exist beyond a MaxResults=2 page"

    larger_page = cc.list_objectives(MaxResults=100)
    larger_objectives = larger_page["Objectives"]
    assert len(larger_objectives) <= 100, (
        f"MaxResults=100 must never be exceeded, got {len(larger_objectives)}"
    )
    assert len(larger_objectives) >= len(objectives), (
        f"a MaxResults=100 page ({len(larger_objectives)}) must return at least as many objectives "
        f"as a MaxResults=2 page ({len(objectives)})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
