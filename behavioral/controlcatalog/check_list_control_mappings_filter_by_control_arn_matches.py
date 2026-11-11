"""list-control-mappings-filter-by-control-arn-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-control-mappings-filter-by-control-arn-matches"
GROUP = "filtering"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListControlMappings filtered by a control ARN returns only mappings for that control."""
    cc = ctx.client("controlcatalog")
    baseline = cc.list_control_mappings(MaxResults=50)
    mappings = baseline.get("ControlMappings", [])
    assert mappings, "ListControlMappings returned no mappings"
    control_arn = mappings[0]["ControlArn"]

    filtered = cc.list_control_mappings(Filter={"ControlArns": [control_arn]}, MaxResults=100)
    filtered_mappings = filtered.get("ControlMappings", [])
    assert filtered_mappings, f"filtering ListControlMappings by {control_arn} returned no mappings"
    for m in filtered_mappings:
        assert m["ControlArn"] == control_arn, (
            f"expected ControlArn {control_arn}, got {m['ControlArn']} in filtered result"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
