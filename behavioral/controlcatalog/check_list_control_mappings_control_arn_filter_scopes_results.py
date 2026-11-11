"""list-control-mappings-control-arn-filter-scopes-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-control-mappings-control-arn-filter-scopes-results"
GROUP = "filtering"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ControlMappingFilter.ControlArns narrows ListControlMappings to only mappings for that control."""
    cc = ctx.client("controlcatalog")

    unfiltered = cc.list_control_mappings(MaxResults=50).get("ControlMappings", [])
    assert unfiltered, "expected at least one control mapping in the catalog"
    target_control_arn = unfiltered[0]["ControlArn"]

    filtered = cc.list_control_mappings(
        MaxResults=1000, Filter={"ControlArns": [target_control_arn]}
    ).get("ControlMappings", [])
    assert filtered, f"expected at least one mapping for control {target_control_arn}"

    for mapping in filtered:
        assert mapping["ControlArn"] == target_control_arn, (
            f"filtered mapping had ControlArn {mapping['ControlArn']!r}, expected {target_control_arn!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
