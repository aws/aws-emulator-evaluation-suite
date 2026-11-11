"""list-control-mappings-filter-by-common-control-arn-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-control-mappings-filter-by-common-control-arn-matches"
GROUP = "filtering"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListControlMappings filtered by a common-control ARN returns only mappings pointing to it."""
    cc = ctx.client("controlcatalog")

    common_control_arn = None
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_control_mappings(**kwargs)
        for m in page.get("ControlMappings", []):
            if m["MappingType"] == "COMMON_CONTROL":
                common_control_arn = m["Mapping"]["CommonControl"]["CommonControlArn"]
                break
        if common_control_arn:
            break
        token = page.get("NextToken")
        if not token:
            break
    if common_control_arn is None:
        raise AssertionError("no COMMON_CONTROL mapping found to filter by")

    filtered = cc.list_control_mappings(
        Filter={"CommonControlArns": [common_control_arn]}, MaxResults=100
    )
    filtered_mappings = filtered.get("ControlMappings", [])
    assert len(filtered_mappings) > 0, (
        f"expected at least one mapping when filtering by CommonControlArns=[{common_control_arn}], got 0"
    )
    for m in filtered_mappings:
        assert m["MappingType"] == "COMMON_CONTROL", (
            f"expected MappingType COMMON_CONTROL for a CommonControlArns-filtered result, "
            f"got {m['MappingType']!r} for ControlArn {m.get('ControlArn')!r}"
        )
        actual_arn = m["Mapping"]["CommonControl"]["CommonControlArn"]
        assert actual_arn == common_control_arn, (
            f"expected CommonControlArn {common_control_arn!r} on every CommonControlArns-filtered "
            f"mapping, got {actual_arn!r} for ControlArn {m.get('ControlArn')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
