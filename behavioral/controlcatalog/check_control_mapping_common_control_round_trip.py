"""control-mapping-common-control-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "control-mapping-common-control-round-trip"
GROUP = "consistency"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A control's COMMON_CONTROL mapping resolves back to that control via the reverse CommonControlArns filter."""
    cc = ctx.client("controlcatalog")

    forward = cc.list_control_mappings(
        MaxResults=50, Filter={"MappingTypes": ["COMMON_CONTROL"]}
    ).get("ControlMappings", [])
    assert forward, "expected at least one COMMON_CONTROL mapping in the catalog"

    entry = forward[0]
    assert entry["MappingType"] == "COMMON_CONTROL", (
        f"expected MappingType COMMON_CONTROL from a COMMON_CONTROL-filtered list, got {entry['MappingType']!r}"
    )
    common_control_arn = entry["Mapping"]["CommonControl"]["CommonControlArn"]
    control_arn = entry["ControlArn"]

    reverse_control_arns: set[str] = set()
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 1000, "Filter": {"CommonControlArns": [common_control_arn]}}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_control_mappings(**kwargs)
        for mapping in page.get("ControlMappings", []):
            actual_cc_arn = mapping["Mapping"]["CommonControl"]["CommonControlArn"]
            assert actual_cc_arn == common_control_arn, (
                f"reverse filter by CommonControlArns=[{common_control_arn}] returned a mapping "
                f"pointing to {actual_cc_arn!r} instead"
            )
            reverse_control_arns.add(mapping["ControlArn"])
        token = page.get("NextToken")
        if not token:
            break

    assert control_arn in reverse_control_arns, (
        f"control {control_arn} was not found when reverse-filtering mappings by "
        f"its own common control {common_control_arn}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
