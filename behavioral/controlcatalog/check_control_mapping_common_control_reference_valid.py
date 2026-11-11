"""control-mapping-common-control-reference-valid."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "control-mapping-common-control-reference-valid"
GROUP = "consistency"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A COMMON_CONTROL mapping's CommonControlArn resolves to a real entry in the common-control catalog."""
    cc = ctx.client("controlcatalog")

    target_arn = None
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_control_mappings(**kwargs)
        for m in page.get("ControlMappings", []):
            if m["MappingType"] == "COMMON_CONTROL":
                target_arn = m["Mapping"]["CommonControl"]["CommonControlArn"]
                break
        if target_arn:
            break
        token = page.get("NextToken")
        if not token:
            break
    if target_arn is None:
        raise AssertionError("no COMMON_CONTROL mapping found to validate")

    found = False
    token = None
    for _ in range(30):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_common_controls(**kwargs)
        if any(c["Arn"] == target_arn for c in page.get("CommonControls", [])):
            found = True
            break
        token = page.get("NextToken")
        if not token:
            break

    assert found, f"CommonControlArn {target_arn} referenced by a mapping was not found in ListCommonControls"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
