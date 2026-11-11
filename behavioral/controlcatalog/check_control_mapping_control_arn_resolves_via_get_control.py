"""control-mapping-control-arn-resolves-via-get-control."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "control-mapping-control-arn-resolves-via-get-control"
GROUP = "data-integrity"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every ControlArn surfaced by ListControlMappings is a real, resolvable control -- the
    referential integrity between the mappings collection and the controls collection holds."""
    cc = ctx.client("controlcatalog")

    control_arns: set[str] = set()
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_control_mappings(**kwargs)
        for mapping in page.get("ControlMappings", []):
            control_arns.add(mapping["ControlArn"])
        token = page.get("NextToken")
        if not token or len(control_arns) >= 25:
            break

    assert control_arns, "ListControlMappings returned no mappings to validate"

    for control_arn in control_arns:
        got = cc.get_control(ControlArn=control_arn)
        assert got["Arn"] == control_arn, (
            f"GetControl({control_arn}) returned Arn {got.get('Arn')!r}, expected it to echo "
            "back the ControlArn it was resolved from"
        )
        assert got["Name"], f"GetControl({control_arn}) returned an empty Name"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
