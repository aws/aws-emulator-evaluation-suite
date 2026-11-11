"""flow-entitlement-status-toggle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "flow-entitlement-status-toggle"
GROUP = "state-machine"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GrantFlowEntitlements creates an ENABLED entitlement by default; UpdateFlowEntitlement
    can disable and re-enable it, and DescribeFlow reflects the persisted EntitlementStatus."""
    mc = ctx.client("mediaconnect")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-mc-flow-")
    flow_arn = mc.create_flow(
        Name=name,
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
        FlowTags={"sim2real": CHECK},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: mc.delete_flow(FlowArn=flow_arn))

    grant_resp = mc.grant_flow_entitlements(
        FlowArn=flow_arn,
        Entitlements=[{"Name": "ent1", "Subscribers": [account_id]}],
    )
    entitlement_arn = grant_resp["Entitlements"][0]["EntitlementArn"]
    granted_status = grant_resp["Entitlements"][0]["EntitlementStatus"]
    assert granted_status == "ENABLED", (
        f"expected a freshly granted entitlement to default to ENABLED, got {granted_status!r}"
    )

    mc.update_flow_entitlement(
        FlowArn=flow_arn, EntitlementArn=entitlement_arn, EntitlementStatus="DISABLED"
    )
    disabled_status = _get_entitlement_status(mc, flow_arn, entitlement_arn)
    assert disabled_status == "DISABLED", (
        f"expected DescribeFlow to reflect DISABLED after UpdateFlowEntitlement, got {disabled_status!r}"
    )

    mc.update_flow_entitlement(
        FlowArn=flow_arn, EntitlementArn=entitlement_arn, EntitlementStatus="ENABLED"
    )
    reenabled_status = _get_entitlement_status(mc, flow_arn, entitlement_arn)
    assert reenabled_status == "ENABLED", (
        f"expected DescribeFlow to reflect ENABLED after re-enabling, got {reenabled_status!r}"
    )


def _get_entitlement_status(mc, flow_arn: str, entitlement_arn: str) -> str:
    flow = mc.describe_flow(FlowArn=flow_arn)["Flow"]
    for ent in flow["Entitlements"]:
        if ent["EntitlementArn"] == entitlement_arn:
            return ent["EntitlementStatus"]
    raise AssertionError("entitlement not found on flow")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
