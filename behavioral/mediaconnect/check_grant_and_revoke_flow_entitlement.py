"""grant-and-revoke-flow-entitlement."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "grant-and-revoke-flow-entitlement"
GROUP = "data-plane"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GrantFlowEntitlements adds an entitlement that DescribeFlow lists, RevokeFlowEntitlement removes it,
    and a second revoke of the same entitlement fails NotFoundException with the exact message while the
    flow still does not list it."""
    mc = ctx.client("mediaconnect")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: mc.delete_flow(FlowArn=flow_arn))

    ent_name = ctx.unique_name("sim2real-mc-ent-")
    grant_resp = mc.grant_flow_entitlements(
        FlowArn=flow_arn,
        Entitlements=[{"Name": ent_name, "Subscribers": [account_id]}],
    )
    entitlement_arn = grant_resp["Entitlements"][0]["EntitlementArn"]

    entitlements = mc.describe_flow(FlowArn=flow_arn)["Flow"].get("Entitlements", [])
    assert entitlement_arn in {e["EntitlementArn"] for e in entitlements}, (
        f"granted entitlement {entitlement_arn} did not appear in DescribeFlow's Entitlements list"
    )

    mc.revoke_flow_entitlement(FlowArn=flow_arn, EntitlementArn=entitlement_arn)

    entitlements = mc.describe_flow(FlowArn=flow_arn)["Flow"].get("Entitlements", [])
    assert entitlement_arn not in {e["EntitlementArn"] for e in entitlements}, (
        f"revoked entitlement {entitlement_arn} still appeared in DescribeFlow's Entitlements list"
    )

    code, message = _client_error(
        lambda: mc.revoke_flow_entitlement(FlowArn=flow_arn, EntitlementArn=entitlement_arn)
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException revoking an already-revoked entitlement, got {code!r}"
    )
    expected = f"Not found: {entitlement_arn}"
    assert message == expected, (
        f"expected message {expected!r} revoking an already-revoked entitlement, got {message!r}"
    )

    entitlements = mc.describe_flow(FlowArn=flow_arn)["Flow"].get("Entitlements", [])
    assert entitlement_arn not in {e["EntitlementArn"] for e in entitlements}, (
        "a rejected re-revoke must not have resurrected the entitlement"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
