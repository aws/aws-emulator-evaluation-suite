"""transit-gateway-metering-policy-entry-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "transit-gateway-metering-policy-entry-lifecycle"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A metering policy entry created against a transit gateway metering policy
    becomes available and is enforced (visible in GetTransitGatewayMeteringPolicyEntries);
    DeleteTransitGatewayMeteringPolicyEntry removes it from evaluation."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[
            {"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    )
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])[
            "TransitGateways"
        ][0],
        lambda t: t["State"] == "available",
        timeout_s=240,
    )

    policy_name = ctx.unique_name("sim2real-tgwmp-")
    policy = ec2.create_transit_gateway_metering_policy(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway-metering-policy",
                "Tags": [{"Key": "Name", "Value": policy_name}],
            }
        ],
    )["TransitGatewayMeteringPolicy"]
    policy_id = policy["TransitGatewayMeteringPolicyId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ec2.delete_transit_gateway_metering_policy(
                TransitGatewayMeteringPolicyId=policy_id
            )
        )
    )
    _poll_until(
        lambda: ec2.describe_transit_gateway_metering_policies(
            TransitGatewayMeteringPolicyIds=[policy_id]
        )["TransitGatewayMeteringPolicies"][0],
        lambda p: p["State"] == "available",
        timeout_s=120,
    )

    rule_number = 100
    entry = ec2.create_transit_gateway_metering_policy_entry(
        TransitGatewayMeteringPolicyId=policy_id,
        PolicyRuleNumber=rule_number,
        SourceCidrBlock="10.40.0.0/24",
        DestinationCidrBlock="10.41.0.0/24",
        Protocol="6",
        MeteredAccount="transit-gateway-owner",
    )["TransitGatewayMeteringPolicyEntry"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ec2.delete_transit_gateway_metering_policy_entry(
                TransitGatewayMeteringPolicyId=policy_id, PolicyRuleNumber=rule_number
            )
        )
    )
    assert entry["MeteredAccount"] == "transit-gateway-owner", (
        f"expected MeteredAccount=transit-gateway-owner, got {entry.get('MeteredAccount')!r}"
    )

    def _find_entry():
        entries = ec2.get_transit_gateway_metering_policy_entries(
            TransitGatewayMeteringPolicyId=policy_id
        )["TransitGatewayMeteringPolicyEntries"]
        return next((e for e in entries if e["PolicyRuleNumber"] == str(rule_number)), None)

    found = _poll_until(_find_entry, lambda e: e is not None and e["State"] == "available", timeout_s=120)
    rule = found["MeteringPolicyRule"]
    assert rule["SourceCidrBlock"] == "10.40.0.0/24", (
        f"expected SourceCidrBlock=10.40.0.0/24, got {rule.get('SourceCidrBlock')!r}"
    )
    assert rule["DestinationCidrBlock"] == "10.41.0.0/24", (
        f"expected DestinationCidrBlock=10.41.0.0/24, got {rule.get('DestinationCidrBlock')!r}"
    )

    ec2.delete_transit_gateway_metering_policy_entry(
        TransitGatewayMeteringPolicyId=policy_id, PolicyRuleNumber=rule_number
    )
    gone = _poll_until(_find_entry, lambda e: e is None, timeout_s=120)
    assert gone is None, f"expected entry to be absent from GetTransitGatewayMeteringPolicyEntries, found {gone!r}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidTransitGatewayID.NotFound",
            "InvalidTransitGatewayMeteringPolicyId.NotFound",
        ):
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
