"""transit-gateway-metering-policy-entry-crud-consistency."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "transit-gateway-metering-policy-entry-crud-consistency"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created TGW metering policy entry appears with the exact fields written and is gone after delete."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    _wait_tgw_available(ec2, tgw_id)

    policy_id = ec2.create_transit_gateway_metering_policy(
        TransitGatewayId=tgw_id,
        TagSpecifications=[{"ResourceType": "transit-gateway-metering-policy", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGatewayMeteringPolicy"]["TransitGatewayMeteringPolicyId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_metering_policy(TransitGatewayMeteringPolicyId=policy_id))

    entry = ec2.create_transit_gateway_metering_policy_entry(
        TransitGatewayMeteringPolicyId=policy_id,
        PolicyRuleNumber=100,
        SourceCidrBlock="10.40.0.0/16",
        SourcePortRange="0-65535",
        DestinationCidrBlock="10.41.0.0/16",
        DestinationPortRange="0-65535",
        Protocol="6",
        MeteredAccount="transit-gateway-owner",
    )["TransitGatewayMeteringPolicyEntry"]
    assert entry["PolicyRuleNumber"] == "100", f"expected rule number '100' on create response, got {entry['PolicyRuleNumber']!r}"
    assert entry["MeteredAccount"] == "transit-gateway-owner", f"expected metered account 'transit-gateway-owner' on create response, got {entry['MeteredAccount']!r}"

    found = _find_entry(ec2, policy_id, "100")
    assert found is not None, "metering policy entry not visible immediately after creation"
    assert found["MeteredAccount"] == "transit-gateway-owner", f"expected metered account 'transit-gateway-owner' on independent read, got {found['MeteredAccount']!r}"
    rule = found["MeteringPolicyRule"]
    assert rule["SourceCidrBlock"] == "10.40.0.0/16", f"expected source CIDR 10.40.0.0/16 on independent read, got {rule['SourceCidrBlock']!r}"
    assert rule["DestinationCidrBlock"] == "10.41.0.0/16", f"expected destination CIDR 10.41.0.0/16 on independent read, got {rule['DestinationCidrBlock']!r}"

    ec2.delete_transit_gateway_metering_policy_entry(TransitGatewayMeteringPolicyId=policy_id, PolicyRuleNumber=100)

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        remaining = _find_entry(ec2, policy_id, "100")
        if remaining is None or remaining.get("State") == "deleted":
            break
        time.sleep(3)
    else:
        raise AssertionError("deleted metering policy entry is still listed as available")

    code, message = _error_code(
        lambda: ec2.delete_transit_gateway_metering_policy_entry(
            TransitGatewayMeteringPolicyId=policy_id, PolicyRuleNumber=100
        )
    )
    assert code == "InvalidParameterValue", (
        f"deleting an already-deleted metering policy entry should be rejected as an absent rule "
        f"number, got code={code!r} message={message!r}"
    )
    assert message == "Metering Policy Entry RuleNumber provided does not exists", (
        f"expected EC2's exact absent-rule-number message, got {message!r}"
    )


def _wait_tgw_available(ec2, tgw_id, timeout_s=300.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        tgw = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
        if tgw["State"] == "available":
            return
        if tgw["State"] in ("deleting", "deleted"):
            raise AssertionError(f"transit gateway entered unexpected state {tgw['State']}")
        time.sleep(2)
    raise AssertionError("transit gateway never became available")


def _find_entry(ec2, policy_id, rule_number):
    resp = ec2.get_transit_gateway_metering_policy_entries(TransitGatewayMeteringPolicyId=policy_id)
    for e in resp.get("TransitGatewayMeteringPolicyEntries", []):
        if e["PolicyRuleNumber"] == rule_number:
            return e
    return None


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the call to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
