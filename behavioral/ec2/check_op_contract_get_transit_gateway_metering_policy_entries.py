"""op-contract-get-transit-gateway-metering-policy-entries."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "op-contract-get-transit-gateway-metering-policy-entries"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTransitGatewayMeteringPolicyEntries lists a real entry with the exact match
    criteria and metered-account attribution it was created with; a nonexistent policy
    ID is rejected as NotFound."""
    ec2 = ctx.client("ec2")

    tgw_id = ec2.create_transit_gateway(
        Description=ctx.unique_name("sim2real-tgw-"),
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgw-")}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    _wait_tgw_state(ec2, tgw_id, {"available"})

    policy_id = ec2.create_transit_gateway_metering_policy(
        TransitGatewayId=tgw_id,
        TagSpecifications=[{"ResourceType": "transit-gateway-metering-policy", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgwmp-")}]}],
    )["TransitGatewayMeteringPolicy"]["TransitGatewayMeteringPolicyId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_metering_policy(TransitGatewayMeteringPolicyId=policy_id))

    ec2.create_transit_gateway_metering_policy_entry(
        TransitGatewayMeteringPolicyId=policy_id,
        PolicyRuleNumber=100,
        MeteredAccount="transit-gateway-owner",
        SourceCidrBlock="10.0.0.0/16",
    )

    # success-path contract: the entry we created is listed with its exact match
    # criteria and metered-account attribution.
    entries = _poll_until(
        lambda: ec2.get_transit_gateway_metering_policy_entries(
            TransitGatewayMeteringPolicyId=policy_id
        )["TransitGatewayMeteringPolicyEntries"],
        lambda es: any(e["PolicyRuleNumber"] == "100" for e in es),
        timeout_s=60,
        interval_s=5,
    )
    match = next(e for e in entries if e["PolicyRuleNumber"] == "100")
    assert match["MeteredAccount"] == "transit-gateway-owner", (
        f"expected MeteredAccount 'transit-gateway-owner', got {match['MeteredAccount']!r}"
    )
    assert match["MeteringPolicyRule"]["SourceCidrBlock"] == "10.0.0.0/16", (
        f"expected SourceCidrBlock '10.0.0.0/16', got {match['MeteringPolicyRule']['SourceCidrBlock']!r}"
    )
    assert match["State"] == "available", f"expected entry State 'available', got {match['State']!r}"

    # error boundary: well-formed but nonexistent policy ID -> NotFound-class error.
    bogus_id = _bogus_id_like(policy_id)
    code, message = _client_error(lambda: ec2.get_transit_gateway_metering_policy_entries(TransitGatewayMeteringPolicyId=bogus_id))
    assert code == "InvalidTransitGatewayMeteringPolicyId.NotFound", f"unexpected error code: {code}"
    expected_message = f"Transit Gateway Metering Policy Id {bogus_id} was deleted or does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _bogus_id_like(real_id: str) -> str:
    def repl(m):
        return "f" * len(m.group())
    bogus = re.sub(r"[0-9a-f]+$", repl, real_id)
    assert bogus != real_id, "could not derive a distinct bogus id"
    return bogus


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result: {last!r}")


def _delete_tgw(ec2, tgw_id):
    ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    _wait_tgw_state(ec2, tgw_id, {"deleted"})


# botocore ships no waiter for transit-gateway create/delete transitions --
# get_waiter("transit_gateway_available"/"transit_gateway_deleted") raises
# ValueError: Waiter does not exist (confirmed against real AWS). Poll the
# describe API's State field directly instead.
def _wait_tgw_state(ec2, tgw_id, target_states, timeout_s=600.0, interval_s=15.0):
    from botocore.exceptions import ClientError

    def probe():
        try:
            tgws = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"]
        except ClientError as err:
            if err.response["Error"]["Code"].endswith("NotFound"):
                return "deleted"
            raise
        return tgws[0]["State"] if tgws else "deleted"

    return _poll_until(probe, lambda s: s in target_states, timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
