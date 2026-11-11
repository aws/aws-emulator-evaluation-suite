"""op-contract-deleteTransitGatewayMeteringPolicy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayMeteringPolicy"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayMeteringPolicy tears down an available policy; bogus id -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwmp-")

    tgw_id = _create_tgw(ctx, ec2, name)

    try:
        created = ec2.create_transit_gateway_metering_policy(
            TransitGatewayId=tgw_id,
            TagSpecifications=[
                {"ResourceType": "transit-gateway-metering-policy", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )
    except ClientError as exc:
        raise AssertionError(f"transit gateway metering policies unavailable: {exc.response['Error']['Code']}") from exc

    policy_id = created["TransitGatewayMeteringPolicy"]["TransitGatewayMeteringPolicyId"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: ec2.delete_transit_gateway_metering_policy(TransitGatewayMeteringPolicyId=policy_id)
        )
    )

    state = _poll(
        lambda: _policy_state(ec2, policy_id),
        lambda s: s == "available",
        timeout_s=120.0,
    )
    assert state == "available", f"metering policy never became available (last={state})"

    delete_resp = ec2.delete_transit_gateway_metering_policy(TransitGatewayMeteringPolicyId=policy_id)
    assert delete_resp["TransitGatewayMeteringPolicy"]["State"] in ("deleting", "deleted")

    final_state = _poll(
        lambda: _policy_state(ec2, policy_id, treat_notfound_as="deleted"),
        lambda s: s == "deleted",
        timeout_s=120.0,
    )
    assert final_state == "deleted", f"metering policy never reached deleted (last={final_state})"

    # Use an ID that matches the real ID *shape* (same prefix/length as the one AWS just handed
    # back) but can't possibly exist, so the boundary under test is genuinely "no such resource"
    # rather than "malformed ID" (a literal made-up suffix like "0123456789abcdef0" tripped the
    # service's format validator first and returned a Malformed code instead of NotFound).
    bogus_id = _bogus_id_like(policy_id)
    code, msg = _client_error(
        lambda: ec2.delete_transit_gateway_metering_policy(TransitGatewayMeteringPolicyId=bogus_id)
    )
    assert code == "InvalidTransitGatewayMeteringPolicyId.NotFound", f"unexpected error code: {code}"
    expected_msg = f"Transit Gateway Metering Policy Id {bogus_id} was deleted or does not exist."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _bogus_id_like(real_id):
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'f' * len(suffix)}"

def _poll(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _policy_state(ec2, policy_id, treat_notfound_as=None):
    try:
        resp = ec2.describe_transit_gateway_metering_policies(TransitGatewayMeteringPolicyIds=[policy_id])
        policies = resp["TransitGatewayMeteringPolicies"]
        if not policies:
            return treat_notfound_as
        return policies[0]["State"]
    except ClientError as exc:
        if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
            return treat_notfound_as
        raise


def _retry_on_tgw_limit(fn, timeout_s=600.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_tgw(ctx, ec2, name):
    created = _retry_on_tgw_limit(
        lambda: ec2.create_transit_gateway(
            Description=name,
            TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
        )
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )
    return tgw_id


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidTransitGatewayID.NotFound",
            "InvalidTransitGatewayMeteringPolicyId.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
