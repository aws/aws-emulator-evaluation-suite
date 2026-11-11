"""op-contract-deleteCarrierGateway."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteCarrierGateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCarrierGateway: success detaches and removes the carrier gateway from its VPC; a
    nonexistent CarrierGatewayId is rejected with InvalidCarrierGatewayID.NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-cagw-")

    vpc_id = _create_vpc(ec2, "10.223.0.0/16", name)
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    try:
        gateway = ec2.create_carrier_gateway(
            VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "carrier-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
        )["CarrierGateway"]
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"CreateCarrierGateway unavailable in this account/region: {exc}")

    gateway_id = gateway["CarrierGatewayId"]

    def _cleanup() -> None:
        try:
            ec2.delete_carrier_gateway(CarrierGatewayId=gateway_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidCarrierGatewayID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    assert gateway["VpcId"] == vpc_id
    assert gateway["State"] in ("pending", "available"), gateway["State"]

    resp = ec2.delete_carrier_gateway(CarrierGatewayId=gateway_id)
    deleted = resp["CarrierGateway"]
    assert deleted["CarrierGatewayId"] == gateway_id
    assert deleted["State"] in ("deleting", "deleted"), deleted["State"]

    # The delete's own response is a mutating-call echo, not independent evidence. Prove the
    # specific gateway is actually gone via an independent read, then that a second delete on the
    # SAME now-dead id is rejected -- not just that some never-existed id is.
    final_state = _wait_for_gone_or_deleted(ec2, gateway_id)
    assert final_state in ("deleted", None), f"expected deleted/absent, got {final_state!r}"

    redelete = _client_error(lambda: ec2.delete_carrier_gateway(CarrierGatewayId=gateway_id))
    assert redelete.get("Code") == "InvalidCarrierGatewayID.NotFound", (
        f"expected InvalidCarrierGatewayID.NotFound re-deleting {gateway_id}, got {redelete!r}"
    )
    assert redelete.get("Message") == _not_found_message(gateway_id), (
        f"unexpected message re-deleting {gateway_id}: {redelete!r}"
    )

    # Error boundary: a CarrierGatewayId that never existed is rejected identically.
    err = _client_error(lambda: ec2.delete_carrier_gateway(CarrierGatewayId="cagw-00000000000000000"))
    assert err.get("Code") == "InvalidCarrierGatewayID.NotFound", f"expected InvalidCarrierGatewayID.NotFound, got {err!r}"
    assert err.get("Message") == _not_found_message("cagw-00000000000000000"), (
        f"unexpected not-found message: {err!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _not_found_message(gateway_id):
    return f"The CarrierGateway ID '{gateway_id}' does not exist"


def _wait_for_gone_or_deleted(ec2, gateway_id, timeout_s=60):
    """Bounded retry on an independent read (DescribeCarrierGateways) for the specific id.

    Returns the last observed state, or None once the id no longer appears in the describe response.
    Raises on timeout rather than returning a stale/last value.
    """
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_state = "pending"
    while time.monotonic() < deadline:
        try:
            gateways = ec2.describe_carrier_gateways(CarrierGatewayIds=[gateway_id]).get("CarrierGateways", [])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidCarrierGatewayID.NotFound":
                raise
            return None
        if not gateways:
            return None
        last_state = gateways[0]["State"]
        if last_state == "deleted":
            return last_state
        time.sleep(2)
    raise AssertionError(f"carrier gateway {gateway_id} did not reach deleted/absent within {timeout_s}s, last state {last_state!r}")


def _create_vpc(ec2, cidr_block, name):
    """Create a VPC, failing loudly if the account has no quota left.

    A quota exhaustion is an environment precondition, not something a check may fix by deleting
    resources it does not own, so `VpcLimitExceeded` propagates.
    """
    return ec2.create_vpc(
        CidrBlock=cidr_block,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
