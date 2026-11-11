"""egress-only-internet-gateway-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call *fn*; return the AWS (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _delete_eigw(ec2, eigw_id):
    """Teardown: the body deletes the gateway itself, so InvalidGatewayID.NotFound is done."""
    try:
        ec2.delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=eigw_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidGatewayID.NotFound":
            raise


CHECK = "egress-only-internet-gateway-lifecycle"
GROUP = 'vpc-networking'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEgressOnlyInternetGateway attaches to the VPC and deletes cleanly."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.102.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda state: state == "available",
        timeout_s=60,
        description=f"vpc {vpc_id} becoming available",
    )

    resp = ec2.create_egress_only_internet_gateway(VpcId=vpc_id, TagSpecifications=[{"ResourceType": "egress-only-internet-gateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    eigw = resp["EgressOnlyInternetGateway"]
    eigw_id = eigw["EgressOnlyInternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_eigw(ec2, eigw_id))
    assert any(a["VpcId"] == vpc_id for a in eigw["Attachments"]), (
        f"expected attachment to {vpc_id}, got {eigw['Attachments']}"
    )

    ret = ec2.delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=eigw_id)
    assert ret["ReturnCode"] is True, f"expected ReturnCode true, got {ret}"

    # Independent read: the deleted gateway must genuinely be gone, not merely
    # reported as deleted by the same call that deleted it.
    remaining = ec2.describe_egress_only_internet_gateways(
        EgressOnlyInternetGatewayIds=[eigw_id]
    ).get("EgressOnlyInternetGateways", [])
    assert remaining == [], f"deleted gateway {eigw_id} still visible via Describe: {remaining}"

    # Deleting a second time must be refused, on the *same* id -- distinct from
    # deleting an id that never existed.
    again, again_message = _error(
        lambda: ec2.delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=eigw_id)
    )
    assert again == "InvalidGatewayID.NotFound", (
        f"expected InvalidGatewayID.NotFound, got {again}"
    )
    assert again_message == f"The eigw ID '{eigw_id}' does not exist", again_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
