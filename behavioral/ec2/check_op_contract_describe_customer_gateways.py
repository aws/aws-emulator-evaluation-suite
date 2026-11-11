"""op-contract-describe-customer-gateways."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-customer-gateways"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCustomerGateways returns a created gateway as available with BgpAsn 65000, IpAddress
    203.0.113.12, Type ipsec.1 and its Name tag; an unknown gateway ID fails with
    InvalidCustomerGatewayID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-cgw-")

    created = ec2.create_customer_gateway(
        BgpAsn=65000,
        PublicIp="203.0.113.12",
        Type="ipsec.1",
        TagSpecifications=[
            {"ResourceType": "customer-gateway", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["CustomerGateway"]
    cgw_id = created["CustomerGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))

    gateway = _poll_until(
        lambda: ec2.describe_customer_gateways(CustomerGatewayIds=[cgw_id])[
            "CustomerGateways"
        ][0],
        lambda g: g["State"] == "available",
        timeout_s=60,
    )
    assert gateway["BgpAsn"] == "65000", f"expected BgpAsn '65000', got {gateway['BgpAsn']!r}"
    assert gateway["IpAddress"] == "203.0.113.12", (
        f"expected IpAddress '203.0.113.12', got {gateway['IpAddress']!r}"
    )
    assert gateway["Type"] == "ipsec.1", f"expected Type 'ipsec.1', got {gateway['Type']!r}"
    assert {"Key": "Name", "Value": name} in gateway.get("Tags", []), (
        f"expected tag Name={name!r} in {gateway.get('Tags')!r}"
    )

    not_found_code, not_found_message = _error(
        lambda: ec2.describe_customer_gateways(
            CustomerGatewayIds=["cgw-00000000000000000"]
        )
    )
    assert not_found_code == "InvalidCustomerGatewayID.NotFound", (
        f"expected InvalidCustomerGatewayID.NotFound, got {not_found_code}"
    )
    assert not_found_message == "The customerGateway ID 'cgw-00000000000000000' does not exist", not_found_message


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
