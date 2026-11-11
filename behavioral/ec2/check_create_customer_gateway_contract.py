"""create-customer-gateway-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-customer-gateway-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCustomerGateway: success returns a gateway that reaches 'available',
    and an out-of-range BgpAsn is rejected before any resource is created.
    """
    ec2 = ctx.client("ec2")
    ip_address = "203.0.113.77"  # TEST-NET-3 (RFC 5737): syntactically valid, no real device needed.

    resp = ec2.create_customer_gateway(
        Type="ipsec.1",
        BgpAsn=65000,
        IpAddress=ip_address,
        TagSpecifications=[_tag_spec(ctx, "customer-gateway")],
    )
    cgw = resp["CustomerGateway"]
    cgw_id = cgw["CustomerGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))

    assert cgw["IpAddress"] == ip_address, f"expected IpAddress {ip_address!r}, got {cgw['IpAddress']!r}"
    assert str(cgw["BgpAsn"]) == "65000", f"expected BgpAsn '65000', got {cgw['BgpAsn']!r}"
    assert cgw["Type"] == "ipsec.1", f"expected Type 'ipsec.1', got {cgw['Type']!r}"
    assert cgw["State"] in ("pending", "available"), f"expected pending/available right after create, got {cgw['State']!r}"

    waiter = ec2.get_waiter("customer_gateway_available")
    waiter.wait(CustomerGatewayIds=[cgw_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    described = ec2.describe_customer_gateways(CustomerGatewayIds=[cgw_id])["CustomerGateways"][0]
    assert described["State"] == "available", f"expected State 'available' after waiter, got {described['State']!r}"

    # Error boundary: BgpAsn is documented as valid only in [1, 2147483647]; an
    # out-of-range value must be rejected up front, and must not leave behind
    # a gateway resource.
    rejected_spec = _tag_spec(ctx, "customer-gateway")
    rejected_name = rejected_spec["Tags"][0]["Value"]
    code, message = _error_detail(
        lambda: ec2.create_customer_gateway(
            Type="ipsec.1", BgpAsn=-1, IpAddress="203.0.113.78", TagSpecifications=[rejected_spec]
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue for out-of-range BgpAsn, got {code!r} ({message})"
    assert message == "Value (-1) for parameter bgpAsn is invalid. Invalid Format.", f"unexpected error message {message!r}"
    left = ec2.describe_customer_gateways(
        Filters=[{"Name": "tag:Name", "Values": [rejected_name]},
                 {"Name": "state", "Values": ["pending", "available"]}]
    )["CustomerGateways"]
    assert left == [], f"a rejected CreateCustomerGateway must not create a gateway resource: {left!r}"

def _error_detail(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
