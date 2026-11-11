"""op-contract-delete-egress-only-internet-gateway."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-egress-only-internet-gateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteEgressOnlyInternetGateway deletes a fresh egress-only IGW, which then disappears from
    Describe; deleting an unknown ID is rejected with InvalidGatewayID.NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-eoigw-")
    vpc = ec2.create_vpc(
        CidrBlock="10.71.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    eoigw = ec2.create_egress_only_internet_gateway(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "egress-only-internet-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["EgressOnlyInternetGateway"]
    eoigw_id = eoigw["EgressOnlyInternetGatewayId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=eoigw_id)))

    resp = ec2.delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=eoigw_id)
    assert resp["ReturnCode"] is True, f"expected ReturnCode true, got {resp}"

    remaining = ec2.describe_egress_only_internet_gateways(EgressOnlyInternetGatewayIds=[eoigw_id]).get(
        "EgressOnlyInternetGateways", []
    )
    assert not remaining, f"gateway {eoigw_id} still present after delete"

    # AWS reports an unknown egress-only IGW with the generic gateway NotFound code.
    fake_id = _zeroed_id(eoigw_id)
    code, message = _error_of(lambda: ec2.delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=fake_id))
    assert code == "InvalidGatewayID.NotFound", f"unexpected error code {code!r}"
    assert message == f"The eigw ID '{fake_id}' does not exist", message


def _error_of(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidGatewayID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _zeroed_id(real_id: str) -> str:
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'0' * len(suffix)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
