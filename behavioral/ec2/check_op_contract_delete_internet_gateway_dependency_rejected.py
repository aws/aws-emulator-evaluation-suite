"""op-contract-delete-internet-gateway-dependency-rejected."""
from __future__ import annotations
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-internet-gateway-dependency-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteInternetGateway on a gateway attached to a VPC fails with DependencyViolation; after detach
    it deletes and describes as InvalidInternetGatewayID.NotFound, and an all-zero gateway ID fails
    with InvalidInternetGatewayId.Malformed (exact messages)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-igw-")

    vpc = ec2.create_vpc(
        CidrBlock="10.73.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    igw = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": name}]}]
    )["InternetGateway"]
    igw_id = igw["InternetGatewayId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))

    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)))

    # Distinct error boundary: an attached IGW cannot be deleted until it is detached.
    code, message = _error(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    assert code == "DependencyViolation", f"expected DependencyViolation while attached, got {code!r}"
    assert message == f"The internetGateway '{igw_id}' has dependencies and cannot be deleted.", message

    ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    # Success path: once detached, deletion succeeds. Internet gateways are hard-deleted, so
    # describing the deleted gateway by ID is itself rejected (rather than returning an empty
    # list) — that rejection is the confirmation that the delete took effect.
    ec2.delete_internet_gateway(InternetGatewayId=igw_id)
    describe_code, describe_message = _error(lambda: ec2.describe_internet_gateways(InternetGatewayIds=[igw_id]))
    assert describe_code == "InvalidInternetGatewayID.NotFound", f"unexpected error code {describe_code!r}"
    assert describe_message == f"The internetGateway ID '{igw_id}' does not exist", describe_message

    # Second error boundary: an all-zero gateway ID fails the ID format check before any existence
    # lookup, so it is rejected as Malformed, not NotFound.
    fake_id = _zeroed_id(igw_id)
    not_found_code, not_found_message = _error(lambda: ec2.delete_internet_gateway(InternetGatewayId=fake_id))
    assert not_found_code == "InvalidInternetGatewayId.Malformed", (
        f"unexpected error code {not_found_code!r}"
    )
    assert not_found_message == f"The internet-gateway ID '{fake_id}' is malformed", not_found_message


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "Gateway.NotAttached",
            "InvalidInternetGatewayID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _zeroed_id(real_id: str) -> str:
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'0' * len(suffix)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
