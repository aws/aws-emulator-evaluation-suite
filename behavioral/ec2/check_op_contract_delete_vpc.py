"""op-contract-deleteVpc."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpc"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVpc is rejected with DependencyViolation while a subnet exists, then succeeds once it's gone."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.212.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")]
    )["Vpc"]["VpcId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                    raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"], lambda s: s == "available", timeout_s=30.0
    )

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.212.1.0/24", TagSpecifications=[_tag_spec(ctx, "subnet", "subnet")]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    # distinct error boundary: cannot delete a VPC while it still has a subnet
    err = _error(lambda: ec2.delete_vpc(VpcId=vpc_id))
    assert err == (
        "DependencyViolation",
        f"The vpc '{vpc_id}' has dependencies and cannot be deleted.",
    ), f"unexpected error deleting a VPC with a subnet: {err!r}"

    # remove the dependency, then the success path: delete succeeds and the VPC disappears
    ec2.delete_subnet(SubnetId=subnet_id)
    ec2.delete_vpc(VpcId=vpc_id)
    state["deleted"] = True

    not_found = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    gone = _error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]))
    assert gone == not_found, f"unexpected error describing the deleted VPC: {gone!r}"

    # deletion must also make the id unusable for a mutation, not just unreadable
    mutate = _error(lambda: ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.212.2.0/24"))
    assert mutate == not_found, f"unexpected error creating a subnet on a deleted VPC: {mutate!r}"


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
