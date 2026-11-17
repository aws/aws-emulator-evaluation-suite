"""modify-vpc-tenancy-to-dedicated-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-vpc-tenancy-to-dedicated-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyVpcTenancy only supports changing a VPC's instance tenancy to 'default': asking
    for 'dedicated' on a default-tenancy VPC is rejected and leaves the tenancy unchanged,
    while 'default' on the same VPC succeeds.
    """
    ec2 = ctx.client("ec2")

    vpc = _create_vpc_with_retry(
        ec2,
        CidrBlock="10.224.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tenancy-")}]}
        ],
    )
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_with_retry(ec2, vpc_id))
    assert vpc["InstanceTenancy"] == "default", f"expected a fresh VPC to be default-tenancy, got {vpc!r}"

    code, message = _error(lambda: ec2.modify_vpc_tenancy(VpcId=vpc_id, InstanceTenancy="dedicated"))
    assert code == "UnsupportedTenancy", (
        f"expected UnsupportedTenancy for ModifyVpcTenancy(InstanceTenancy='dedicated'), got {code!r} ({message!r})"
    )
    assert message == "The tenancy value dedicated is not supported.", (
        f"unexpected rejection message for InstanceTenancy='dedicated': {message!r}"
    )

    unchanged = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert unchanged["InstanceTenancy"] == "default", (
        f"a rejected ModifyVpcTenancy('dedicated') must leave tenancy unchanged, got {unchanged['InstanceTenancy']!r}"
    )

    # Positive control: the same VPC accepts the one supported transition, to 'default'.
    resp = ec2.modify_vpc_tenancy(VpcId=vpc_id, InstanceTenancy="default")
    assert resp["ReturnValue"] is True, f"expected ReturnValue True for the supported transition, got {resp!r}"
    confirmed = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert confirmed["InstanceTenancy"] == "default", confirmed


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises: an
    accepted call is the strongest signal and must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_vpc_with_retry(ec2, timeout_s: float = 420.0, interval_s: float = 10.0, **kwargs):
    """Create a VPC, retrying VpcLimitExceeded: the account's VPC quota can be transiently
    held by another concurrent caller's own, still-tearing-down VPCs."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)["Vpc"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_vpc_with_retry(ec2, vpc_id: str, timeout_s: float = 180.0, interval_s: float = 10.0) -> None:
    """Delete the VPC, retrying DependencyViolation: a just-removed dependency can take a
    moment to stop blocking delete_vpc."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
