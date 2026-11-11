"""op-contract-delete-security-group-dependency-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-security-group-dependency-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSecurityGroup succeeds on an unattached group; fails DependencyViolation while
    the group is still attached to a network interface."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.94.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _tag(ec2, vpc_id, ctx.unique_name("sim2real-behav-sg-vpc-"))

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.94.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    free_sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-free-"),
        Description="unattached",
        VpcId=vpc_id,
    )["GroupId"]
    resp = ec2.delete_security_group(GroupId=free_sg_id)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    code, msg = _client_error(
        lambda: ec2.describe_security_groups(GroupIds=[free_sg_id])
    )
    assert code == "InvalidGroup.NotFound", f"expected NotFound, got {code!r}"
    expected_msg = f"The security group '{free_sg_id}' does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Error boundary: a security group attached to an ENI cannot be deleted.
    attached_sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-attached-"),
        Description="attached to eni",
        VpcId=vpc_id,
    )["GroupId"]
    eni_id = ec2.create_network_interface(SubnetId=subnet_id, Groups=[attached_sg_id])[
        "NetworkInterface"
    ]["NetworkInterfaceId"]

    def _cleanup_attached() -> None:
        try:
            ec2.delete_network_interface(NetworkInterfaceId=eni_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
                raise
        try:
            ec2.delete_security_group(GroupId=attached_sg_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidGroup.NotFound":
                raise

    ctx.on_cleanup(_cleanup_attached)

    code, msg = _client_error(lambda: ec2.delete_security_group(GroupId=attached_sg_id))
    assert code == "DependencyViolation", f"expected DependencyViolation, got {code!r}"
    expected_msg = f"resource {attached_sg_id} has a dependent object"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    still_there = ec2.describe_security_groups(GroupIds=[attached_sg_id])["SecurityGroups"]
    assert len(still_there) == 1 and still_there[0]["GroupId"] == attached_sg_id, (
        f"expected {attached_sg_id} to survive the rejected delete, got {still_there!r}"
    )

    # ENI deletion releases the group asynchronously, so the delete is retried briefly.
    ec2.delete_network_interface(NetworkInterfaceId=eni_id)
    _poll_until(
        lambda: _succeeds(lambda: ec2.delete_security_group(GroupId=attached_sg_id)),
        lambda ok: ok is True,
        timeout_s=30,
    )

    code, msg = _client_error(
        lambda: ec2.describe_security_groups(GroupIds=[attached_sg_id])
    )
    assert code == "InvalidGroup.NotFound", f"expected NotFound, got {code!r}"
    expected_msg = f"The security group '{attached_sg_id}' does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _tag(ec2: Any, resource_id: str, name: str) -> None:
    ec2.create_tags(Resources=[resource_id], Tags=[{"Key": "Name", "Value": name}])


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _succeeds(fn: Callable[[], Any]) -> bool:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError:
        return False
    return True


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
