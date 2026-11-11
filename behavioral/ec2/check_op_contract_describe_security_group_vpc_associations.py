"""op-contract-describeSecurityGroupVpcAssociations."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeSecurityGroupVpcAssociations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSecurityGroupVpcAssociations filtered by group and VPC shows an association made with
    AssociateSecurityGroupVpc as associated and drops it after disassociation; DryRun answers
    DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")

    vpc_name = ctx.unique_name("sim2real-behav-sgvpcassoc-")
    vpc_target = _create_vpc_retrying(ec2, "10.194.0.0/16", vpc_name)
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_target))
    _wait_vpc_available(ec2, vpc_target)

    vpc_home = _create_vpc_retrying(ec2, "10.195.0.0/16", ctx.unique_name("sim2real-behav-sgvpchome-"))
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_home))
    _wait_vpc_available(ec2, vpc_home)

    group_id = ec2.create_security_group(
        GroupName=vpc_name,
        Description="sim2real behavioral check: security group vpc associations",
        VpcId=vpc_home,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": vpc_name}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=group_id))

    resp = ec2.associate_security_group_vpc(GroupId=group_id, VpcId=vpc_target)
    assert resp["State"] in ("associating", "associated"), resp["State"]
    ctx.on_cleanup(lambda: _best_effort_disassociate(ec2, group_id, vpc_target))

    def _find(filters):
        return ec2.describe_security_group_vpc_associations(Filters=filters)["SecurityGroupVpcAssociations"]

    filters = [{"Name": "group-id", "Values": [group_id]}, {"Name": "vpc-id", "Values": [vpc_target]}]
    associated = _poll_until(
        lambda: _find(filters),
        lambda assocs: bool(assocs) and assocs[0]["State"] == "associated",
        timeout_s=90,
        interval_s=3,
    )[0]
    assert associated["GroupId"] == group_id, associated
    assert associated["VpcId"] == vpc_target, associated
    assert associated["State"] == "associated", associated

    code, code_message = _error_code(lambda: ec2.describe_security_group_vpc_associations(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    ec2.disassociate_security_group_vpc(GroupId=group_id, VpcId=vpc_target)
    removed = _poll_until(
        lambda: _find(filters),
        lambda assocs: not assocs or assocs[0]["State"] not in ("associated", "disassociating"),
        timeout_s=90,
        interval_s=3,
    )
    assert not removed or removed[0]["State"] == "disassociated", (
        f"expected disassociation to be reflected (absent or disassociated), got {removed!r}"
    )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_disassociate(ec2, group_id: str, vpc_id: str) -> None:
    try:
        ec2.disassociate_security_group_vpc(GroupId=group_id, VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidGroup.NotFound":
            raise


def _create_vpc_retrying(ec2, cidr: str, name: str, *, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    """Retry create_vpc on VpcLimitExceeded, which concurrent checks holding VPCs can cause, until
    their cleanup releases quota or the timeout passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(
                CidrBlock=cidr,
                TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
            )["Vpc"]["VpcId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_vpc_available(ec2, vpc_id: str, *, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    """Newly created VPCs briefly report State=pending before flipping to available; poll for
    that transition instead of assuming create_vpc's response already reflects the final state."""
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda state: state == "available",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
