"""get-security-groups-for-vpc-reflects-a-shared-group-until-disassociated."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-security-groups-for-vpc-reflects-a-shared-group-until-disassociated"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSecurityGroupsForVpc, read against the target VPC, lists a group shared into it with
    PrimaryVpcId naming its home VPC, and drops the group again once it is disassociated.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-sgfv-")

    home_vpc = _create_vpc_retrying(ec2, "10.217.0.0/16", name + "-home")
    ctx.on_cleanup(lambda: _delete_while_dependent(lambda: ec2.delete_vpc(VpcId=home_vpc)))
    target_vpc = _create_vpc_retrying(ec2, "10.218.0.0/16", name + "-target")
    ctx.on_cleanup(lambda: _delete_while_dependent(lambda: ec2.delete_vpc(VpcId=target_vpc)))

    shared_group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sgfv-shared-"),
        Description="created in the home VPC, shared into the target VPC",
        VpcId=home_vpc,
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_while_dependent(lambda: ec2.delete_security_group(GroupId=shared_group)))

    target_default_group = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [target_vpc]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]

    before = _group_ids(ec2, target_vpc)
    assert before == {target_default_group}, (
        f"before any sharing, GetSecurityGroupsForVpc({target_vpc!r}) should list only its own "
        f"default group {target_default_group!r}, got {before!r}"
    )

    ec2.associate_security_group_vpc(GroupId=shared_group, VpcId=target_vpc)
    associated = {"done": True}

    def _disassociate_if_needed() -> None:
        if associated["done"]:
            ec2.disassociate_security_group_vpc(GroupId=shared_group, VpcId=target_vpc)
            _wait_association_gone(ec2, shared_group, target_vpc)

    ctx.on_cleanup(_disassociate_if_needed)
    _wait_association_state(ec2, shared_group, target_vpc, "associated")

    during = _security_groups_for_vpc(ec2, target_vpc)
    during_ids = {sg["GroupId"] for sg in during}
    assert during_ids == {target_default_group, shared_group}, (
        f"once shared, GetSecurityGroupsForVpc({target_vpc!r}) should list its default group plus "
        f"the shared one, got {during_ids!r}"
    )
    shared_entry = next(sg for sg in during if sg["GroupId"] == shared_group)
    assert shared_entry["PrimaryVpcId"] == home_vpc, (
        f"the shared group's PrimaryVpcId should stay {home_vpc!r} (its home VPC), got "
        f"{shared_entry['PrimaryVpcId']!r}"
    )

    ec2.disassociate_security_group_vpc(GroupId=shared_group, VpcId=target_vpc)
    associated["done"] = False
    _wait_association_gone(ec2, shared_group, target_vpc)

    after = _group_ids(ec2, target_vpc)
    assert after == {target_default_group}, (
        f"once disassociated, GetSecurityGroupsForVpc({target_vpc!r}) should list only its own "
        f"default group {target_default_group!r} again, got {after!r}"
    )


def _security_groups_for_vpc(ec2, vpc_id: str) -> list:
    return ec2.get_security_groups_for_vpc(VpcId=vpc_id)["SecurityGroupForVpcs"]


def _group_ids(ec2, vpc_id: str) -> set:
    return {sg["GroupId"] for sg in _security_groups_for_vpc(ec2, vpc_id)}


def _wait_association_state(ec2, group_id: str, vpc_id: str, state: str, *, timeout_s: float = 90.0) -> None:
    _poll_until(
        lambda: ec2.describe_security_group_vpc_associations(
            Filters=[{"Name": "group-id", "Values": [group_id]}, {"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroupVpcAssociations"],
        lambda assocs: bool(assocs) and assocs[0]["State"] == state,
        timeout_s=timeout_s,
        interval_s=3,
    )


def _wait_association_gone(ec2, group_id: str, vpc_id: str, *, timeout_s: float = 90.0) -> None:
    _poll_until(
        lambda: ec2.describe_security_group_vpc_associations(
            Filters=[{"Name": "group-id", "Values": [group_id]}, {"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroupVpcAssociations"],
        lambda assocs: not assocs or assocs[0]["State"] not in ("associated", "associating", "disassociating"),
        timeout_s=timeout_s,
        interval_s=3,
    )


def _create_vpc_retrying(ec2, cidr: str, name: str, *, timeout_s: float = 180.0, interval_s: float = 10.0) -> str:
    """Create a VPC, retrying through a transient VpcLimitExceeded from sibling runs sharing the account."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return vpc_id


def _delete_while_dependent(fn, *, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    """Retry a delete while AWS still reports a dependency that is itself draining asynchronously."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("DependencyViolation", "SecurityGroupVpcAssociationExists") or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _tag_spec(resource_type: str, value: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": value}]}


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
