"""put-inventory-then-delete-inventory-lifecycle."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-inventory-then-delete-inventory-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """PutInventory data is listable, DeleteInventory removes it, and the deletion is tracked.

    DescribeInventoryDeletions reaches Complete and ListInventoryEntries then lists nothing."""
    ssm = ctx.client("ssm")
    # PutInventory fails InvalidInstanceId unless SSM Agent is registered on the node.
    instance_id = _launch_managed_instance(ctx)

    type_name = "Custom:Sim2Real" + uuid.uuid4().hex[:12]
    capture_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    ssm.put_inventory(
        InstanceId=instance_id,
        Items=[
            {
                "TypeName": type_name,
                "SchemaVersion": "1.0",
                "CaptureTime": capture_time,
                "Content": [{"Stage": "PreProd", "Marker": type_name}],
            }
        ],
    )

    entries = _poll_until(
        lambda: _try_list_entries(ssm, instance_id, type_name),
        lambda entries: len(entries) > 0,
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2.0,
        ctx=ctx,
    )
    assert len(entries) == 1, f"expected exactly 1 inventory entry for {type_name!r}, got {entries!r}"
    assert entries[0]["Stage"] == "PreProd", (
        f"expected entry Stage='PreProd', got {entries[0].get('Stage')!r}: {entries[0]!r}"
    )
    assert entries[0]["Marker"] == type_name, (
        f"expected entry Marker={type_name!r}, got {entries[0].get('Marker')!r}: {entries[0]!r}"
    )

    delete_resp = ssm.delete_inventory(TypeName=type_name)
    deletion_id = delete_resp["DeletionId"]

    deletions = _poll_until(
        lambda: ssm.describe_inventory_deletions(DeletionId=deletion_id)["InventoryDeletions"],
        lambda deletions: len(deletions) > 0 and deletions[0]["LastStatus"] == "Complete",
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2.0,
        ctx=ctx,
    )
    assert deletions[0]["TypeName"] == type_name, (
        f"expected DescribeInventoryDeletions TypeName={type_name!r}, got {deletions[0].get('TypeName')!r}: {deletions[0]!r}"
    )
    assert deletions[0]["DeletionId"] == deletion_id, (
        f"expected DescribeInventoryDeletions DeletionId={deletion_id!r}, got {deletions[0].get('DeletionId')!r}: {deletions[0]!r}"
    )
    assert deletions[0]["LastStatus"] == "Complete", (
        f"expected deletion {deletion_id} to reach LastStatus='Complete', "
        f"got {deletions[0].get('LastStatus')!r}: {deletions[0]!r}"
    )

    remaining_entries = _poll_until(
        lambda: _try_list_entries(ssm, instance_id, type_name),
        lambda entries: len(entries) == 0,
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2.0,
        ctx=ctx,
    )
    assert remaining_entries == [], (
        f"expected ListInventoryEntries to be empty for {type_name!r} after DeleteInventory, "
        f"got {remaining_entries!r}"
    )


def _try_list_entries(ssm, instance_id: str, type_name: str) -> list:
    """ListInventoryEntries, reading InvalidTypeNameException as empty; a just-written or
    just-deleted custom type raises it transiently while the index catches up."""
    try:
        return ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_name)["Entries"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidTypeNameException":
            return []
        raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_running(ec2, instance_ids, timeout_s: float, ctx=None) -> None:
    """Poll every 2 s until every instance is running; fails on a dead-end state or the deadline."""
    deadline = time.monotonic() + timeout_s
    states = {}
    while True:
        try:
            reservations = ec2.describe_instances(InstanceIds=list(instance_ids))["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            reservations = []
        states = {i["InstanceId"]: i["State"]["Name"] for r in reservations for i in r["Instances"]}
        if len(states) == len(instance_ids) and all(s == "running" for s in states.values()):
            return
        assert not any(s in ("shutting-down", "terminated", "stopping", "stopped") for s in states.values()), (
            f"instances {list(instance_ids)} reached {states!r} instead of running")
        if time.monotonic() >= deadline and ctx is not None and _budget_spent(ctx):
            raise TimeoutError("instances reaching running: the run budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"instances {list(instance_ids)} not running in time: {states!r}")
        time.sleep(2.0)


def _default_subnet_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    return subnets[0]["SubnetId"] if subnets else None


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _launch_managed_instance(ctx) -> str:
    """Launch a t3.micro SSM-managed EC2 instance and wait for PingStatus=Online; return its id."""

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    if not subnet_id:
        raise AssertionError(
            "no shared network VPC/subnet available to launch a test managed-instance EC2 host"
        )

    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    role_name = ctx.unique_name("sim2real-ssm-mi-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    profile_name = ctx.unique_name("sim2real-ssm-mi-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    deadline = time.monotonic() + _budget_s(ctx, 30.0)
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            break
        except ClientError:
            time.sleep(2)

    ami_id = _latest_al2023_ami(ctx)
    tag_name = ctx.unique_name("sim2real-ssm-mi-")

    instance_id = None
    launch_deadline = time.monotonic() + _budget_s(ctx, 60.0)
    last_error: Exception | None = None
    while time.monotonic() < launch_deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": tag_name}]}
                ],
            )
            instance_id = run_resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            last_error = exc
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            time.sleep(2)
    if instance_id is None:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"could not launch test instance: {last_error}")

    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    _wait_running(ec2, [instance_id], _budget_s(ctx, 300.0), ctx=ctx)

    online_deadline = time.monotonic() + _budget_s(ctx, 480.0)
    online = False
    while time.monotonic() < online_deadline:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp.get("InstanceInformationList", [])
        if infos and infos[0].get("PingStatus") == "Online":
            online = True
            break
        time.sleep(2)
    if not online:
        if _budget_spent(ctx):
            raise TimeoutError(f"instance {instance_id} reaching PingStatus=Online: the run budget ended first; "
                               "not graded")
        raise AssertionError(
            f"EC2 instance {instance_id} did not register as an SSM managed node in time "
            "(agent bootstrap or outbound network egress issue in this environment)"
        )
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
