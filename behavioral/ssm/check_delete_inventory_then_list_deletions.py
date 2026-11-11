"""delete-inventory-then-list-deletions."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-inventory-then-list-deletions"
GROUP = "state-machine"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """DeleteInventory of a Custom: type yields a DescribeInventoryDeletions record that reaches
    Complete with the matching TypeName, after which ListInventoryEntries rejects the type.
    """
    ssm = ctx.client("ssm")
    # PutInventory rejects an instance id that is not a registered, online managed node.
    instance_id = _provision_connected_targets(ctx, count=1)[0]

    type_name = "Custom:" + ctx.unique_name("S2RInv").replace("-", "")
    capture_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    item = {
        "TypeName": type_name,
        "SchemaVersion": "1.0",
        "CaptureTime": capture_time,
        "Content": [{"TestKey": "TestValue"}],
    }

    def _cleanup() -> None:
        try:
            ssm.delete_inventory(TypeName=type_name, SchemaDeleteOption="DeleteSchema")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTypeNameException":
                raise

    ctx.on_cleanup(_cleanup)

    ssm.put_inventory(InstanceId=instance_id, Items=[item])

    # PutInventory registers the custom schema asynchronously -- poll list_inventory_entries
    # (retrying through InvalidTypeNameException) until the type is actually visible before
    # attempting to delete it.
    _poll_until(
        lambda: _try_list_entries(ssm, instance_id, type_name),
        lambda entries: entries is not None and len(entries) >= 1,
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2.0,
        ctx=ctx,
    )

    delete_resp = ssm.delete_inventory(TypeName=type_name, SchemaDeleteOption="DeleteSchema")
    deletion_id = delete_resp["DeletionId"]
    assert delete_resp["TypeName"] == type_name, (
        f"expected DeleteInventory to echo TypeName={type_name!r}, got {delete_resp['TypeName']!r}"
    )
    # DeletionSummary counts are not asserted: AWS reports them inconsistently for the same
    # one-item deletion (TotalCount 0 or 1, SummaryItems empty or populated).

    # DeleteSchema clears the whole custom type; completion can take well over 10 minutes.
    final = _poll_until(
        lambda: ssm.describe_inventory_deletions(DeletionId=deletion_id)["InventoryDeletions"][0],
        lambda d: d["LastStatus"] in ("Complete", "Failed"),
        timeout_s=_budget_s(ctx, 1200.0),
        interval_s=2.0,
        ctx=ctx,
    )
    assert final["LastStatus"] == "Complete", f"deletion did not complete: {final}"
    assert final["TypeName"] == type_name, (
        f"expected deletion record TypeName={type_name!r}, got {final['TypeName']!r}"
    )

    # The deletion status alone doesn't prove the data is gone -- an independent read
    # (ListInventoryEntries, the same call that proved the item was there) must now
    # reject the deleted custom type, the way it does for a type that never existed.
    gone_err, gone_message = _expect_error(
        lambda: ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_name)
    )
    assert gone_err == "InvalidTypeNameException", (
        f"expected ListInventoryEntries to reject the deleted type with InvalidTypeNameException, got {gone_err!r}"
    )
    assert gone_message == f"Inventory type name {type_name} is not defined.", (
        f"ListInventoryEntries message: {gone_message!r}"
    )


def _try_list_entries(ssm, instance_id: str, type_name: str):
    try:
        resp = ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_name)
        return resp.get("Entries", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidTypeNameException":
            return None
        raise


def _expect_error(fn) -> tuple:
    """Return the (code, message) of the ClientError `fn` raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")

def _provision_connected_targets(ctx, count: int = 1) -> list[str]:
    """Create an IAM role + instance profile with AmazonSSMManagedInstanceCore, launch `count`
    EC2 instances in one call, and wait until all register Online with Systems Manager."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-behav-ssm-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    )

    profile_name = ctx.unique_name("sim2real-behav-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    name_tag = ctx.unique_name("sim2real-behav-ssm-target-")

    instance_ids: list[str] = []
    last_err = None
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while not instance_ids and time.monotonic() < deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=count,
                MaxCount=count,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue",
                "InvalidParameterValueError",
            ):
                raise
            time.sleep(2)
    if not instance_ids:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"run_instances never succeeded after IAM propagation: {last_err}")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))

    _wait_instances(ec2, instance_ids, "running", _budget_s(ctx, 600.0), ctx=ctx)

    deadline = time.monotonic() + _budget_s(ctx, 600)
    pending = set(instance_ids)
    while pending and time.monotonic() < deadline:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": list(pending)}]
        )["InstanceInformationList"]
        online = {i["InstanceId"] for i in info if i.get("PingStatus") == "Online"}
        pending -= online
        if pending:
            time.sleep(2)
    if pending:
        if _budget_spent(ctx):
            raise TimeoutError(f"instances {pending} reaching PingStatus=Online: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"instances {pending} never reached SSM PingStatus=Online in time")
    return instance_ids


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0, ctx=None) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
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


def _wait_instances(ec2, instance_ids, want: str, timeout_s: float, *, strict: bool = True, ctx=None) -> None:
    """Poll every 1 s until every instance is in state want; a strict wait fails on a dead end."""
    dead = {"running": ("shutting-down", "terminated", "stopping", "stopped")}.get(want, ())
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
        if len(states) == len(instance_ids) and all(s == want for s in states.values()):
            return
        if not strict:
            if time.monotonic() >= deadline:
                return
        else:
            assert not any(s in dead for s in states.values()), (
                f"instances {list(instance_ids)} reached {states!r} instead of {want!r}")
            if time.monotonic() >= deadline and ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"instances reaching {want!r}: the run budget ended first; not graded")
            assert time.monotonic() < deadline, (
                f"instances {list(instance_ids)} not {want!r} in time: {states!r}")
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
