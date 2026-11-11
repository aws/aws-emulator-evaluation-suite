"""put-inventory-malformed-instance-id-blocked."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-inventory-malformed-instance-id-blocked"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """PutInventory for a well-formed but unregistered instance id fails InvalidInstanceId.

    No inventory is listed for that id, while PutInventory on a real managed node succeeds."""
    ssm = ctx.client("ssm")
    instance_id = _provision_ssm_managed_instance(ctx)
    type_name = "Custom:Sim2RealBogusIdTest"
    capture_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    item = {
        "TypeName": type_name,
        "SchemaVersion": "1.0",
        "CaptureTime": capture_time,
        "Content": [{"Attr1": "value1"}],
    }

    ssm.put_inventory(InstanceId=instance_id, Items=[item])
    entries = _poll_until(
        lambda: _entries_once_defined(ssm, instance_id, type_name),
        lambda es: len(es) >= 1,
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2,
    )
    if not len(entries) >= 1 and _budget_spent(ctx):
        raise TimeoutError("the inventory entry listing: the run budget ended first; not graded")
    assert len(entries) == 1, f"expected exactly 1 inventory entry for {instance_id}, got {entries!r}"

    bogus_id = "mi-00000000000000000"
    code, message = _client_error(lambda: ssm.put_inventory(InstanceId=bogus_id, Items=[item]))
    assert code == "InvalidInstanceId", (
        f"PutInventory against unregistered {bogus_id} should fail InvalidInstanceId, got {code!r}"
    )
    assert message == "", f"unexpected message {message!r}"

    # ListInventoryEntries does not validate InstanceId; it reports no entries. The built-in
    # type is used because a just-registered custom type can transiently fail
    # InvalidTypeNameException until its schema propagates.
    builtin_entries = ssm.list_inventory_entries(
        InstanceId=bogus_id, TypeName="AWS:InstanceInformation"
    )["Entries"]
    assert builtin_entries == [], (
        f"ListInventoryEntries(InstanceId={bogus_id}, TypeName=AWS:InstanceInformation) should "
        f"report no entries for a never-registered instance, got {builtin_entries!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except Exception:
        pass


def _entries_once_defined(ssm, instance_id: str, type_name: str) -> list:
    """ListInventoryEntries for type_name, reading InvalidTypeNameException as no entries yet;
    a just-registered custom type raises it until its schema propagates."""
    try:
        return ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_name)["Entries"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidTypeNameException":
            raise
        return []


def _client_error(fn) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


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


def _ssm_ami_id(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _provision_ssm_managed_instance(ctx, timeout_s: float = 420.0) -> str:
    """Launch an EC2 instance with AmazonSSMManagedInstanceCore; wait until it is Online in SSM."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ssm-role-")
    profile_name = ctx.unique_name("sim2real-ssm-prof-")
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup_role() -> None:
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup_role)

    iam.create_instance_profile(InstanceProfileName=profile_name)
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)

    def _cleanup_profile() -> None:
        _safe(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
        )
        _safe(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    ctx.on_cleanup(_cleanup_profile)

    ami_id = _ssm_ami_id(ctx)
    name_tag = ctx.unique_name("sim2real-ssm-node-")
    instance_id = None
    last_err = None
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValue":
                time.sleep(2)
                continue
            raise
    if instance_id is None:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"could not launch instance with IAM profile: {last_err}")

    def _cleanup_instance() -> None:
        _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    ctx.on_cleanup(_cleanup_instance)

    _wait_running(ec2, [instance_id], _budget_s(ctx, 600.0), ctx=ctx)

    def _ping_status():
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp["InstanceInformationList"]
        return infos[0]["PingStatus"] if infos else None

    status = _poll_until(_ping_status, lambda s: s == "Online", timeout_s=_budget_s(ctx, timeout_s), interval_s=2)
    if status != "Online":
        if _budget_spent(ctx):
            raise TimeoutError(f"instance {instance_id} reaching PingStatus=Online: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"managed instance {instance_id} never reached Online ping status")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
