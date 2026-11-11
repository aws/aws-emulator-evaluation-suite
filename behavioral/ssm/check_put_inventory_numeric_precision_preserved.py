"""put-inventory-numeric-precision-preserved."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-inventory-numeric-precision-preserved"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """A high-decimal-precision numeric custom-inventory content value survives
    PutInventory -> ListInventoryEntries without truncation or rounding."""
    ssm = ctx.client("ssm")
    instance_id = _provision_ssm_managed_instance(ctx)

    precise_value = "3.14159265358979323846264338327950288419716939937510582097494459"
    type_name = "Custom:HighPrecision"
    capture_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    ssm.put_inventory(
        InstanceId=instance_id,
        Items=[
            {
                "TypeName": type_name,
                "SchemaVersion": "1.0",
                "CaptureTime": capture_time,
                "Content": [{"Value": precise_value}],
            }
        ],
    )

    def _list_entries():
        try:
            return ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_name).get(
                "Entries", []
            )
        except ssm.exceptions.InvalidTypeNameException:
            # SSM registers a brand-new custom type name asynchronously after
            # PutInventory; ListInventoryEntries can 400 on it for a window
            # afterwards, so that specific error means "not visible yet", not failure.
            return []

    entries = _poll_until(
        _list_entries,
        lambda entries: len(entries) == 1,
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=2,
        ctx=ctx,
    )
    assert entries[0]["Value"] == precise_value, (
        f"numeric precision was altered: expected {precise_value!r}, got {entries[0]['Value']!r}"
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
    ctx=None,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


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


def _provision_ssm_managed_instance(ctx) -> str:
    """Launch a minimal EC2 instance with an SSM instance profile and wait for it to
    register with SSM as an Online managed node."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ssm-role-")
    profile_name = ctx.unique_name("sim2real-ssm-profile-")
    trust_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    )
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    )
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
        )
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]

    instance_id = None
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": ctx.unique_name("sim2real-ssm-managed-")}
                        ],
                    }
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except Exception as exc:  # IAM instance-profile propagation lag
            last_error = exc
            time.sleep(2)
    if instance_id is None:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"could not launch instance (IAM propagation?): {last_error}")

    ctx.on_cleanup(lambda: _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))
    _wait_running(ec2, [instance_id], _budget_s(ctx, 600.0), ctx=ctx)

    _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        ).get("InstanceInformationList", []),
        lambda infos: bool(infos) and infos[0].get("PingStatus") == "Online",
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2,
        ctx=ctx,
    )
    return instance_id


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
