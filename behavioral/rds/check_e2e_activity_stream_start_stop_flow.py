"""e2e-activity-stream-start-stop-flow."""
from __future__ import annotations

import secrets
import string
import time


from behavioral_harness import tags

CHECK = "e2e-activity-stream-start-stop-flow"
GROUP = "e2e"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Starting an activity stream on an encrypted RDS for SQL Server instance yields an active
    Kinesis association visible on the instance and on the stream; stopping it clears it."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    kms = ctx.client("kms")
    kinesis = ctx.client("kinesis")

    key_id = kms.create_key(
        Description="sim2real behavioral activity-stream CMK",
        Tags=[{"TagKey": "sim2real", "TagValue": "behav"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    kms_key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]

    subnet_ids = _pick_subnets_in_distinct_azs(ec2, count=2, ctx=ctx)
    subnet_group_name = ctx.unique_name("sim2real-actstream-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real behavioral activity-stream test",
        SubnetIds=subnet_ids,
    )
    ctx.on_cleanup(lambda: _retry_while_held(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name), "InvalidDBSubnetGroupStateFault", timeout_s=1200.0))

    instance_id = ctx.unique_name("sim2real-actstream-")
    password = _rand_password()
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        # Activity streams exist only on Oracle, SQL Server and Aurora, and need a large class
        # that SQL Server Express is not offered on, so Standard Edition on db.m5.large.
        Engine="sqlserver-se",
        DBInstanceClass="db.m5.large",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        DBSubnetGroupName=subnet_group_name,
        LicenseModel="license-included",
        StorageEncrypted=True,
        PubliclyAccessible=False,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    instance = _wait_instance_status(ctx, instance_id, "available", timeout_s=1800)
    instance_arn = instance["DBInstanceArn"]
    assert instance.get("ActivityStreamStatus", "stopped") == "stopped", (
        f"expected a freshly created instance to report no active activity stream, "
        f"got ActivityStreamStatus={instance.get('ActivityStreamStatus')!r}"
    )

    rds.start_activity_stream(
        ResourceArn=instance_arn, Mode="async", KmsKeyId=kms_key_arn, ApplyImmediately=True
    )
    instance = _wait_activity_stream_status(ctx, instance_id, "started", timeout_s=600)
    stream_name = instance["ActivityStreamKinesisStreamName"]
    assert stream_name, "no Kinesis stream name populated once the activity stream started"

    stream_deadline = time.monotonic() + _budget_s(ctx, 60)
    while True:
        stream = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        if stream["StreamStatus"] == "ACTIVE" or time.monotonic() >= stream_deadline:
            break
        time.sleep(1)
    if stream["StreamStatus"] != "ACTIVE" and _budget_spent(ctx):
        raise TimeoutError(f"Kinesis stream {stream_name!r} ACTIVE: the run budget ended first; not graded")
    assert stream["StreamStatus"] == "ACTIVE", f"backing Kinesis stream status was {stream['StreamStatus']!r}"

    rds.stop_activity_stream(ResourceArn=instance_arn, ApplyImmediately=True)
    instance = _wait_activity_stream_status(ctx, instance_id, "stopped", timeout_s=600)
    assert not instance.get("ActivityStreamKinesisStreamName"), (
        "Kinesis stream association was not cleared after stopping the activity stream"
    )


def _pick_subnets_in_distinct_azs(ec2, count: int = 2, *, ctx) -> list[str]:
    """Return `count` subnet ids in distinct AZs from a VPC, without depending on an
    ambient default VPC being present."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < count:
        raise AssertionError(
            f"VPC {vpc_id} has subnets in only {len(by_az)} AZ(s); need >= {count} for an RDS "
            f"subnet group"
        )
    return list(by_az.values())[:count]


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1200, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance {instance_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
    )


def _wait_activity_stream_status(ctx, instance_id, target_status, timeout_s=300, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last.get("ActivityStreamStatus") == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"instance {instance_id} ActivityStreamStatus {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"ActivityStreamStatus never reached {target_status!r}, "
        f"last observed {last and last.get('ActivityStreamStatus')!r}"
    )


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=2.0):
    """Run a teardown delete, retrying while AWS refuses it because a dependent resource deleted just
    before it is still going away; after the deadline the last refusal is raised."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
