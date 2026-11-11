"""e2e-activity-stream-start-stop-delivery-target."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-activity-stream-start-stop-delivery-target"
GROUP = "e2e"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartActivityStream makes the instance report an ACTIVE Kinesis delivery stream;
    StopActivityStream sets status stopped and removes the stream name from the instance.
    """
    rds = ctx.client("rds")
    kms = ctx.client("kms")
    kinesis = ctx.client("kinesis")
    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_ids = [s["SubnetId"] for s in az_subnets]

    subnet_group_name = ctx.unique_name("sim2real-rdsas-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real activity-stream behavioral test",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name))

    key_arn = kms.create_key(
        Description="sim2real RDS activity-stream behavioral test key",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]["Arn"]
    key_id = key_arn.split("/")[-1]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )

    instance_id = ctx.unique_name("sim2real-rdsas-db-")
    user = "s2radmin"
    password = _master_password()
    # Instance-level activity streams exist only for RDS for Oracle and SQL Server, and need at
    # least db.m5.large.
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.m5.large",
        Engine="sqlserver-se",
        AllocatedStorage=20,
        StorageType="gp2",
        MasterUsername=user,
        MasterUserPassword=password,
        DBSubnetGroupName=subnet_group_name,
        PubliclyAccessible=False,
        StorageEncrypted=True,
        KmsKeyId=key_arn,
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _cleanup_instance() -> None:
        try:
            rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
        except rds.exceptions.DBInstanceNotFoundFault:
            return
        rds.get_waiter("db_instance_deleted").wait(
            DBInstanceIdentifier=instance_id, WaiterConfig={"Delay": 2, "MaxAttempts": 750}
        )

    ctx.on_cleanup(_cleanup_instance)

    instance_arn = _poll_instance_available(rds, instance_id, timeout_s=_budget_s(ctx, 1800), ctx=ctx)[
        "DBInstanceArn"
    ]

    stream_name: str | None = None

    def _delete_kinesis_stream_best_effort() -> None:
        if not stream_name:
            return
        try:
            kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
        except kinesis.exceptions.ResourceNotFoundException:
            pass

    rds.start_activity_stream(
        ResourceArn=instance_arn, Mode="async", KmsKeyId=key_arn, ApplyImmediately=True
    )
    ctx.on_cleanup(_delete_kinesis_stream_best_effort)
    ctx.on_cleanup(lambda: _stop_activity_stream(rds, instance_arn, instance_id))

    started = _poll_activity_stream_status(
        rds, instance_id, "started", timeout_s=_budget_s(ctx, 600), ctx=ctx
    )
    assert started["ActivityStreamStatus"] == "started", (
        f"expected ActivityStreamStatus 'started', got {started['ActivityStreamStatus']!r}"
    )
    stream_name = started.get("ActivityStreamKinesisStreamName")
    assert stream_name, (
        f"expected a real ActivityStreamKinesisStreamName delivery target once started, got "
        f"{stream_name!r}"
    )

    # Confirm the target in Kinesis itself: an RDS-only read cannot tell a live stream from a label.
    delivery_deadline = time.monotonic() + _budget_s(ctx, 60)
    while True:
        delivery_status = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamStatus"
        ]
        if delivery_status == "ACTIVE" or time.monotonic() >= delivery_deadline:
            break
        time.sleep(1)
    if delivery_status != "ACTIVE" and _budget_spent(ctx):
        raise TimeoutError(f"Kinesis stream {stream_name!r} ACTIVE: the run budget ended first; not graded")
    assert delivery_status == "ACTIVE", (
        f"expected the backing Kinesis stream {stream_name!r} to be ACTIVE once RDS reports the "
        f"activity stream started, got {delivery_status!r}"
    )
    # RDS created this stream itself, so tag it to keep it findable by tag-based cleanup.
    kinesis.add_tags_to_stream(StreamName=stream_name, Tags={"sim2real": "true"})

    rds.stop_activity_stream(ResourceArn=instance_arn, ApplyImmediately=True)

    stopped = _poll_activity_stream_status(
        rds, instance_id, "stopped", timeout_s=_budget_s(ctx, 600), ctx=ctx
    )
    assert stopped["ActivityStreamStatus"] == "stopped", (
        f"expected ActivityStreamStatus 'stopped', got {stopped['ActivityStreamStatus']!r}"
    )
    assert not stopped.get("ActivityStreamKinesisStreamName"), (
        f"expected the Kinesis delivery target to be removed after stop, still got "
        f"{stopped.get('ActivityStreamKinesisStreamName')!r}"
    )


def _master_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Sim2Real1" + "".join(secrets.choice(alphabet) for _ in range(12))


def _pick_azs_with_subnets(ctx, count: int = 2) -> tuple[str, list[dict]]:
    """Return (vpc_id, [subnet, ...]) covering `count` distinct AZs, for a DBSubnetGroup."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < count:
        raise AssertionError(
            f"VPC {vpc_id} has subnets in only {len(by_az)} AZ(s); need >= {count} for an RDS "
            f"subnet group"
        )
    return vpc_id, list(by_az.values())[:count]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_instance_available(rds, instance_id: str, timeout_s: float, *, ctx) -> dict:
    """Poll until DBInstanceStatus == available and return the instance, or raise."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        desc = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        last = desc.get("DBInstanceStatus")
        if last == "available":
            return desc
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance {instance_id!r} available: the run budget ended first; not graded")
    raise AssertionError(
        f"instance {instance_id!r} never reached 'available' within {timeout_s:.0f}s, last seen "
        f"{last!r}"
    )


def _poll_activity_stream_status(rds, instance_id: str, want_status: str, timeout_s: float, *, ctx) -> dict:
    """Poll until ActivityStreamStatus == want_status and return the instance, or raise."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        last = desc.get("ActivityStreamStatus")
        if last == want_status:
            return desc
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"instance {instance_id!r} ActivityStreamStatus {want_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"instance {instance_id!r} ActivityStreamStatus never reached {want_status!r} within "
        f"{timeout_s:.0f}s, last seen {last!r}"
    )


def _stop_activity_stream(rds, instance_arn: str, instance_id: str) -> None:
    """Stop the activity stream; return once it is stopped/stopping or the instance is gone, raise the rest."""
    deadline = time.monotonic() + 120
    while True:
        try:
            rds.stop_activity_stream(ResourceArn=instance_arn, ApplyImmediately=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("DBInstanceNotFound", "ResourceNotFoundFault"):
                return
            if code != "InvalidDBInstanceState":
                raise
            status = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0].get(
                "ActivityStreamStatus"
            )
            if status in ("stopped", "stopping"):
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
