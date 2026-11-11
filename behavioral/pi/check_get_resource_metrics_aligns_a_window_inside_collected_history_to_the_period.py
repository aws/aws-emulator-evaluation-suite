"""get-resource-metrics-aligns-a-window-inside-collected-history-to-the-period."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags


CHECK = "get-resource-metrics-aligns-a-window-inside-collected-history-to-the-period"
GROUP = "data-plane"
SERVICES = ["pi"]


#: The sample-collection ceiling, not a sleep: PI collection lags the instance becoming available.
_FIRST_SAMPLE_S = 600.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """For a window inside the instance's collected history, AlignedStartTime is StartTime floored to
    a PeriodInSeconds boundary and AlignedEndTime is a period boundary between EndTime aligned up and
    the call-time clock floored, so a target that echoes the unaligned request back fails.
    Reference: https://docs.aws.amazon.com/performance-insights/latest/APIReference/API_GetResourceMetrics.html
    """
    dbi = _create_pi_source(ctx)
    pi = ctx.client("pi")

    period_s = 60
    period = timedelta(seconds=period_s)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)

    def _floor_to_period(ts: datetime) -> datetime:
        return epoch + ((ts - epoch) // period) * period

    def _ceil_to_period(ts: datetime) -> datetime:
        floored = _floor_to_period(ts)
        return floored if floored == ts else floored + period

    # PI clips AlignedStartTime to when the instance's history begins, so the graded window starts
    # 17 s past a sampled datapoint that follows the earliest one: floored, StartTime is that
    # datapoint's Timestamp, inside the collected history and already in the past.
    start = _sampled_after_first(ctx, pi, dbi) + timedelta(seconds=17)
    now_before = datetime.now(timezone.utc)
    # An unaligned EndTime: in the past when the clock is far enough along, else one period ahead.
    end = now_before - timedelta(seconds=23)
    if end <= start:
        end = start + period
    resp = pi.get_resource_metrics(
        ServiceType="RDS",
        Identifier=dbi,
        MetricQueries=[{"Metric": "db.load.avg"}],
        StartTime=start,
        EndTime=end,
        PeriodInSeconds=period_s,
    )
    now_after = datetime.now(timezone.utc)

    expected_start = _floor_to_period(start)
    assert resp["AlignedStartTime"] == expected_start, (
        f"AlignedStartTime {resp['AlignedStartTime']} must equal StartTime {start} floored to "
        f"the nearest {period_s}s boundary ({expected_start})"
    )
    # pi#GetResourceMetricsResponse$AlignedEndTime: aligned to a period boundary and >= EndTime,
    # i.e. EndTime aligned up. AWS has also answered the call-time clock floored to a boundary,
    # which can land before EndTime; both are accepted, and nothing outside them.
    aligned_end = resp["AlignedEndTime"]
    lowest = min(_ceil_to_period(end), _floor_to_period(now_before))
    highest = max(_ceil_to_period(end), _floor_to_period(now_after))
    assert _floor_to_period(aligned_end) == aligned_end, (
        f"AlignedEndTime {aligned_end} must sit on a {period_s}s boundary"
    )
    assert lowest <= aligned_end <= highest, (
        f"AlignedEndTime {aligned_end} must lie between {lowest} (the lower of EndTime {end} "
        f"aligned up and the call-time clock floored) and {highest}; observed clock "
        f"{now_before}..{now_after}"
    )


def _sampled_after_first(ctx, pi, dbi: str) -> datetime:
    """The Timestamp of the second db.load.avg datapoint carrying a Value over the last 30 minutes,
    once it lies at least 60 s in the past; polls until PI has collected it, bounded by the run's
    remaining time."""
    left = ctx.time_left()
    cap = _FIRST_SAMPLE_S if left is None else max(1.0, min(_FIRST_SAMPLE_S, left - 30.0))
    deadline = time.monotonic() + cap
    while True:
        now = datetime.now(timezone.utc)
        resp = pi.get_resource_metrics(
            ServiceType="RDS",
            Identifier=dbi,
            MetricQueries=[{"Metric": "db.load.avg"}],
            StartTime=now - timedelta(minutes=30),
            EndTime=now,
            PeriodInSeconds=60,
        )
        stamps = sorted(
            p["Timestamp"] for m in resp["MetricList"] for p in m["DataPoints"] if "Value" in p
        )
        if len(stamps) >= 2 and stamps[1] <= now - timedelta(seconds=60):
            return stamps[1]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"Performance Insights collected no second db.load.avg sample for {dbi} "
                f"within {cap:.0f}s"
            )
        time.sleep(5)


# ===== helpers =====
def _create_pi_source(ctx) -> str:
    """Create this check's own PI-enabled RDS instance in the run's shared network, register its
    teardown, and return its DbiResourceId once it is available.

    The report operations need Database Insights in advanced mode, not bare Performance
    Insights. The instance is private and nothing connects to it (the checks only call the pi
    API about it), so its own security group admits nothing; the group exists so the teardown
    can wait for the instance's network interfaces to detach. The admin password is random per
    run.
    """
    import secrets as _secrets
    import time as _time
    from botocore.exceptions import ClientError as _ClientError

    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    network = ctx.network()
    db_id = ctx.unique_name("sim2real-behav-pi-")
    subnet_group_name = f"{db_id}-subnets"
    tags = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]
    sg_id = ec2.create_security_group(
        GroupName=f"{db_id}-sg",
        Description="sim2real pi check",
        VpcId=network.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_pi_source(rds, ec2, db_id, subnet_group_name, sg_id))
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real pi check",
        SubnetIds=network.subnet_ids,
        Tags=tags,
    )
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.medium",
        Engine="mysql",
        MasterUsername="piadmin",
        MasterUserPassword=_secrets.token_urlsafe(18),
        AllocatedStorage=20,
        EnablePerformanceInsights=True,
        DatabaseInsightsMode="advanced",
        PerformanceInsightsRetentionPeriod=465,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        MultiAZ=False,
        StorageType="gp2",
        DBSubnetGroupName=subnet_group_name,
        VpcSecurityGroupIds=[sg_id],
        Tags=tags,
    )

    deadline = _time.monotonic() + 1200
    desc = {}
    while _time.monotonic() < deadline:
        try:
            desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        except _ClientError as exc:
            if exc.response["Error"]["Code"] != "DBInstanceNotFound":
                raise
        status = desc.get("DBInstanceStatus")
        if status == "available":
            break
        if status in ("failed", "incompatible-parameters", "incompatible-network", "storage-full"):
            raise AssertionError(f"RDS instance {db_id} entered a bad state: {status}")
        _time.sleep(5)
    else:
        raise AssertionError(
            f"RDS instance {db_id} never became available (last status: {desc.get('DBInstanceStatus')})"
        )
    assert desc.get("DatabaseInsightsMode") == "advanced", (
        f"expected Database Insights advanced mode on {db_id}, got {desc.get('DatabaseInsightsMode')!r}"
    )
    return desc["DbiResourceId"]


def _delete_pi_source(rds, ec2, db_id, subnet_group_name, sg_id):
    """Delete the instance (no final snapshot), wait for its network interfaces to detach, then
    delete its subnet group and its security group, waiting for each delete. Every step runs even
    if an earlier one fails; then the teardown raises naming each step that failed. The waits sum
    to at most 870 s, inside the 900 s teardown budget of a suite that declares long waits.
    """
    import time as _time
    from botocore.exceptions import ClientError as _ClientError

    def _gone(delete, describe, gone_code, busy_codes, timeout_s):
        deadline = _time.monotonic() + timeout_s
        deleted = False
        while True:
            try:
                if not deleted:
                    delete()
                    deleted = True
                describe()
            except _ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == gone_code:
                    return
                if code not in busy_codes:
                    raise
            if _time.monotonic() >= deadline:
                raise TimeoutError(f"still present after {timeout_s}s")
            _time.sleep(15)

    def _enis_detached(timeout_s):
        deadline = _time.monotonic() + timeout_s
        while True:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "group-id", "Values": [sg_id]}]
            )["NetworkInterfaces"]
            if not enis:
                return
            if _time.monotonic() >= deadline:
                ids = [e["NetworkInterfaceId"] for e in enis]
                raise TimeoutError(f"{ids} still attached after {timeout_s}s")
            _time.sleep(15)

    # Wire codes as the rds model's awsQueryError traits give them: DBInstanceNotFound and
    # InvalidDBInstanceState drop "Fault"; DBSubnetGroupNotFoundFault and
    # InvalidDBSubnetGroupStateFault keep it.
    steps = [
        (f"instance {db_id}", lambda: _gone(
            lambda: rds.delete_db_instance(
                DBInstanceIdentifier=db_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
            ),
            lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id),
            "DBInstanceNotFound", {"InvalidDBInstanceState"}, 600,
        )),
        (f"network interfaces in {sg_id}", lambda: _enis_detached(120)),
        (f"subnet group {subnet_group_name}", lambda: _gone(
            lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name),
            lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=subnet_group_name),
            "DBSubnetGroupNotFoundFault", {"InvalidDBSubnetGroupStateFault"}, 60,
        )),
        (f"security group {sg_id}", lambda: _gone(
            lambda: ec2.delete_security_group(GroupId=sg_id),
            lambda: ec2.describe_security_groups(GroupIds=[sg_id]),
            "InvalidGroup.NotFound", {"DependencyViolation"}, 90,
        )),
    ]
    failures = []
    for what, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - every step runs; each failure is raised below
            failures.append(f"{what}: {exc!r}")
    if failures:
        raise RuntimeError("pi teardown failed: " + "; ".join(failures))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
