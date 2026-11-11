"""get-resource-metrics-returns-full-datapoint-series."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags


CHECK = "get-resource-metrics-returns-full-datapoint-series"
GROUP = "data-plane"
SERVICES = ["pi"]


# timing:real-time — metric: 60 s
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """GetResourceMetrics for db.load.avg on a Performance Insights instance returns one metric with the
    expected number of datapoints, each with a Timestamp and a float Value, at least one of them set
    (polled, since collection lags DB availability)."""
    dbi = _create_pi_source(ctx)
    pi = ctx.client("pi")

    def _query():
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=30)
        return pi.get_resource_metrics(
            ServiceType="RDS",
            Identifier=dbi,
            MetricQueries=[{"Metric": "db.load.avg"}],
            StartTime=start,
            EndTime=now,
            PeriodInSeconds=60,
        )

    resp = _poll_until_datapoints(_query, timeout_s=600.0)

    assert resp["Identifier"] == dbi
    metric_list = resp["MetricList"]
    assert len(metric_list) == 1
    assert metric_list[0]["Key"]["Metric"] == "db.load.avg"
    data_points = metric_list[0]["DataPoints"]

    # The aligned window is the target's own reported grid: GetResourceMetrics always returns one
    # Timestamp per period across [AlignedStartTime, AlignedEndTime) regardless of whether PI has
    # collected a sample yet, so the series length is derived from the response, never guessed.
    aligned_start = resp["AlignedStartTime"]
    aligned_end = resp["AlignedEndTime"]
    expected_len = round((aligned_end - aligned_start).total_seconds() / 60)
    assert len(data_points) == expected_len, (
        f"expected {expected_len} periods between AlignedStartTime={aligned_start} and "
        f"AlignedEndTime={aligned_end} at 60s granularity, got {len(data_points)}"
    )

    values = [p["Value"] for p in data_points if "Value" in p]
    assert len(values) > 0, (
        "expected a populated time series for db.load.avg -- every point had a Timestamp but "
        "none carried a Value, i.e. an all-placeholder grid"
    )
    for point in data_points:
        assert "Timestamp" in point
        # A DataPoint's Value is only present when PI actually has a sample for that period --
        # a period with no sample (e.g. right at the collection boundary) legitimately omits it,
        # so only type-check it when present rather than assuming every point carries one.
        if "Value" in point:
            assert isinstance(point["Value"], float)


def _poll_until_datapoints(query_fn, timeout_s: float):
    """Bounded poll: retry query_fn() until >=1 DataPoint carries an actual Value, or raise.

    GetResourceMetrics always returns a full grid of Timestamp-only placeholders for the
    aligned window, even with zero PI samples collected -- so "DataPoints is non-empty" is
    true on the very first call and never actually waits for real data. The thing worth
    waiting for is a Value.
    """
    import time

    deadline = time.monotonic() + timeout_s
    last_resp = None
    while time.monotonic() < deadline:
        last_resp = query_fn()
        metric_list = last_resp.get("MetricList", [])
        if metric_list and any("Value" in p for p in metric_list[0].get("DataPoints", [])):
            return last_resp
        time.sleep(2)
    last_points = (
        last_resp.get("MetricList", [{}])[0].get("DataPoints") if last_resp else None
    )
    raise TimeoutError(
        f"no db.load.avg datapoint carried a Value after {timeout_s:.0f}s of polling "
        f"(last MetricList DataPoints={last_points!r})"
    )


def _create_pi_source(ctx) -> str:
    """Create a PI-enabled RDS instance (Database Insights advanced mode, which the report ops
    require) owned by this check, wait for it to be available, and delete it at cleanup."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-pi-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.medium",
        Engine="mysql",
        MasterUsername="piadmin",
        MasterUserPassword="Sim2Real-Pw-12345",
        AllocatedStorage=20,
        EnablePerformanceInsights=True,
        DatabaseInsightsMode="advanced",
        PerformanceInsightsRetentionPeriod=465,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        MultiAZ=False,
        StorageType="gp2",
        Tags=[{"Key": "Name", "Value": db_id}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=db_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        )
    )
    waiter = rds.get_waiter("db_instance_available")
    waiter.wait(DBInstanceIdentifier=db_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
    desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
    assert desc.get("DatabaseInsightsMode") == "advanced", (
        f"expected Database Insights advanced mode on {db_id}, got {desc.get('DatabaseInsightsMode')!r}"
    )
    return desc["DbiResourceId"]


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
