"""obs-rds-2-forged-aurora-role-metric-rejected."""

# On real AWS, PutMetricData(Namespace="AWS/RDS", MetricName="DatabaseConnections",
# Dimensions=[DBClusterIdentifier=<absent>, Role=WRITER]) returns HTTP 400, Error.Code
# "InvalidParameterValue", Message "The value AWS/ for parameter Namespace is invalid.";
# DescribeDBClusters on that identifier returns HTTP 404 "DBClusterNotFoundFault".

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-rds-2-forged-aurora-role-metric-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "rds"]

_NS = "AWS/RDS"
_METRIC = "DatabaseConnections"
#: A value no real connection count in this check can produce, so its appearance is unambiguous.
_FORGED = 4242.0
_ARRIVAL_CEILING_S = 900.0
#: AWS names only the reserved prefix, not the namespace the caller sent.
_NS_REFUSAL = "The value AWS/ for parameter Namespace is invalid."


@tags("axis:rejection", "cap:c2", "concern:metrics", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """PutMetricData forging AWS/RDS DatabaseConnections with the Aurora Role dimensions is refused
    with 400 InvalidParameterValue and the series stays absent, while the same datum in a custom
    namespace reads back: a customer must not overwrite the series alarms and autoscaling act on."""
    rds = ctx.client("rds")
    cw = ctx.client("cloudwatch")
    start = datetime.now(timezone.utc) - timedelta(minutes=10)

    # The forged dimension names a cluster that does not exist, and is unique to this run, so the
    # absence asserted below is a property of the query rather than of who else uses the account.
    ghost = ctx.unique_name("sim2real-obs-forged-")
    code, status, message = _error(lambda: rds.describe_db_clusters(DBClusterIdentifier=ghost),
                          what=f"DescribeDBClusters({ghost!r})")
    want = ("DBClusterNotFoundFault", 404, f"DBCluster {ghost} not found.")
    assert (code, status, message) == want, (
        f"the forged dimension must name no cluster; DescribeDBClusters returned "
        f"code={code!r} status={status!r} message={message!r}"
    )
    dims = [{"Name": "DBClusterIdentifier", "Value": ghost}, {"Name": "Role", "Value": "WRITER"}]
    datum = {"MetricName": _METRIC, "Dimensions": dims, "Value": _FORGED, "Unit": "Count"}

    # ---- the refusal ---------------------------------------------------------------------------
    code, status, message = _error(lambda: cw.put_metric_data(Namespace=_NS, MetricData=[datum]),
                          what=f"PutMetricData into {_NS!r}")
    assert (code, status, message) == ("InvalidParameterValue", 400, _NS_REFUSAL), (
        f"PutMetricData into the service-owned namespace {_NS!r} returned code={code!r} "
        f"status={status!r} message={message!r}; real AWS refuses it with "
        f"InvalidParameterValue/400 {_NS_REFUSAL!r}"
    )

    # ---- positive control: the same datum outside AWS/ is accepted and reads back ------------
    custom_ns = ctx.unique_name("Sim2Real/obs-rds-2-")
    cw.put_metric_data(Namespace=custom_ns, MetricData=[datum])
    custom = _poll(
        lambda: _points(cw, custom_ns, dims, start),
        lambda pts: bool(pts),
        description=f"the control datum in custom namespace {custom_ns!r} reading back",
    )
    assert [p["Maximum"] for p in custom] == [_FORGED], (
        f"the control datum in {custom_ns!r} read back as {custom!r}, expected one {_FORGED}"
    )
    assert [p.get("Unit") for p in custom] == ["Count"], (
        f"the control datum's Unit must read back as 'Count'; got {custom!r}"
    )

    # ---- effect absent, behind the control's arrival -------------------------------------------
    forged = _points(cw, _NS, dims, start)
    assert forged == [], (
        f"the refused datum surfaced in the service-owned series {_NS} {_METRIC} "
        f"DBClusterIdentifier={ghost} Role=WRITER: {forged!r}"
    )
    listed = [
        m for page in cw.get_paginator("list_metrics").paginate(
            Namespace=_NS, MetricName=_METRIC,
            Dimensions=[{"Name": "DBClusterIdentifier", "Value": ghost}],
        ) for m in page.get("Metrics", [])
    ]
    assert listed == [], (
        f"ListMetrics must not catalogue a refused {_NS} {_METRIC} series for {ghost}; got "
        f"{listed!r}"
    )


# ===== helpers =====
def _error(fn, *, what) -> tuple[str, int, str]:
    """(Error.Code, HTTP status, Error.Message) of a call expected to fail. An unexpected SUCCESS
    raises: for the put, the forged datum was accepted, which is the strongest failure this check
    exists to catch."""
    try:
        fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response["ResponseMetadata"]["HTTPStatusCode"],
            exc.response["Error"].get("Message"),
        )
    raise AssertionError(f"{what} SUCCEEDED; real AWS refuses it")


def _points(cw, namespace, dims, start):
    dps = cw.get_metric_statistics(
        Namespace=namespace, MetricName=_METRIC, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5), Period=60,
        Statistics=["Maximum"],
    )["Datapoints"]
    return sorted(dps, key=lambda d: d["Timestamp"])


def _poll(probe, ok, *, timeout_s=_ARRIVAL_CEILING_S, interval_s=15.0, description="value"):
    """Poll until ok(value); RAISE past the ceiling, never return a stale value."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = probe()
        if ok(got):
            return got
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} never arrived within {timeout_s}s; last {got!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
