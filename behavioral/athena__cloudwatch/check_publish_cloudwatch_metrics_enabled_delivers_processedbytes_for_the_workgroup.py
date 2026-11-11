"""publish-cloudwatch-metrics-enabled-delivers-processedbytes-for-the-workgroup."""
from __future__ import annotations

import datetime as dt
import time

from behavioral_harness import tags

CHECK = "publish-cloudwatch-metrics-enabled-delivers-processedbytes-for-the-workgroup"
GROUP = "telemetry"
SERVICES = ["athena", "cloudwatch"]

_NAMESPACE = "AWS/Athena"
_METRIC = "ProcessedBytes"
_ENGINE_METRIC = "EngineExecutionTime"


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket. Athena writes `<qid>.csv`, `<qid>.csv.metadata` and
    `<qid>.txt` into the output location, so DeleteBucket alone would fail. No bare
    `except Exception`: a teardown that cannot finish must surface rather than leak silently."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "publish-cloudwatch-metrics-processedbytes"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _output_location(ctx):
    return f"s3://{_make_bucket(ctx, 'sim2real-xsvc-athena-results-')}/results/"


def _start_query(athena, out, query_string, workgroup=None, database=None):
    kwargs = {"QueryString": query_string}
    if out:
        kwargs["ResultConfiguration"] = {"OutputLocation": out}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a terminal state with a bounded deadline; raises on timeout."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _run_sql(athena, out, sql, database=None, workgroup=None):
    qid = _start_query(athena, out, sql, database=database, workgroup=workgroup)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}")
    return qid


def _data_rows(results):
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:].
    Hard-subscripted so a missing ResultSet raises."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _dml_name(database, table):
    """DML goes through the Trino parser (double-quoted identifiers); DDL through Hive
    (backticks)."""
    return f'"{database}"."{table}"'


def _wg_dim(workgroup):
    return [{"Name": "WorkGroup", "Value": workgroup}]


def _query_state_type_dims(workgroup, state="SUCCEEDED", qtype="DML"):
    return [
        {"Name": "QueryState", "Value": state},
        {"Name": "QueryType", "Value": qtype},
        {"Name": "WorkGroup", "Value": workgroup},
    ]


def _datapoints(cw, metric, dimensions, start, end):
    """Every datapoint for one metric/dimension pair."""
    resp = cw.get_metric_statistics(
        Namespace=_NAMESPACE, MetricName=metric, Dimensions=dimensions,
        StartTime=start, EndTime=end, Period=60, Statistics=["Sum", "SampleCount"])
    return resp.get("Datapoints", [])


def _await_datapoints(cw, metric, dimensions, start, *, timeout_s, interval_s, description,
                      ctx=None):
    """Poll until at least one datapoint exists; return (datapoints, elapsed_seconds).
    Raises on timeout; the absence leg reports the elapsed time."""
    began = time.monotonic()
    deadline = began + timeout_s
    while time.monotonic() < deadline:
        end = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
        points = _datapoints(cw, metric, dimensions, start, end)
        if points:
            return points, time.monotonic() - began
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} did not appear in CloudWatch within {timeout_s}s "
        f"(namespace {_NAMESPACE}, metric {metric}, dimensions {dimensions!r})")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _metric_exists(cw, metric, dimensions):
    """Whether ListMetrics knows this metric/dimension pair at all — the second, independent
    observable that separates 'no datapoint yet' from 'this metric was never created'."""
    resp = cw.list_metrics(Namespace=_NAMESPACE, MetricName=metric, Dimensions=[
        {"Name": d["Name"], "Value": d["Value"]} for d in dimensions])
    return resp.get("Metrics", [])


# timing:real-time — metric: 44 s https://docs.aws.amazon.com/athena/latest/ug/query-metrics-viewing.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With PublishCloudWatchMetricsEnabled on, AWS/Athena ProcessedBytes (Sum == DataScannedInBytes,
    SampleCount 1) is delivered under both dimension sets; an identical workgroup with it off has
    no metric until the flag is turned on, after which its next query's bytes are delivered.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/query-metrics-viewing.html
    """
    athena = ctx.client("athena")
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-xsvc-athena-data-")

    marker = ctx.unique_name("").replace("-", "")[:12]
    # A body large enough that a fabricated or rounded byte figure cannot coincide with it.
    body = "".join(f"{i},row-{marker}\n" for i in range(200)).encode()
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-xsvc-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-xsvc-tbl-").replace("-", "_")
    # The DDL runs with NO WorkGroup, deliberately: ProcessedBytes is documented as not reported
    # for DDL, and keeping the DDL out of both workgroups removes any doubt about what the
    # SampleCount and Sum below are counting.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    wg_on = ctx.unique_name("sim2real-xsvc-athena-wg-on-")
    wg_off = ctx.unique_name("sim2real-xsvc-athena-wg-off-")
    for name, publish in ((wg_on, True), (wg_off, False)):
        athena.create_work_group(
            Name=name,
            Configuration={
                "ResultConfiguration": {"OutputLocation": out},
                "EnforceWorkGroupConfiguration": True,
                "PublishCloudWatchMetricsEnabled": publish,
            },
            Tags=[{"Key": "sim2real", "Value": "publish-cloudwatch-metrics-processedbytes"},
                  {"Key": "sim2real:managed", "Value": "true"}],
        )
        ctx.on_cleanup(
            lambda n=name: athena.delete_work_group(WorkGroup=n, RecursiveDeleteOption=True))
        stored = athena.get_work_group(WorkGroup=name)["WorkGroup"]["Configuration"][
            "PublishCloudWatchMetricsEnabled"]
        assert stored is publish, (
            f"workgroup {name!r} must observably hold PublishCloudWatchMetricsEnabled={publish!r} "
            f"before its effect is asserted; GetWorkGroup reported {stored!r}")

    # The window starts before the first DML, so the datapoint cannot be missed by a late window.
    window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=2)
    sql = f"SELECT count(*) AS n FROM {_dml_name(database, table)}"

    # --- the twin: the SAME query in both workgroups, back to back, differing only in the flag.
    on_qid = _start_query(athena, None, sql, workgroup=wg_on, database=database)
    off_qid = _start_query(athena, None, sql, workgroup=wg_off, database=database)
    for qid, name in ((on_qid, wg_on), (off_qid, wg_off)):
        state = _wait_terminal(athena, qid)
        assert state == "SUCCEEDED", (
            f"the query in workgroup {name!r} must SUCCEED so that both twins really ran; got "
            f"{state!r}")
    on_exec = athena.get_query_execution(QueryExecutionId=on_qid)["QueryExecution"]
    on_scanned = on_exec["Statistics"]["DataScannedInBytes"]
    on_total_ms = on_exec["Statistics"]["TotalExecutionTimeInMillis"]
    assert on_scanned == len(body), (
        f"the metrics-enabled query must really have read the {len(body)} bytes this check "
        f"uploaded, else the metric has nothing correct to agree with; got "
        f"DataScannedInBytes={on_scanned!r}")
    on_rows = _data_rows(athena.get_query_results(QueryExecutionId=on_qid))
    assert on_rows == [["200"]], (
        f"the query must have counted the 200 uploaded rows, got {on_rows!r}")

    # --- leg 1: the metric is DELIVERED for the enabled workgroup, with the right value and count.
    points, latency = _await_datapoints(
        cw, _METRIC, _wg_dim(wg_on), window_start,
        timeout_s=_budget_s(ctx, 420), interval_s=1.5,
        description=f"{_NAMESPACE}/{_METRIC} for the metrics-enabled workgroup {wg_on!r}",
        ctx=ctx)
    total_sum = sum(p["Sum"] for p in points)
    total_samples = sum(p["SampleCount"] for p in points)
    assert total_samples == 1.0, (
        f"exactly one DML query ran in {wg_on!r}, so ProcessedBytes must carry SampleCount 1 "
        f"across the window; got {total_samples!r} from {points!r}")
    assert total_sum == float(on_scanned), (
        f"ProcessedBytes must equal the bytes the query itself reported scanning "
        f"({on_scanned}, which is the exact length of the object this check uploaded); got "
        f"{total_sum!r} from {points!r}")

    # --- leg 2: the dimension set is right, not merely the aggregate.
    dimensioned, _ = _await_datapoints(
        cw, _METRIC, _query_state_type_dims(wg_on), window_start,
        timeout_s=_budget_s(ctx, 180), interval_s=1.5,
        description=(f"{_NAMESPACE}/{_METRIC} dimensioned by QueryState=SUCCEEDED, QueryType=DML, "
                     f"WorkGroup={wg_on!r}"), ctx=ctx)
    dim_sum = sum(p["Sum"] for p in dimensioned)
    assert dim_sum == float(on_scanned), (
        f"the QueryState/QueryType/WorkGroup-dimensioned ProcessedBytes must carry the same "
        f"{on_scanned} bytes as the WorkGroup-only series; got {dim_sum!r} from {dimensioned!r}")

    engine_points, _ = _await_datapoints(
        cw, _ENGINE_METRIC, _query_state_type_dims(wg_on), window_start,
        timeout_s=_budget_s(ctx, 180), interval_s=1.5,
        description=f"{_NAMESPACE}/{_ENGINE_METRIC} for {wg_on!r}", ctx=ctx)
    engine_sum = sum(p["Sum"] for p in engine_points)
    # A sub-millisecond engine run publishes 0 ms, so the lower bound is inclusive.
    assert 0 <= engine_sum <= float(on_total_ms), (
        f"EngineExecutionTime is published in milliseconds and TotalExecutionTime is documented to "
        f"include it, so the published sum must be in [0, {on_total_ms}]; got {engine_sum!r}")

    # --- leg 3, the absence, read once the enabled twin's metrics (its query ran back to back with
    #     the disabled one) are delivered, with a second independent observable; leg 4 proves it
    #     again by contrast. A bare sleep would prove nothing.
    off_points = _datapoints(
        cw, _METRIC, _wg_dim(wg_off), window_start,
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5))
    assert off_points == [], (
        f"workgroup {wg_off!r} has PublishCloudWatchMetricsEnabled=False, so no "
        f"{_NAMESPACE}/{_METRIC} datapoint may exist for it; found {off_points!r} "
        f"(the enabled twin's metric took {latency:.1f}s to appear)")
    off_metrics = _metric_exists(cw, _METRIC, _wg_dim(wg_off))
    assert off_metrics == [], (
        f"with metrics disabled the metric must not exist AT ALL for {wg_off!r}: ListMetrics "
        f"returned {off_metrics!r}")

    # --- leg 4, the repair: turn the withheld thing on and DEMAND delivery. A target that fakes
    #     the disabled state by never publishing anything fails here.
    athena.update_work_group(
        WorkGroup=wg_off, ConfigurationUpdates={"PublishCloudWatchMetricsEnabled": True})
    flipped = athena.get_work_group(WorkGroup=wg_off)["WorkGroup"]["Configuration"][
        "PublishCloudWatchMetricsEnabled"]
    assert flipped is True, (
        f"UpdateWorkGroup must turn metrics on for {wg_off!r}; GetWorkGroup reported {flipped!r}")
    repair_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    repair_qid = _start_query(athena, None, sql, workgroup=wg_off, database=database)
    repair_state = _wait_terminal(athena, repair_qid)
    assert repair_state == "SUCCEEDED", (
        f"the repaired workgroup's query must SUCCEED, got {repair_state!r}")
    repair_scanned = athena.get_query_execution(QueryExecutionId=repair_qid)["QueryExecution"][
        "Statistics"]["DataScannedInBytes"]
    repair_points, _ = _await_datapoints(
        cw, _METRIC, _wg_dim(wg_off), repair_start,
        timeout_s=_budget_s(ctx, 420), interval_s=1.5,
        description=(f"{_NAMESPACE}/{_METRIC} for {wg_off!r} once "
                     f"PublishCloudWatchMetricsEnabled was turned on"), ctx=ctx)
    repair_sum = sum(p["Sum"] for p in repair_points)
    assert repair_sum == float(repair_scanned), (
        f"the once-withheld metric must now carry the repaired query's own byte count "
        f"({repair_scanned}); got {repair_sum!r} from {repair_points!r}")
    # The repaired query ran after the disabled one, so once its datapoint is delivered a datapoint
    # for the disabled query would be too: the whole window must count the repaired query alone.
    off_window = _datapoints(
        cw, _METRIC, _wg_dim(wg_off), window_start,
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5))
    off_samples = sum(p["SampleCount"] for p in off_window)
    assert off_samples == 1.0, (
        f"only the query run after PublishCloudWatchMetricsEnabled was turned on may be counted for "
        f"{wg_off!r}; SampleCount across the window is {off_samples!r} from {off_window!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
