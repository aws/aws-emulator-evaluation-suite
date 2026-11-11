"""search-expression-discovers-series-server-side-and-is-refused-in-an-alarm."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-expression-discovers-series-server-side-and-is-refused-in-an-alarm"
GROUP = "metric-math"
SERVICES = ["cloudwatch"]

#: Three hosts with three DISTINCT sums, so a target that discovers the right number of series but
#: mixes up which datapoints belong to which cannot pass.
_HOSTS = {"alpha": 11.0, "bravo": 23.0, "charlie": 37.0}
_METRIC = "SearchableLoad"
#: Same namespace, same dimension name, different metric name: must NOT be returned.
_DECOY_METRIC = "UnrelatedGauge"
_DECOY_VALUE = 99.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SEARCH() query returns exactly the matching series, each labelled by host with its own sum
    and excluding a decoy metric; PutMetricAlarm refuses SEARCH while a plain math alarm is accepted.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-search-expressions.html"""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealSearchNs")
    control_alarm = ctx.unique_name("sim2real-search-control-")
    rejected_alarm = ctx.unique_name("sim2real-search-rejected-")
    stamp = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=2)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": _METRIC,
                "Dimensions": [{"Name": "Host", "Value": host}],
                "Timestamp": stamp,
                "Value": value,
                "Unit": "Count",
            }
            for host, value in _HOSTS.items()
        ]
        + [
            {
                "MetricName": _DECOY_METRIC,
                "Dimensions": [{"Name": "Host", "Value": "alpha"}],
                "Timestamp": stamp,
                "Value": _DECOY_VALUE,
                "Unit": "Count",
            }
        ],
    )

    expression = f"SEARCH('{{{namespace},Host}} MetricName=\"{_METRIC}\"', 'Sum', 60)"
    start = stamp - timedelta(minutes=1)
    end = stamp + timedelta(minutes=2)

    def _search() -> list[dict]:
        return cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "s1", "Expression": expression, "Period": 60, "ReturnData": True}
            ],
            StartTime=start,
            EndTime=end,
            ScanBy="TimestampAscending",
        )["MetricDataResults"]

    # SEARCH resolves against the metric index, which lags the datapoint store.
    results = _poll_until(
        _search,
        lambda rs: len(rs) == len(_HOSTS) and all(r.get("Values") for r in rs),
        timeout_s=300.0,
        interval_s=10.0,
        description=(
            f"the search expression {expression!r} discovered all {len(_HOSTS)} Host series with "
            f"datapoints; SEARCH resolves against CloudWatch's metric index, which lags the "
            f"datapoint store, and an exhausted poll here is a FAIL, not a skip"
        ),
    )

    # --- discovery: exactly the three matching series, and the decoy is not among them --------- #
    assert len(results) == len(_HOSTS), (
        f"the search returned {len(results)} series, expected {len(_HOSTS)} -- one per Host "
        f"published under {_METRIC!r}. Ids seen: {[r.get('Id') for r in results]!r}"
    )
    ids = [r["Id"] for r in results]
    # CloudWatch returns every discovered series under the query's own Id; only Label differs.
    assert all(i == "s1" for i in ids), (
        f"the search's result ids {ids!r} are not all the literal query id 's1'; CloudWatch "
        f"returns every discovered series under the query's own Id rather than minting a "
        f"distinct per-series id, so a client can only tell the series apart by Label"
    )
    for result in results:
        assert result["StatusCode"] == "Complete", (
            f"series {result['Id']!r} came back with StatusCode {result['StatusCode']!r}, "
            f"expected 'Complete' for a closed window entirely inside the retention period"
        )

    # --- attribution: each host's own value, matched through the server-generated Label -------- #
    by_host: dict[str, list[float]] = {}
    for result in results:
        label = result["Label"]
        matched = [host for host in _HOSTS if host in label]
        assert len(matched) == 1, (
            f"the server-generated Label {label!r} for result {result['Id']!r} names "
            f"{len(matched)} of the published hosts {sorted(_HOSTS)!r}; a searched series must be "
            f"labelled with the identity CloudWatch discovered, and nothing in the request "
            f"contains these host names in a position an echo could copy from"
        )
        by_host[matched[0]] = [float(v) for v in result["Values"]]
    assert set(by_host) == set(_HOSTS), (
        f"the search covered hosts {sorted(by_host)!r}, expected {sorted(_HOSTS)!r}"
    )
    for host, expected in _HOSTS.items():
        values = by_host[host]
        assert values == [expected], (
            f"host {host!r} came back with Sum values {values!r}, expected exactly [{expected!r}]. "
            f"The three hosts carry three distinct sums {sorted(_HOSTS.values())!r}, so a "
            f"transposition shows up here and nowhere else"
        )
    assert _DECOY_VALUE not in {v for vs in by_host.values() for v in vs}, (
        f"the search returned the decoy value {_DECOY_VALUE} published under the different metric "
        f"name {_DECOY_METRIC!r} in the same namespace with the same dimension name; the "
        f"expression scopes on MetricName and must exclude it"
    )

    # --- positive control: without it, a refusal of every Metrics-array alarm would pass ------ #
    control_queries = [
        {
            "Id": "m1",
            "MetricStat": {
                "Metric": {
                    "Namespace": namespace,
                    "MetricName": _METRIC,
                    "Dimensions": [{"Name": "Host", "Value": "alpha"}],
                },
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": False,
        },
        {"Id": "e1", "Expression": "m1 * 2", "ReturnData": True},
    ]
    cw.put_metric_alarm(
        AlarmName=control_alarm,
        Metrics=control_queries,
        Threshold=1000.0,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        TreatMissingData="notBreaching",
        ActionsEnabled=False,
        AlarmDescription="sim2real depth: positive control for the SEARCH-in-an-alarm refusal",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[control_alarm]))
    described = _describe(cw, control_alarm)
    assert {q["Id"] for q in described["Metrics"]} == {"m1", "e1"}, (
        f"the control alarm read back Metrics ids "
        f"{sorted(q['Id'] for q in described['Metrics'])!r}, expected ['e1', 'm1'] -- this alarm "
        f"exists solely to prove Metrics-array alarms are accepted at all in this account"
    )

    # --- the refusal: the identical alarm shape with a SEARCH expression instead --------------- #
    search_queries = [
        {"Id": "e1", "Expression": expression, "Period": 60, "ReturnData": True}
    ]
    code, message = _error_code(
        lambda: cw.put_metric_alarm(
            AlarmName=rejected_alarm,
            Metrics=search_queries,
            Threshold=1000.0,
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=1,
            TreatMissingData="notBreaching",
            ActionsEnabled=False,
        ),
        subject="a SEARCH() expression as an alarm's watched series",
    )
    assert code == "ValidationError", (
        f"PutMetricAlarm over a SEARCH expression raised {code!r}, expected ValidationError. A search expression cannot be "
        f"used within an alarm -- an alarm watches one time series and this query returned "
        f"{len(results)} -- so the call must be refused rather than silently alarming on one of "
        f"them or on their aggregate"
    )
    assert message == "SEARCH is not supported on Metric Alarms.", (
        f"expected the exact ValidationError message AWS returns, got {message!r}"
    )
    assert _describe_all(cw, [rejected_alarm]) == [], (
        f"the refused PutMetricAlarm created an alarm anyway: "
        f"{_describe_all(cw, [rejected_alarm])!r}"
    )

    # --- the search still resolves after the refusal ------------------------------------------ #
    # SEARCH reads an eventually consistent metric index, so one read can briefly miss series
    # an earlier read already returned; poll until the full set is back.
    _poll_until(
        _search,
        lambda rs: len(rs) == len(_HOSTS),
        timeout_s=120.0,
        interval_s=10.0,
        description=(
            f"after the alarm refusal the same search returning all {len(_HOSTS)} series -- the "
            f"refusal must be about the alarm, not about the expression"
        ),
    )

    # --- the deleted alarm is gone and unusable ----------------------------------------------- #
    cw.delete_alarms(AlarmNames=[control_alarm])
    assert _describe_all(cw, [control_alarm]) == [], (
        f"DeleteAlarms left {_describe_all(cw, [control_alarm])!r} behind"
    )
    dead, dead_message = _error_code(
        lambda: cw.set_alarm_state(
            AlarmName=control_alarm, StateValue="OK", StateReason="post-delete mutation probe"
        ),
        subject=f"SetAlarmState on the deleted alarm {control_alarm!r}",
    )
    assert dead == "ResourceNotFound", (
        f"a mutation on the deleted control alarm raised {dead!r}, expected ResourceNotFound"
    )
    assert dead_message == "", (
        f"expected the exact ResourceNotFound message AWS returns, got {dead_message!r}"
    )


def _describe_all(cw, names):
    out = []
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=list(names), AlarmTypes=["MetricAlarm"]
    ):
        out.extend(page.get("MetricAlarms", []))
    return out


def _describe(cw, alarm_name):
    for alarm in _describe_all(cw, [alarm_name]):
        if alarm["AlarmName"] == alarm_name:
            return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


def _error_code(fn, *, subject: str) -> tuple[str, str]:
    """Call fn() and return its error (code, message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"real AWS refuses {subject}, but the call SUCCEEDED and returned "
        f"{json.dumps(result, default=str)}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result) holds; fail on exhaustion."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
