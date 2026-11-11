"""obs-cloudwatch-1-usage-callcount-tracks-calls-against-never-called-control."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cloudwatch-1-usage-callcount-tracks-calls-against-never-called-control"
GROUP = "usage-metrics"
SERVICES = ["cloudwatch"]

_NS = "AWS/Usage"
_METRIC = "CallCount"
_N_CALLS = 8
_CEILING_S = 600.0
_POLL_S = 15.0
_USAGE_DIMS = ["Class", "Resource", "Service", "Type"]


def _dims(resource: str, service: str = "CloudWatch") -> list[dict]:
    return [
        {"Name": "Service", "Value": service},
        {"Name": "Class", "Value": "None"},
        {"Name": "Type", "Value": "API"},
        {"Name": "Resource", "Value": resource},
    ]


def _query(qid: str, namespace: str, dims: list[dict]) -> dict:
    return {
        "Id": qid,
        "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": _METRIC, "Dimensions": dims},
            "Period": 60,
            "Stat": "Sum",
        },
        "ReturnData": True,
    }


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Service-Quota-Integration.html
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics",
      "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """AWS/Usage CallCount counts ListMetrics and a failed GetDashboard, a never-called twin stays
    at zero, the series has exactly {Class, Resource, Service, Type}, and AWS/Usage rejects puts.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Service-Quota-Integration.html"""
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + _CEILING_S

    def _remaining(what: str) -> float:
        left = deadline - time.monotonic()
        assert left > 0, f"{_CEILING_S:.0f}s ceiling exhausted while waiting for {what}"
        return left

    def _error(fn) -> tuple[str, str, int]:
        try:
            fn()
        except ClientError as e:
            return (e.response["Error"]["Code"], e.response["Error"].get("Message"),
                    e.response["ResponseMetadata"]["HTTPStatusCode"])
        raise AssertionError("call was ACCEPTED; real AWS rejects it")

    # --- beat 1: a fresh period, then exactly the calls under test ------------------------------ #
    # Starting on a fresh 60 s boundary keeps earlier calls out of the window; the control assumes
    # nothing else calls DeleteDashboards in it.
    boundary = (datetime.now(timezone.utc) + timedelta(minutes=1)).replace(second=0, microsecond=0)
    while datetime.now(timezone.utc) < boundary:
        left = _remaining("the next 60 s period boundary")
        gap = (boundary - datetime.now(timezone.utc)).total_seconds()
        time.sleep(max(0.05, min(1.0, gap, left)))
    window_start = boundary

    empty_ns = ctx.unique_name("Sim2RealUsageEmptyNs")
    for i in range(_N_CALLS):
        page = cw.list_metrics(Namespace=empty_ns)
        assert page["Metrics"] == [], (
            f"ListMetrics #{i + 1} on never-written namespace {empty_ns!r} returned "
            f"{page['Metrics']!r}"
        )
    missing = ctx.unique_name("sim2real-usage-missing-dash-")
    error = _error(lambda: cw.get_dashboard(DashboardName=missing))
    assert error == ("ResourceNotFound", f"Dashboard {missing} does not exist", 404), (
        f"GetDashboard on missing {missing!r} returned {error!r}"
    )
    last_call = datetime.now(timezone.utc)
    window_end = last_call.replace(second=0, microsecond=0) + timedelta(minutes=1)

    # --- beat 2: bounded poll of the usage series --------------------------------------------- #
    # Usage datapoints arrive asynchronously (tens of seconds); >= tolerates SDK retries.
    queries = [
        _query("listmetrics", _NS, _dims("ListMetrics")),
        _query("deletedashboards", _NS, _dims("DeleteDashboards")),
        _query("getdashboard", _NS, _dims("GetDashboard")),
    ]
    sums: dict = {}
    while True:
        resp = cw.get_metric_data(
            MetricDataQueries=queries, StartTime=window_start, EndTime=window_end,
            ScanBy="TimestampAscending",
        )
        results = {r["Id"]: r for r in resp["MetricDataResults"]}
        assert set(results) == {q["Id"] for q in queries}, (
            f"GetMetricData returned ids {sorted(results)!r} for {len(queries)} queries"
        )
        for qid, r in results.items():
            assert r["StatusCode"] == "Complete", f"{qid!r} StatusCode {r['StatusCode']!r}"
            for ts in r["Timestamps"]:
                assert window_start <= ts < window_end, (
                    f"{qid!r} datapoint at {ts!r} outside the window [{window_start}, {window_end})"
                )
        sums = {qid: sum(r["Values"]) for qid, r in results.items()}
        closed = datetime.now(timezone.utc) >= window_end
        if closed and sums["listmetrics"] >= _N_CALLS and sums["getdashboard"] >= 1:
            break
        left = _remaining(
            f"AWS/Usage CallCount to reach ListMetrics>={_N_CALLS} and GetDashboard>=1 over "
            f"[{window_start}, {window_end}); last sums {sums!r}"
        )
        time.sleep(min(_POLL_S, left))

    assert sums["listmetrics"] >= _N_CALLS, (
        f"CallCount Resource=ListMetrics Sum {sums['listmetrics']!r} < {_N_CALLS} calls made"
    )
    assert sums["deletedashboards"] == 0, (
        f"CallCount Resource=DeleteDashboards Sum {sums['deletedashboards']!r} over a window in "
        f"which DeleteDashboards was never called; expected 0 (control on identical wiring)"
    )
    assert sums["getdashboard"] >= 1, (
        f"the failed (404) GetDashboard was not counted: Sum {sums['getdashboard']!r}"
    )

    stats = cw.get_metric_statistics(
        Namespace=_NS, MetricName=_METRIC, Dimensions=_dims("ListMetrics"),
        StartTime=window_start, EndTime=window_end, Period=60, Statistics=["Sum"],
    )["Datapoints"]
    assert stats, f"GetMetricStatistics returned no datapoints where GetMetricData saw {sums!r}"
    units = sorted({d.get("Unit") for d in stats})
    assert units == ["None"], f"AWS/Usage CallCount unit(s) {units!r}, expected ['None']"
    assert sum(d["Sum"] for d in stats) >= _N_CALLS, (
        f"GetMetricStatistics Sum {sum(d['Sum'] for d in stats)!r} < {_N_CALLS} over the window"
    )

    # --- beat 3: discovery and the exact dimension schema -------------------------------------- #
    # ListMetrics discovery lags datapoints by minutes. Scoped to CallCount/API: other AWS/Usage
    # metrics (e.g. ResourceCount) can carry a fifth ResourceId dimension.
    paginator = cw.get_paginator("list_metrics")
    listed: list = []
    while True:
        assert datetime.now(timezone.utc) >= window_end, "discovery must follow the closed window"
        listed = [
            m
            for page in paginator.paginate(
                Namespace=_NS, MetricName=_METRIC,
                Dimensions=[{"Name": "Service", "Value": "CloudWatch"},
                            {"Name": "Type", "Value": "API"}],
            )
            for m in page["Metrics"]
        ]
        ours = [
            m for m in listed
            if {d["Name"]: d["Value"] for d in m["Dimensions"]}.get("Resource") == "ListMetrics"
        ]
        if ours:
            break
        left = _remaining(
            f"ListMetrics to discover the AWS/Usage CallCount Resource=ListMetrics series "
            f"({len(listed)} CallCount/CloudWatch/API metrics listed so far)"
        )
        time.sleep(min(_POLL_S, left))

    for m in listed:
        names = sorted(d["Name"] for d in m["Dimensions"])
        assert names == _USAGE_DIMS, (
            f"AWS/Usage metric {m['MetricName']!r} has dimensions {names!r}, expected exactly "
            f"{_USAGE_DIMS!r}"
        )
    found = {d["Name"]: d["Value"] for d in ours[0]["Dimensions"]}
    assert found == {"Service": "CloudWatch", "Class": "None", "Type": "API",
                     "Resource": "ListMetrics"}, f"discovered series dimensions {found!r}"

    # --- beat 4: the namespace is reserved ----------------------------------------------------- #
    marker = ctx.unique_name("Sim2RealUsageForged")
    payload = [{"MetricName": _METRIC, "Dimensions": _dims("ListMetrics", service=marker),
                "Value": 1.0, "Unit": "None"}]
    error = _error(lambda: cw.put_metric_data(Namespace=_NS, MetricData=payload))
    assert error == ("InvalidParameterValue", "The value AWS/ for parameter Namespace is invalid.", 400), (
        f"PutMetricData into {_NS!r} returned {error!r}"
    )

    control_ns = ctx.unique_name("Sim2RealUsageCtlNs")
    put_at = datetime.now(timezone.utc)
    cw.put_metric_data(Namespace=control_ns, MetricData=payload)
    read_start = put_at.replace(second=0, microsecond=0) - timedelta(minutes=1)
    probe = [_query("control", control_ns, _dims("ListMetrics", service=marker)),
             _query("forged", _NS, _dims("ListMetrics", service=marker))]
    while True:
        res = {r["Id"]: r for r in cw.get_metric_data(
            MetricDataQueries=probe, StartTime=read_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        )["MetricDataResults"]}
        if sum(res["control"]["Values"]) >= 1.0:
            break
        left = _remaining(f"the positive-control put into {control_ns!r} to become readable")
        time.sleep(min(5.0, left))
    assert res["control"]["Values"] == [1.0], (
        f"positive-control series read back {res['control']['Values']!r}, expected [1.0]"
    )
    assert res["forged"]["Values"] == [], (
        f"the REJECTED put into {_NS!r} is readable anyway: {res['forged']['Values']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
