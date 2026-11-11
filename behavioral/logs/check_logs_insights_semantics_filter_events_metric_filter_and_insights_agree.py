"""logs-insights-semantics-filter-events-metric-filter-and-insights-agree."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "logs-insights-semantics-filter-events-metric-filter-and-insights-agree"
GROUP = 'insights'
SERVICES = ['logs']


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")


def _run_query(svc, groups, start_s, end_s, query, *, timeout_s=120, interval_s=1.0):
    qid = svc.start_query(
        logGroupNames=groups, startTime=start_s, endTime=end_s, queryString=query
    )["queryId"]
    deadline = time.monotonic() + timeout_s
    while True:
        resp = svc.get_query_results(queryId=qid)
        if resp["status"] in _TERMINAL:
            resp["queryId"] = qid
            return resp
        if time.monotonic() > deadline:
            raise AssertionError(f"query {qid} ({query!r}) still {resp['status']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _rows(resp, *, drop=("@ptr",)):
    return [{f["field"]: f["value"] for f in row if f["field"] not in drop} for row in resp["results"]]


def _poll_until(probe, predicate, *, what, budget_s=300, interval_s=5.0):
    deadline = time.monotonic() + budget_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() > deadline:
            raise AssertionError(f"{what} not reached within {budget_s}s; last={last!r}")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents, TestMetricFilter, a live metric filter's datapoints and a Logs Insights
    filter select exactly the same events for one predicate, rejecting case, prefix, nesting and
    plain-text near misses.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    group = ctx.unique_name("sim2real-lisem-agree-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    namespace = ctx.unique_name("Sim2Real/LisemAgree-")
    metric = "ErrorEvents"
    fname = ctx.unique_name("sim2real-lisem-mf-")
    pattern = '{ $.level = "ERROR" }'
    logs.put_metric_filter(logGroupName=group, filterName=fname, filterPattern=pattern,
                           metricTransformations=[{"metricName": metric, "metricNamespace": namespace,
                                                   "metricValue": "1"}])
    ctx.on_cleanup(lambda: logs.delete_metric_filter(logGroupName=group, filterName=fname))

    docs = [
        {"level": "ERROR", "k": 1}, {"level": "INFO", "k": 2}, {"level": "error", "k": 3},
        {"level": "ERROR", "k": 4}, {"level": "ERRORS", "k": 5}, {"level": {"level": "ERROR"}, "k": 6},
        {"level": "ERROR", "k": 7}, {"level": "WARN", "k": 8}, {"level": "ERROR", "k": 9},
    ]
    messages = [json.dumps(d) for d in docs] + ["ERROR: plain text, not JSON, k=10"]
    want_k = [d["k"] for d in docs if d.get("level") == "ERROR"]
    assert len(want_k) == 4, f"test plan itself is wrong: {want_k!r}"

    logs.create_log_stream(logGroupName=group, logStreamName="s")
    base = int(time.time() * 1000) - 120_000
    events = [{"timestamp": base + i * 1000, "message": m} for i, m in enumerate(messages)]
    logs.put_log_events(logGroupName=group, logStreamName="s", logEvents=events)
    end_ms = int(time.time() * 1000) + 60_000

    # TestMetricFilter evaluates the pattern statelessly over the same messages.
    tested = logs.test_metric_filter(filterPattern=pattern, logEventMessages=messages)["matches"]
    tested_k = sorted(json.loads(m["eventMessage"])["k"] for m in tested)
    assert tested_k == want_k, f"TestMetricFilter matched k={tested_k!r}, predicate selects {want_k!r}"

    def fle():
        out = []
        for page in logs.get_paginator("filter_log_events").paginate(
                logGroupName=group, filterPattern=pattern, startTime=base - 60_000, endTime=end_ms):
            out += page["events"]
        return out
    fle_events = _poll_until(fle, lambda ev: len(ev) >= len(want_k), what="FilterLogEvents sees all matches",
                             interval_s=2.0)
    fle_k = sorted(json.loads(e["message"])["k"] for e in fle_events)
    assert fle_k == want_k, f"FilterLogEvents matched k={fle_k!r}, predicate selects {want_k!r}"

    start_s, end_s = base // 1000 - 60, end_ms // 1000
    ins = _poll_until(lambda: _run_query(logs, [group], start_s, end_s,
                                         "filter level = 'ERROR' | fields k | sort k asc"),
                      lambda r: r["status"] == "Complete" and len(r["results"]) >= len(want_k),
                      what="Insights sees all matches", interval_s=3.0)
    ins_k = [int(r["k"]) for r in _rows(ins)]
    assert ins_k == want_k, f"Insights matched k={ins_k!r}, predicate selects {want_k!r}"
    assert ins["statistics"]["recordsMatched"] == float(len(want_k)), f"recordsMatched {ins['statistics']!r}"

    # FilterLogEvents and Insights must pick the same stored events, not just as many.
    fle_ids = sorted(e["timestamp"] for e in fle_events)
    ins_ts = _rows(_run_query(logs, [group], start_s, end_s,
                              "filter level = 'ERROR' | fields @timestamp | sort @timestamp asc"))
    as_ms = [int(datetime.datetime.strptime(r["@timestamp"], "%Y-%m-%d %H:%M:%S.%f")
                 .replace(tzinfo=datetime.timezone.utc).timestamp() * 1000 + 0.5) for r in ins_ts]
    assert as_ms == fle_ids, f"Insights timestamps {as_ms!r} != FilterLogEvents timestamps {fle_ids!r}"

    # Metric filter datapoints are published asynchronously, hence the longer budget.
    t0 = datetime.datetime.fromtimestamp(base / 1000 - 600, tz=datetime.timezone.utc)
    t1 = datetime.datetime.fromtimestamp(end_ms / 1000 + 600, tz=datetime.timezone.utc)

    def datapoints():
        return cw.get_metric_statistics(Namespace=namespace, MetricName=metric, StartTime=t0, EndTime=t1,
                                        Period=60, Statistics=["Sum", "SampleCount"])["Datapoints"]
    dps = _poll_until(datapoints, lambda d: sum(x["Sum"] for x in d) >= len(want_k),
                      what="metric filter datapoints reach the match count", budget_s=420)
    assert sum(x["Sum"] for x in dps) == float(len(want_k)), f"metric Sum {dps!r} != {len(want_k)}"
    assert sum(x["SampleCount"] for x in dps) == float(len(want_k)), (
        f"metric SampleCount {dps!r} != {len(want_k)}: one sample per matching event, none for near misses"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
