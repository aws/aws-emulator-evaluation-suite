"""obs-logs-2-metric-filter-apply-on-transformed-logs-matches-transformed-event."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "obs-logs-2-metric-filter-apply-on-transformed-logs-matches-transformed-event"
GROUP = "metric-filters"
SERVICES = ["cloudwatch", "logs"]

_PATTERN = '{ $.sev = "HIGH" }'
_N_EVENTS = 4
# One shared ceiling for every asynchronous wait, from the PutLogEvents call. AWS typically
# publishes every metric below within ~30 s of the write; the ceiling is a bound, not a wait.
_DEADLINE_S = 420.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """With a parseJSON -> addKeys{sev: HIGH} transformer, a `{ $.sev = "HIGH" }` filter with
    applyOnTransformedLogs=true sums 4 while the raw-event twin publishes nothing; AWS/Logs
    TransformedLogEvents counts the same 4 events and TransformedBytes is positive.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    group = ctx.unique_name("sim2real-xsvc-lg-txmf-")
    namespace = ctx.unique_name("sim2real-xsvc-txmf-ns-")

    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = "events"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    config = [
        {"parseJSON": {}},
        {"addKeys": {"entries": [{"key": "sev", "value": "HIGH"}]}},
    ]
    logs.put_transformer(logGroupIdentifier=group, transformerConfig=config)
    ctx.on_cleanup(lambda: logs.delete_transformer(logGroupIdentifier=group))
    stored = logs.get_transformer(logGroupIdentifier=group).get("transformerConfig")
    stored_kinds = [next(iter(p)) for p in (stored or [])]
    assert stored_kinds == ["parseJSON", "addKeys"], (
        f"GetTransformer must return the two processors in order; got {stored!r}"
    )
    added = stored[1]["addKeys"]["entries"]
    assert [(e["key"], e["value"]) for e in added] == [("sev", "HIGH")], (
        f"the addKeys processor must persist exactly sev=HIGH; got {added!r}"
    )

    filters = {"txmf-transformed": (True, "Transformed"), "txmf-raw": (False, "Raw")}
    for fname, (on_transformed, metric) in filters.items():
        logs.put_metric_filter(
            logGroupName=group, filterName=fname, filterPattern=_PATTERN,
            applyOnTransformedLogs=on_transformed,
            metricTransformations=[
                {"metricName": metric, "metricNamespace": namespace, "metricValue": "1"}
            ],
        )
        ctx.on_cleanup(lambda _n=fname: logs.delete_metric_filter(logGroupName=group, filterName=_n))

    described = {
        f["filterName"]: f
        for f in _paginate(logs, "describe_metric_filters", "metricFilters", logGroupName=group)
    }
    assert sorted(described) == sorted(filters), (
        f"DescribeMetricFilters must list exactly {sorted(filters)!r}; got {sorted(described)!r}"
    )
    for fname, (on_transformed, _) in filters.items():
        echoed = described[fname].get("applyOnTransformedLogs")
        assert echoed is on_transformed, (
            f"DescribeMetricFilters must echo applyOnTransformedLogs={on_transformed!r} for "
            f"{fname!r}; got {echoed!r} in {described[fname]!r}"
        )

    write_ms = int(time.time() * 1000)
    messages = [json.dumps({"msg": "order processed", "n": i}) for i in range(_N_EVENTS)]
    assert all("sev" not in json.loads(m) for m in messages), "raw lines must not carry sev"
    resp = logs.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{"timestamp": write_ms + i, "message": m} for i, m in enumerate(messages)],
    )
    assert "rejectedLogEventsInfo" not in resp, f"the batch was partially rejected: {resp!r}"
    deadline = time.monotonic() + _DEADLINE_S
    start = (datetime.fromtimestamp(write_ms / 1000, timezone.utc)
             .replace(second=0, microsecond=0) - timedelta(minutes=2))

    def _points(ns, metric, dims):
        return cw.get_metric_statistics(
            Namespace=ns, MetricName=metric, Dimensions=dims, StartTime=start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60, Statistics=["Sum"],
        ).get("Datapoints", [])

    def _sum(points):
        return sum(p.get("Sum", 0.0) for p in points)

    # 1. Filter A (applyOnTransformedLogs=true) counts every transformed event.
    transformed = _poll_until(
        lambda: _points(namespace, "Transformed", []),
        lambda pts: _sum(pts) >= _N_EVENTS, deadline=deadline,
        description=f"{namespace}/Transformed to reach Sum {_N_EVENTS}",
    )
    assert _sum(transformed) == float(_N_EVENTS), (
        f"filter A (applyOnTransformedLogs=true) must count exactly {_N_EVENTS} transformed "
        f"events; got datapoints {transformed!r}"
    )
    raw_early = _points(namespace, "Raw", [])
    assert raw_early == [], (
        "filter B (applyOnTransformedLogs=false) evaluates the RAW events, which lack sev, so it "
        f"must publish nothing; after filter A's datapoint arrived it holds {raw_early!r}"
    )

    # 2. Discover the AWS/Logs dimension name from ListMetrics rather than assuming a spelling.
    def _listed():
        return [
            m for m in _paginate(cw, "list_metrics", "Metrics",
                                 Namespace="AWS/Logs", MetricName="TransformedLogEvents")
            if any(d.get("Value") == group for d in m.get("Dimensions", []))
        ]

    listed = _poll_until(_listed, lambda ms: len(ms) >= 1, deadline=deadline,
                         description=f"ListMetrics to list AWS/Logs TransformedLogEvents for {group}")
    assert len(listed) == 1 and len(listed[0]["Dimensions"]) == 1, (
        f"AWS/Logs TransformedLogEvents must be published under exactly one per-log-group "
        f"dimension; ListMetrics returned {listed!r}"
    )
    dim = listed[0]["Dimensions"][0]
    assert dim["Name"].lower() == "loggroupname" and dim["Value"] == group, (
        f"the TransformedLogEvents dimension must name the log group; got {dim!r}"
    )
    dims = [{"Name": dim["Name"], "Value": group}]

    # 3. The transformer-side metrics count the same events.
    tle = _poll_until(
        lambda: _points("AWS/Logs", "TransformedLogEvents", dims),
        lambda pts: _sum(pts) >= _N_EVENTS, deadline=deadline,
        description=f"AWS/Logs TransformedLogEvents{{{dim['Name']}={group}}} to reach {_N_EVENTS}",
    )
    assert _sum(tle) == float(_N_EVENTS), (
        f"AWS/Logs TransformedLogEvents must count exactly {_N_EVENTS} events; got {tle!r}"
    )
    tbytes = _poll_until(
        lambda: _points("AWS/Logs", "TransformedBytes", dims),
        lambda pts: len(pts) >= 1, deadline=deadline,
        description=f"AWS/Logs TransformedBytes{{{dim['Name']}={group}}} to publish a datapoint",
    )
    units = sorted({p.get("Unit") for p in tbytes})
    assert units == ["Bytes"], f"TransformedBytes must be published in Bytes; got {tbytes!r}"
    assert _sum(tbytes) > 0.0, f"TransformedBytes must be positive for 4 events; got {tbytes!r}"

    # 4. Absence again, after every barrier above, so it cannot be publication lag.
    raw_late = _points(namespace, "Raw", [])
    assert raw_late == [], (
        "filter B (applyOnTransformedLogs=false) must still publish nothing after Transformed, "
        f"TransformedLogEvents and TransformedBytes all arrived; it holds {raw_late!r}"
    )
    transformed_late = _sum(_points(namespace, "Transformed", []))
    assert transformed_late == float(_N_EVENTS), (
        f"filter A's Sum must stay {_N_EVENTS} (no double counting); got {transformed_late!r}"
    )


def _poll_until(probe, predicate, *, deadline, interval_s=5.0, description="condition"):
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {description}; last: {last!r}")
        time.sleep(interval_s)


def _paginate(client, op, key, **kwargs):
    out, token_in, token_out = [], None, None
    token_names = {"list_metrics": ("NextToken", "NextToken")}.get(op, ("nextToken", "nextToken"))
    for _ in range(500):
        call = dict(kwargs)
        if token_in:
            call[token_names[0]] = token_in
        resp = getattr(client, op)(**call)
        out.extend(resp.get(key, []))
        token_out = resp.get(token_names[1])
        if not token_out:
            return out
        token_in = token_out
    raise AssertionError(f"{op} pagination did not terminate within 500 pages")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
