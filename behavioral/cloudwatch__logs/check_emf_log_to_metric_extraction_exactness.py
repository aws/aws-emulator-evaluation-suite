"""emf-log-to-metric-extraction-exactness."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "emf-log-to-metric-extraction-exactness"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "logs"]

#: Twelve distinct latencies. Sum 364, min 11, max 53 -- no round number anywhere, so a
#: constant-returning emulator cannot land on any of them by accident.
_LATENCIES = (11.0, 13.0, 17.0, 19.0, 23.0, 29.0, 31.0, 37.0, 41.0, 43.0, 47.0, 53.0)
_N = len(_LATENCIES)
_LAT_SUM = float(sum(_LATENCIES))
_LAT_MIN = float(min(_LATENCIES))
_LAT_MAX = float(max(_LATENCIES))


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=2, description="reading"):
    """Return probe()'s first value predicate accepts; raise naming the last reading otherwise."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not reached within {timeout_s}s; last reading {last!r}")
# ===== end helpers =====


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """PutLogEvents of EMF documents materialises exactly the declared metrics, dimension sets, units,
    storage resolutions and aggregates, while undeclared high-cardinality properties stay in Logs and
    malformed declarations yield no metric under the undeclarable dimension or missing value.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    group = ctx.unique_name("sim2real-behav-emf-")
    namespace = group
    stream = "emf"

    logs.create_log_group(logGroupName=group, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    # All twelve documents live inside ONE whole minute, at distinct one-second offsets, so the
    # Period=60 rollup is a single bucket while the sub-minute reads below have twelve.
    minute = int(time.time()) // 60 * 60 - 120
    base_ms = (minute + 10) * 1000

    request_ids: list[str] = []
    customer_ids: list[str] = []
    events: list[dict] = []
    for i, latency in enumerate(_LATENCIES):
        rid, cid = uuid.uuid4().hex, uuid.uuid4().hex
        request_ids.append(rid)
        customer_ids.append(cid)
        ts = base_ms + i * 1000
        events.append({
            "timestamp": ts,
            "message": json.dumps({
                "_aws": {
                    "Timestamp": ts,
                    "CloudWatchMetrics": [{
                        "Namespace": namespace,
                        # TWO dimension sets from ONE document: the extractor must materialise
                        # two independent series, not one.
                        "Dimensions": [["Service", "Operation"], ["Service"]],
                        "Metrics": [
                            {"Name": "OrderLatency", "Unit": "Milliseconds",
                             "StorageResolution": 1},
                            {"Name": "OrderCount", "Unit": "Count"},
                        ],
                    }],
                },
                "Service": "checkout",
                "Operation": "PlaceOrder",
                "OrderLatency": latency,
                "OrderCount": 1,
                # High-cardinality properties. An extractor that promotes every top-level
                # property to a dimension creates 12 distinct series from these two keys.
                "requestId": rid,
                "customerId": cid,
            }),
        })

    # Failure arm A: a DECLARED metric with no sibling value in the document.
    bad_a_rid = uuid.uuid4().hex
    events.append({"timestamp": base_ms, "message": json.dumps({
        "_aws": {"Timestamp": base_ms, "CloudWatchMetrics": [{
            "Namespace": namespace, "Dimensions": [["Service", "Operation"]],
            "Metrics": [{"Name": "NotPresentInDocument", "Unit": "Count"}]}]},
        "Service": "checkout", "Operation": "PlaceOrder", "requestId": bad_a_rid})})

    # Failure arm B: a declared DIMENSION name that is not a property of the document.
    bad_b_rid = uuid.uuid4().hex
    events.append({"timestamp": base_ms, "message": json.dumps({
        "_aws": {"Timestamp": base_ms, "CloudWatchMetrics": [{
            "Namespace": namespace, "Dimensions": [["NotAProperty"]],
            "Metrics": [{"Name": "OrphanMetric", "Unit": "Count"}]}]},
        "Service": "checkout", "OrphanMetric": 5, "requestId": bad_b_rid})})

    put = logs.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=sorted(events, key=lambda e: e["timestamp"]),
    )
    # The log write is proven to have SUCCEEDED independently of any metric outcome, so every
    # absence asserted later is an extraction decision and never a dropped log event.
    assert "rejectedLogEventsInfo" not in put, (
        f"PutLogEvents rejected events: {put.get('rejectedLogEventsInfo')!r} -- the log write "
        f"must succeed before any metric absence can be attributed to EMF validation"
    )

    start = datetime.fromtimestamp(minute - 60, timezone.utc)
    end = datetime.now(timezone.utc) + timedelta(minutes=5)

    def _dps(metric, dims, period=60):
        return cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dims,
            StartTime=start, EndTime=end, Period=period,
            Statistics=["Sum", "SampleCount", "Minimum", "Maximum"],
        )["Datapoints"]

    def _one(metric, dims, period=60):
        dps = _dps(metric, dims, period)
        assert len(dps) == 1, (
            f"{metric} under {dims!r} at Period={period} returned {len(dps)} datapoints, "
            f"expected exactly 1: {dps!r}"
        )
        return dps[0]

    d2 = [{"Name": "Service", "Value": "checkout"},
          {"Name": "Operation", "Value": "PlaceOrder"}]
    d1 = [{"Name": "Service", "Value": "checkout"}]

    def _catalogue():
        seen = set()
        token = None
        while True:
            kwargs = {"Namespace": namespace}
            if token:
                kwargs["NextToken"] = token
            page = cw.list_metrics(**kwargs)
            for m in page["Metrics"]:
                seen.add((m["MetricName"],
                          tuple(sorted(d["Name"] for d in m["Dimensions"]))))
            token = page.get("NextToken")
            if not token:
                return seen

    expected_catalogue = {
        ("OrderCount", ("Operation", "Service")),
        ("OrderLatency", ("Operation", "Service")),
        ("OrderCount", ("Service",)),
        ("OrderLatency", ("Service",)),
        # A declared dimension name that is not a property of the document is DROPPED, and the
        # metric is still materialised -- dimensionless.
        ("OrphanMetric", ()),
    }

    # --- the extracted values, read behind a barrier ------------------------------------- #
    # Polling only until the expected total appears could miss an over-count landing later, so
    # a barrier document follows in the same stream: once its own metric is readable, every
    # extraction of the earlier batch has landed, and the reads below see the final values.
    def _snapshot():
        dps = tuple((d["Sum"], d["SampleCount"]) for d in _dps("OrderCount", d2))
        return (dps, frozenset(_catalogue()))

    _poll_until(
        _snapshot,
        lambda snap: sum(n for _, n in snap[0]) >= _N and snap[1] >= expected_catalogue,
        timeout_s=210,
        description=f"extracted OrderCount and the metric catalogue for namespace {namespace!r}",
    )
    barrier_ns = f"{namespace}-barrier"
    barrier_ms = int(time.time() * 1000)
    logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=[{
        "timestamp": barrier_ms,
        "message": json.dumps({
            "_aws": {"Timestamp": barrier_ms, "CloudWatchMetrics": [{
                "Namespace": barrier_ns, "Dimensions": [["Service"]],
                "Metrics": [{"Name": "Barrier", "Unit": "Count"}]}]},
            "Service": "checkout", "Barrier": 1}),
    }])
    _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=barrier_ns, MetricName="Barrier", Dimensions=d1,
            StartTime=start, EndTime=end, Period=60, Statistics=["Sum"],
        )["Datapoints"],
        bool,
        timeout_s=210,
        description=f"the barrier document's metric in namespace {barrier_ns!r}",
    )
    dps_stable, catalogue = _snapshot()
    assert dps_stable == ((float(_N), float(_N)),), (
        f"OrderCount stabilised at {dps_stable!r}; {_N} EMF documents each declaring "
        f"OrderCount=1 must extract to exactly one bucket of Sum={float(_N)} "
        f"SampleCount={float(_N)}"
    )

    count_d2 = _one("OrderCount", d2)
    assert count_d2["Sum"] == float(_N), f"OrderCount Sum was {count_d2['Sum']!r}, expected {float(_N)}"
    assert count_d2["SampleCount"] == float(_N), (
        f"OrderCount SampleCount was {count_d2['SampleCount']!r}, expected {float(_N)} -- one "
        f"sample per extracted document, not one datapoint carrying the total"
    )
    assert count_d2["Unit"] == "Count", (
        f"OrderCount Unit was {count_d2['Unit']!r}; the EMF envelope declared 'Count' and the "
        f"extractor must carry the declared unit into the metric store"
    )

    lat_d2 = _one("OrderLatency", d2)
    assert lat_d2["Sum"] == _LAT_SUM, f"OrderLatency Sum was {lat_d2['Sum']!r}, expected {_LAT_SUM}"
    assert lat_d2["Minimum"] == _LAT_MIN, (
        f"OrderLatency Minimum was {lat_d2['Minimum']!r}, expected {_LAT_MIN}"
    )
    assert lat_d2["Maximum"] == _LAT_MAX, (
        f"OrderLatency Maximum was {lat_d2['Maximum']!r}, expected {_LAT_MAX}"
    )
    assert lat_d2["SampleCount"] == float(_N), (
        f"OrderLatency SampleCount was {lat_d2['SampleCount']!r}, expected {float(_N)}"
    )
    assert lat_d2["Unit"] == "Milliseconds", (
        f"OrderLatency Unit was {lat_d2['Unit']!r}, expected 'Milliseconds' from the envelope"
    )

    # The SECOND declared dimension set is an independently materialised series. CloudWatch
    # never aggregates across dimension combinations, so the only way ["Service"] alone carries
    # these totals is that the extractor projected Dimensions[1] as well as Dimensions[0].
    lat_d1 = _one("OrderLatency", d1)
    assert (lat_d1["Sum"], lat_d1["SampleCount"], lat_d1["Minimum"], lat_d1["Maximum"]) == (
        _LAT_SUM, float(_N), _LAT_MIN, _LAT_MAX
    ), (
        f"OrderLatency under the second declared dimension set {d1!r} read "
        f"{lat_d1!r}; both declared sets must materialise as full independent series"
    )
    count_d1 = _one("OrderCount", d1)
    assert (count_d1["Sum"], count_d1["SampleCount"]) == (float(_N), float(_N)), (
        f"OrderCount under {d1!r} read Sum={count_d1['Sum']!r} "
        f"SampleCount={count_d1['SampleCount']!r}, expected {float(_N)} for both"
    )

    # --- per-metric StorageResolution, from ONE document --------------------------------- #
    # OrderLatency declared StorageResolution: 1; OrderCount declared none, i.e. standard.
    # The high-resolution series keeps its per-SECOND timestamps while the standard series is
    # truncated to the minute -- so a Period=1 read splits one into 12 buckets and returns a
    # single minute-stamped bucket for the other, and that contrast is the discriminator.
    hi = sorted(_dps("OrderLatency", d2, period=1), key=lambda d: d["Timestamp"])
    assert len(hi) == _N, (
        f"OrderLatency at Period=1 returned {len(hi)} buckets, expected {_N} -- one per second, "
        f"because StorageResolution:1 was declared for it inside the EMF envelope"
    )
    want_secs = [(base_ms // 1000) + i for i in range(_N)]
    got_secs = [int(d["Timestamp"].timestamp()) for d in hi]
    assert got_secs == want_secs, (
        f"OrderLatency Period=1 bucket timestamps were {got_secs!r}, expected the {_N} distinct "
        f"one-second boundaries {want_secs!r} the documents were stamped with"
    )
    got_vals = [d["Sum"] for d in hi]
    assert got_vals == list(_LATENCIES), (
        f"OrderLatency per-second values were {got_vals!r}, expected {list(_LATENCIES)!r} -- "
        f"each document's own value in its own second"
    )
    assert all(d["SampleCount"] == 1.0 for d in hi), (
        f"each one-second high-resolution bucket must hold exactly 1 sample, got "
        f"{[d['SampleCount'] for d in hi]!r}"
    )

    std = _one("OrderCount", d2, period=1)
    assert int(std["Timestamp"].timestamp()) == minute, (
        f"OrderCount at Period=1 is stamped {std['Timestamp'].isoformat()}; a metric declared "
        f"WITHOUT StorageResolution is stored at minute granularity, so its only bucket must "
        f"sit on the minute boundary {minute} even when the read period is 1 second"
    )
    assert std["Sum"] == float(_N), (
        f"the standard-resolution OrderCount bucket read Sum={std['Sum']!r}, expected "
        f"{float(_N)} -- all {_N} samples collapsed into the one minute-stamped bucket"
    )

    # --- the catalogue: exactly the declared projections, nothing else -------------------- #
    assert set(catalogue) == expected_catalogue, (
        f"ListMetrics for the EMF namespace returned {sorted(catalogue)!r}; expected exactly "
        f"{sorted(expected_catalogue)!r}. Extra entries mean the extractor invented series the "
        f"envelope never declared; missing ones mean it dropped a declared projection"
    )
    # The high-cardinality trap, stated as its own assertion so the failure names it.
    promoted = {name for _, dims in catalogue for name in dims} | {n for n, _ in catalogue}
    assert not promoted & {"requestId", "customerId"}, (
        f"the catalogue exposes {sorted(promoted & {'requestId', 'customerId'})!r} as a metric "
        f"or a dimension; a non-declared top-level property must never be promoted -- doing so "
        f"turns {_N} log lines into {_N} billable metric series"
    )

    # The dropped-dimension metric still carries its VALUE, dimensionless.
    orphan = _one("OrphanMetric", [])
    assert orphan["Sum"] == 5.0 and orphan["SampleCount"] == 1.0, (
        f"OrphanMetric read {orphan!r}; the document's undeclarable dimension was dropped but "
        f"its value 5 must still be extracted into the dimensionless series"
    )

    # --- the properties ARE in Logs: extraction excluded them, ingestion did not ---------- #
    def _events(pattern):
        out, token = [], None
        while True:
            kwargs = {"logGroupName": group, "filterPattern": pattern}
            if token:
                kwargs["nextToken"] = token
            page = logs.filter_log_events(**kwargs)
            out.extend(page["events"])
            token = page.get("nextToken")
            if not token:
                return out

    ingested = {json.loads(e["message"])["requestId"] for e in _events('{ $.OrderCount = 1 }')}
    assert ingested == set(request_ids), (
        f"a structured Logs filter over the EMF documents returned "
        f"{len(ingested)} distinct requestIds, expected the {_N} the check generated; missing "
        f"{sorted(set(request_ids) - ingested)!r}. The high-cardinality properties must be "
        f"fully queryable in Logs while absent from the metric catalogue"
    )
    assert customer_ids[0] in _events(f'"{customer_ids[0]}"')[0]["message"], (
        f"customerId {customer_ids[0]!r} is not readable back out of the stored log event"
    )
    # Effect-absent control: both malformed documents were STORED as log events. EMF validation
    # rejects the metric, never the log.
    for label, rid in (("declared-metric-with-no-value", bad_a_rid),
                       ("undeclarable-dimension", bad_b_rid)):
        found = _events(f'"{rid}"')
        assert len(found) == 1, (
            f"the {label} document is not in the log group ({len(found)} events matched "
            f"{rid!r}); its metric absence would then be a dropped log, not an extraction "
            f"decision"
        )

    # --- failure arm: the absences, read after the barrier ------------------------------- #
    absent_probes = {
        "OrderCount under the undeclared dimension set [Operation]":
            lambda: _dps("OrderCount", [{"Name": "Operation", "Value": "PlaceOrder"}]),
        "NotPresentInDocument (declared with no sibling value)":
            lambda: _dps("NotPresentInDocument", d2),
        "OrphanMetric under the dimension name that was not a property":
            lambda: _dps("OrphanMetric", [{"Name": "NotAProperty", "Value": "checkout"}]),
    }
    absent = {k: p() for k, p in absent_probes.items()}
    assert absent == {k: [] for k in absent_probes}, (
        f"the three EMF absences (undeclared dimension projection, declared metric with no "
        f"sibling value, dropped dimension name) read {absent!r}, expected each to be empty"
    )

    # --- positive control, after every negative ------------------------------------------- #
    control = _one("OrderCount", d2)
    assert (control["Sum"], control["SampleCount"]) == (float(_N), float(_N)), (
        f"after the absence probes the positive series read {control!r}; the extracted "
        f"OrderCount must still be Sum={float(_N)} SampleCount={float(_N)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
