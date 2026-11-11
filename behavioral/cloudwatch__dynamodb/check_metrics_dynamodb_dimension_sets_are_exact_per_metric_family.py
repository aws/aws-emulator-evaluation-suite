"""metrics-dynamodb-dimension-sets-are-exact-per-metric-family."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-dynamodb-dimension-sets-are-exact-per-metric-family"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

_N_ITEMS = 3
_N_STRONG_GETS = 2
_BLOB = "z" * 200

_METRIC_TIMEOUT_S = 200
_HOLD_S = 30


# ===== helpers =====
def _series(cw, metric, dims, start, end, stat="Sum"):
    """One statistic of an AWS/DynamoDB series over the window, or None if it has no datapoints."""
    dps = cw.get_metric_statistics(
        Namespace="AWS/DynamoDB", MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in dims],
        StartTime=start, EndTime=end, Period=60, Statistics=[stat])["Datapoints"]
    if not dps:
        return None
    if stat == "Maximum":
        return max(d[stat] for d in dps)
    return sum(d[stat] for d in dps)


def _await_exact(ctx, probe, expected, *, timeout_s, hold_s, interval_s=2, description):
    """Poll probe() every 2 s until it EQUALS expected (ceiling capped by the runner's remaining
    time), then require it to hold for hold_s, so a late over-count fails with the reading quoted."""
    left = ctx.time_left()
    budget = timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))
    deadline = time.monotonic() + budget
    last = None
    while True:
        last = probe()
        if last == expected:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: never equalled {expected!r} within {budget:.0f}s; "
                f"last reading {last!r}")
        time.sleep(interval_s)
    hold_until = time.monotonic() + hold_s
    while time.monotonic() < hold_until:
        time.sleep(interval_s)
        got = probe()
        assert got == expected, (
            f"{description}: reached {expected!r} and then moved to {got!r}")
    return last
# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Each AWS/DynamoDB metric family is published under exactly one dimension set and CloudWatch
    matches the COMPLETE set: consumption under {TableName}, latency and returned items under
    {TableName, Operation}; a neighbouring set is an empty series, read alongside the matching one."""
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    table = ctx.unique_name("sim2real-xsvc-ddbm-dim-")

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    start = datetime.now(timezone.utc) - timedelta(minutes=2)

    api_wcu = api_rcu = 0.0
    for i in range(_N_ITEMS):
        api_wcu += ddb.put_item(
            TableName=table, ReturnConsumedCapacity="TOTAL",
            Item={"pk": {"S": "P"}, "sk": {"S": f"{i:02d}"}, "b": {"S": _BLOB}},
        )["ConsumedCapacity"]["CapacityUnits"]
    for i in range(_N_STRONG_GETS):
        got = ddb.get_item(TableName=table, Key={"pk": {"S": "P"}, "sk": {"S": f"{i:02d}"}},
                           ConsistentRead=True, ReturnConsumedCapacity="TOTAL")
        assert "Item" in got, f"GetItem of sk={i:02d} returned no item: {got!r}"
        api_rcu += got["ConsumedCapacity"]["CapacityUnits"]
    q = ddb.query(TableName=table, KeyConditionExpression="pk = :p", ConsistentRead=True,
                  ExpressionAttributeValues={":p": {"S": "P"}}, ReturnConsumedCapacity="TOTAL")
    assert q["Count"] == _N_ITEMS, f"consistent Query returned {q['Count']} items, expected {_N_ITEMS}"
    api_rcu += q["ConsumedCapacity"]["CapacityUnits"]
    s = ddb.scan(TableName=table, ConsistentRead=True, ReturnConsumedCapacity="TOTAL")
    assert s["Count"] == _N_ITEMS, f"consistent Scan returned {s['Count']} items, expected {_N_ITEMS}"
    api_rcu += s["ConsumedCapacity"]["CapacityUnits"]
    assert api_wcu == float(_N_ITEMS), f"{_N_ITEMS} sub-KB puts cost {api_wcu!r} WCU"

    end = datetime.now(timezone.utc) + timedelta(minutes=5)
    t = [("TableName", table)]

    def op(o):
        return t + [("Operation", o)]

    def _snapshot():
        return {
            # consumption: {TableName} present, {TableName, Operation} absent
            "WCU {T}": _series(cw, "ConsumedWriteCapacityUnits", t, start, end),
            "RCU {T}": _series(cw, "ConsumedReadCapacityUnits", t, start, end),
            "WCU {T,Op=PutItem}": _series(cw, "ConsumedWriteCapacityUnits", op("PutItem"),
                                          start, end),
            "RCU {T,Op=GetItem}": _series(cw, "ConsumedReadCapacityUnits", op("GetItem"),
                                          start, end),
            # latency: {TableName, Operation} present per op, {TableName} alone absent
            "Latency {T,Op=PutItem} n": _series(cw, "SuccessfulRequestLatency", op("PutItem"),
                                                start, end, "SampleCount"),
            "Latency {T,Op=GetItem} n": _series(cw, "SuccessfulRequestLatency", op("GetItem"),
                                                start, end, "SampleCount"),
            "Latency {T,Op=Query} n": _series(cw, "SuccessfulRequestLatency", op("Query"),
                                              start, end, "SampleCount"),
            "Latency {T,Op=Scan} n": _series(cw, "SuccessfulRequestLatency", op("Scan"),
                                             start, end, "SampleCount"),
            "Latency {T} n": _series(cw, "SuccessfulRequestLatency", t, start, end,
                                     "SampleCount"),
            # returned items: {TableName, Operation} present, {TableName} alone absent
            "ReturnedItemCount {T,Op=Query}": _series(cw, "ReturnedItemCount", op("Query"),
                                                      start, end),
            "ReturnedItemCount {T,Op=Scan}": _series(cw, "ReturnedItemCount", op("Scan"),
                                                     start, end),
            "ReturnedItemCount {T}": _series(cw, "ReturnedItemCount", t, start, end),
        }

    _await_exact(
        ctx, _snapshot,
        {"WCU {T}": api_wcu,
         "RCU {T}": api_rcu,
         "WCU {T,Op=PutItem}": None,
         "RCU {T,Op=GetItem}": None,
         "Latency {T,Op=PutItem} n": float(_N_ITEMS),
         "Latency {T,Op=GetItem} n": float(_N_STRONG_GETS),
         "Latency {T,Op=Query} n": 1.0,
         "Latency {T,Op=Scan} n": 1.0,
         "Latency {T} n": None,
         "ReturnedItemCount {T,Op=Query}": float(q["Count"]),
         "ReturnedItemCount {T,Op=Scan}": float(s["Count"]),
         "ReturnedItemCount {T}": None},
        timeout_s=_METRIC_TIMEOUT_S, hold_s=_HOLD_S,
        description=(f"AWS/DynamoDB dimension-set matrix for {table!r} (API plane: "
                     f"{api_wcu!r} WCU, {api_rcu!r} RCU; None means an empty series)"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
