"""metrics-dynamodb-write-units-round-up-per-kb-agree-with-cloudwatch."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-dynamodb-write-units-round-up-per-kb-agree-with-cloudwatch"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

#: (item size in bytes, WCU it must cost). Item size is the sum of UTF-8 attribute-name lengths
#: plus string-value lengths, so a {pk, b} item of exactly N bytes is built below by padding `b`.
#: Measured on real AWS: 1024 -> 1, 1025 -> 2, 1536 -> 2, 2048 -> 2, 2049 -> 3.
#: The boundaries are the claim: one byte past a KB costs a whole extra unit, and 1.5 KB costs 2.
_SIZES = ((1024, 1.0), (1025, 2.0), (1536, 2.0), (2048, 2.0), (2049, 3.0))
_COPIES = 2
_EXPECTED_WCU = _COPIES * sum(w for _, w in _SIZES)       # 20.0 -- no request count matches it
_EXPECTED_MAX = max(w for _, w in _SIZES)                  # 3.0 -- one sample per request
_N_PUTS = _COPIES * len(_SIZES)

_METRIC_TIMEOUT_S = 200
_HOLD_S = 30


# ===== helpers =====
def _item(pk: str, total_bytes: int) -> dict:
    """A {pk, b} item whose DynamoDB item size is exactly total_bytes (ASCII only)."""
    pad = total_bytes - len("pk") - len(pk) - len("b")
    assert pad > 0, f"cannot build a {total_bytes}-byte item around key {pk!r}"
    return {"pk": {"S": pk}, "b": {"S": "x" * pad}}


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A write costs one WCU per started kilobyte (1024 B: 1, 1025 B: 2, 1.5 KB: 2, 2049 B: 3), and
    ConsumedWriteCapacityUnits reproduces the API's own per-request ConsumedCapacity exactly, in
    total and in its per-request maximum."""
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    table = ctx.unique_name("sim2real-xsvc-ddbm-wu-")

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    start = datetime.now(timezone.utc) - timedelta(minutes=2)

    api_wcu = 0.0
    for copy in range(_COPIES):
        for size, want in _SIZES:
            pk = f"c{copy}-s{size}"
            resp = ddb.put_item(TableName=table, Item=_item(pk, size),
                                ReturnConsumedCapacity="TOTAL")
            got = resp["ConsumedCapacity"]["CapacityUnits"]
            assert got == want, (
                f"a PutItem of exactly {size} bytes reported {got!r} WCU, expected {want!r}: "
                f"one write unit per STARTED 1 KB of item size (attribute names included)")
            api_wcu += got

    assert api_wcu == _EXPECTED_WCU, (
        f"the {_N_PUTS} PutItems reported {api_wcu!r} WCU in total, expected {_EXPECTED_WCU!r}")

    end = datetime.now(timezone.utc) + timedelta(minutes=5)
    tdims = [("TableName", table)]

    def _snapshot():
        return {
            "ConsumedWriteCapacityUnits Sum": _series(
                cw, "ConsumedWriteCapacityUnits", tdims, start, end),
            "ConsumedWriteCapacityUnits Maximum": _series(
                cw, "ConsumedWriteCapacityUnits", tdims, start, end, "Maximum"),
            "SuccessfulRequestLatency PutItem SampleCount": _series(
                cw, "SuccessfulRequestLatency", tdims + [("Operation", "PutItem")],
                start, end, "SampleCount"),
        }

    expected = {
        "ConsumedWriteCapacityUnits Sum": api_wcu,
        "ConsumedWriteCapacityUnits Maximum": _EXPECTED_MAX,
        "SuccessfulRequestLatency PutItem SampleCount": float(_N_PUTS),
    }
    _await_exact(
        ctx, _snapshot, expected, timeout_s=_METRIC_TIMEOUT_S, hold_s=_HOLD_S,
        description=(f"AWS/DynamoDB write accounting for {table!r} (API plane reported "
                     f"{api_wcu!r} WCU over {_N_PUTS} PutItems; a per-request meter would "
                     f"read {float(_N_PUTS)!r})"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
