"""metrics-dynamodb-read-units-4kb-boundary-by-consistency-agree-with-cloudwatch."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-dynamodb-read-units-4kb-boundary-by-consistency-agree-with-cloudwatch"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

#: (item size, WCU to write it, RCU eventually consistent, RCU strongly consistent).
#: Measured on real AWS: a 4096 B item reads for 0.5 / 1.0 and a 4097 B item -- one
#: byte into the second 4 KB block -- reads for 1.0 / 2.0; they write for 4 and 5 WCU.
_ITEMS = ((4096, 4.0, 0.5, 1.0), (4097, 5.0, 1.0, 2.0))
_READS_EACH = 2          # per item, per consistency mode
_EXPECTED_WCU = sum(w for _, w, _, _ in _ITEMS)                                   # 9.0
_EXPECTED_RCU = _READS_EACH * sum(ev + sc for _, _, ev, sc in _ITEMS)             # 9.0
_EXPECTED_RCU_MAX = max(sc for _, _, _, sc in _ITEMS)                             # 2.0
_N_GETS = _READS_EACH * 2 * len(_ITEMS)                                           # 8

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
    """Reads are billed per started 4 KB block, halved for eventual consistency (4096 B: 0.5/1.0 RCU,
    4097 B: 1.0/2.0), and ConsumedReadCapacityUnits carries the same fractional total and per-request
    maximum as the API's own ConsumedCapacity."""
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    table = ctx.unique_name("sim2real-xsvc-ddbm-ru-")

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
    for size, wcu, _, _ in _ITEMS:
        got = ddb.put_item(TableName=table, Item=_item(f"r{size}", size),
                           ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]
        assert got == wcu, f"writing a {size} B item reported {got!r} WCU, expected {wcu!r}"
        api_wcu += got

    api_rcu = 0.0
    for size, _, ev_want, sc_want in _ITEMS:
        key = {"pk": {"S": f"r{size}"}}
        for _ in range(_READS_EACH):
            ev = ddb.get_item(TableName=table, Key=key, ReturnConsumedCapacity="TOTAL")
            assert ev.get("Item", {}).get("pk") == key["pk"], (
                f"eventually consistent GetItem of the {size} B item returned {ev.get('Item')!r}")
            ev_units = ev["ConsumedCapacity"]["CapacityUnits"]
            assert ev_units == ev_want, (
                f"an eventually consistent read of a {size} B item cost {ev_units!r} RCU, "
                f"expected {ev_want!r} (half a unit per started 4 KB block)")
            sc = ddb.get_item(TableName=table, Key=key, ConsistentRead=True,
                              ReturnConsumedCapacity="TOTAL")
            sc_units = sc["ConsumedCapacity"]["CapacityUnits"]
            assert sc_units == sc_want, (
                f"a strongly consistent read of a {size} B item cost {sc_units!r} RCU, "
                f"expected {sc_want!r} (one unit per started 4 KB block)")
            assert sc_units == 2 * ev_units, (
                f"strong read {sc_units!r} is not exactly twice eventual read {ev_units!r}")
            api_rcu += ev_units + sc_units

    assert api_rcu == _EXPECTED_RCU, (
        f"the {_N_GETS} GetItems reported {api_rcu!r} RCU, expected {_EXPECTED_RCU!r}")

    end = datetime.now(timezone.utc) + timedelta(minutes=5)
    tdims = [("TableName", table)]

    def _snapshot():
        return {
            "ConsumedReadCapacityUnits Sum": _series(
                cw, "ConsumedReadCapacityUnits", tdims, start, end),
            "ConsumedReadCapacityUnits Maximum": _series(
                cw, "ConsumedReadCapacityUnits", tdims, start, end, "Maximum"),
            "ConsumedWriteCapacityUnits Sum": _series(
                cw, "ConsumedWriteCapacityUnits", tdims, start, end),
            "SuccessfulRequestLatency GetItem SampleCount": _series(
                cw, "SuccessfulRequestLatency", tdims + [("Operation", "GetItem")],
                start, end, "SampleCount"),
        }

    _await_exact(
        ctx, _snapshot,
        {"ConsumedReadCapacityUnits Sum": api_rcu,
         "ConsumedReadCapacityUnits Maximum": _EXPECTED_RCU_MAX,
         "ConsumedWriteCapacityUnits Sum": api_wcu,
         "SuccessfulRequestLatency GetItem SampleCount": float(_N_GETS)},
        timeout_s=_METRIC_TIMEOUT_S, hold_s=_HOLD_S,
        description=(f"AWS/DynamoDB read accounting for {table!r} (API plane reported "
                     f"{api_rcu!r} RCU over {_N_GETS} GetItems and {api_wcu!r} WCU)"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
