"""metrics-dynamodb-transactional-write-costs-double-in-both-planes."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-dynamodb-transactional-write-costs-double-in-both-planes"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

#: Item sizes written identically to two twin tables: once with PutItem, once as a single-Put
#: TransactWriteItems. 1024 B costs 1 WCU plain / 2 WCU transactional; 1025 B crosses the 1 KB
#: boundary and costs 2 / 4.
_SIZES = (1024, 1025)
_COPIES = 3
_EXPECTED_PLAIN = _COPIES * (1.0 + 2.0)       # 9.0
_EXPECTED_TXN = 2 * _EXPECTED_PLAIN           # 18.0
_N_WRITES = _COPIES * len(_SIZES)             # 6 per table

_METRIC_TIMEOUT_S = 200
_HOLD_S = 30


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


def _await_exact(probe, expected, *, timeout_s, hold_s, interval_s=1, description, ctx=None):
    """Poll probe() until it EQUALS expected, then require it to hold for hold_s.

    Waits for arrival, never for speed: the timeout is a ceiling, not an assertion. An
    over-count never equals expected and fails at the ceiling with the reading quoted.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if last == expected:
            break
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"{description}: never equalled {expected!r} within {timeout_s}s; "
                f"last reading {last!r}")
        time.sleep(interval_s)
    hold_until = time.monotonic() + hold_s
    while time.monotonic() < hold_until:
        time.sleep(interval_s)
        got = probe()
        assert got == expected, (
            f"{description}: reached {expected!r} and then moved to {got!r}")
    return last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _make_table(ctx, ddb, prefix):
    name = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=name, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    return name


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A single-Put TransactWriteItems costs exactly twice the WCU of the same item via PutItem,
    both in ConsumedCapacity and in CloudWatch ConsumedWriteCapacityUnits, and latency series
    book each table's writes under its own Operation only.
    """
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    plain = _make_table(ctx, ddb, "sim2real-xsvc-ddbm-txp-")
    txn = _make_table(ctx, ddb, "sim2real-xsvc-ddbm-txt-")
    for t in (plain, txn):
        ddb.get_waiter("table_exists").wait(
            TableName=t,
            WaiterConfig={"Delay": 1, "MaxAttempts": 120},
        )

    start = datetime.now(timezone.utc) - timedelta(minutes=2)

    api_plain = api_txn = 0.0
    for copy in range(_COPIES):
        for size in _SIZES:
            pk = f"c{copy}-s{size}"
            p = ddb.put_item(TableName=plain, Item=_item(pk, size),
                             ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]
            t = ddb.transact_write_items(
                TransactItems=[{"Put": {"TableName": txn, "Item": _item(pk, size)}}],
                ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]
            assert len(t) == 1 and t[0]["TableName"] == txn, (
                f"TransactWriteItems ConsumedCapacity should name exactly {txn!r}, got {t!r}")
            assert t[0]["CapacityUnits"] == 2 * p["CapacityUnits"], (
                f"a {size} B item cost {p['CapacityUnits']!r} WCU through PutItem but "
                f"{t[0]['CapacityUnits']!r} through TransactWriteItems; a transactional write "
                f"must cost exactly double")
            assert t[0].get("WriteCapacityUnits") == t[0]["CapacityUnits"], (
                f"a write-only transaction's WriteCapacityUnits {t[0].get('WriteCapacityUnits')!r} "
                f"must equal its CapacityUnits {t[0]['CapacityUnits']!r}")
            api_plain += p["CapacityUnits"]
            api_txn += t[0]["CapacityUnits"]

    assert (api_plain, api_txn) == (_EXPECTED_PLAIN, _EXPECTED_TXN), (
        f"API plane reported plain={api_plain!r} and transactional={api_txn!r} WCU, expected "
        f"{_EXPECTED_PLAIN!r} and {_EXPECTED_TXN!r}")

    # Both copies are really stored, byte-identical, so the extra cost bought no extra data.
    for copy in range(_COPIES):
        for size in _SIZES:
            key = {"pk": {"S": f"c{copy}-s{size}"}}
            a = ddb.get_item(TableName=plain, Key=key, ConsistentRead=True).get("Item")
            b = ddb.get_item(TableName=txn, Key=key, ConsistentRead=True).get("Item")
            assert a is not None and a == b, (
                f"key {key!r}: plain table holds {a and len(a['b']['S'])!r}-char blob, "
                f"transactional table holds {b and len(b['b']['S'])!r}; they must be identical")

    end = datetime.now(timezone.utc) + timedelta(minutes=5)

    def _lat(t, op):
        return _series(cw, "SuccessfulRequestLatency",
                       [("TableName", t), ("Operation", op)], start, end, "SampleCount")

    def _snapshot():
        return {
            "plain WCU Sum": _series(cw, "ConsumedWriteCapacityUnits",
                                     [("TableName", plain)], start, end),
            "txn WCU Sum": _series(cw, "ConsumedWriteCapacityUnits",
                                   [("TableName", txn)], start, end),
            "txn latency TransactWriteItems": _lat(txn, "TransactWriteItems"),
            "txn latency PutItem": _lat(txn, "PutItem"),
            "plain latency PutItem": _lat(plain, "PutItem"),
            "plain latency TransactWriteItems": _lat(plain, "TransactWriteItems"),
        }

    _await_exact(
        _snapshot,
        {"plain WCU Sum": api_plain,
         "txn WCU Sum": api_txn,
         "txn latency TransactWriteItems": float(_N_WRITES),
         "txn latency PutItem": None,
         "plain latency PutItem": float(_N_WRITES),
         "plain latency TransactWriteItems": None},
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S), ctx=ctx, hold_s=_HOLD_S,
        description=(f"AWS/DynamoDB write accounting for twin tables {plain!r} (PutItem, "
                     f"{api_plain!r} WCU) and {txn!r} (TransactWriteItems, {api_txn!r} WCU)"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
