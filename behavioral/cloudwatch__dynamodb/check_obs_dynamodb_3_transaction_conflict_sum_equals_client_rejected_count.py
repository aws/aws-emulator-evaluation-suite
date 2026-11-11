"""obs-dynamodb-3-transaction-conflict-sum-equals-client-rejected-count."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-dynamodb-3-transaction-conflict-sum-equals-client-rejected-count"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

_NS = "AWS/DynamoDB"
_METRIC = "TransactionConflict"
ERR_CANCELLED = "TransactionCanceledException"
REASON_CONFLICT = "TransactionConflict"
CANCELLED_MESSAGE = ("Transaction cancelled, please refer cancellation reasons for specific reasons "
                     "[TransactionConflict]")
CONFLICT_MESSAGE = "Transaction is ongoing for the item"
#: Two racers, fired together through a barrier, for a fixed number of rounds. Real AWS may or
#: may not cancel any of them; the metric must equal whatever the client counted.
_RACERS = 2
_ROUNDS = 10
_CONTROL_WRITES = 10
_BUDGET_S = 900
_HOLD_S = 30
_INTERVAL_S = 2


# ===== helpers =====
def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 10 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 10.0))


def _exact_dimension_sets(cw, metric, table):
    """Every dimension set list_metrics reports for (AWS/DynamoDB, metric) on this table."""
    sets = []
    for page in cw.get_paginator("list_metrics").paginate(
            Namespace=_NS, MetricName=metric,
            Dimensions=[{"Name": "TableName", "Value": table}]):
        for m in page["Metrics"]:
            sets.append(sorted((d["Name"], d["Value"]) for d in m["Dimensions"]))
    return sets


def _sum(cw, metric, table, start, end):
    """Sum over the window, or None if the series has no datapoints."""
    dps = cw.get_metric_statistics(
        Namespace=_NS, MetricName=metric,
        Dimensions=[{"Name": "TableName", "Value": table}],
        StartTime=start, EndTime=end, Period=60, Statistics=["Sum"])["Datapoints"]
    if not dps:
        return None
    return sum(d["Sum"] for d in dps)


def _await_exact(probe, expected, *, deadline, hold_s, interval_s, description):
    """Poll probe() until it EQUALS expected, then require it to hold for hold_s (two-sided:
    an over-count never equals expected and fails at the ceiling with the reading quoted)."""
    last = None
    while True:
        last = probe()
        if last == expected:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: never equalled {expected!r} before the wait ceiling; "
                f"last reading {last!r}")
        time.sleep(interval_s)
    hold_until = min(time.monotonic() + hold_s, deadline)
    while time.monotonic() < hold_until:
        time.sleep(interval_s)
        got = probe()
        assert got == expected, f"{description}: reached {expected!r} and then moved to {got!r}"
    return last


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


def _txn_add(ddb, table):
    """One single-item unconditional TransactWriteItems. Returns 'ok', or (message,
    CancellationReasons) on a cancellation; anything else raises."""
    try:
        ddb.transact_write_items(TransactItems=[{"Update": {
            "TableName": table, "Key": {"pk": {"S": "HOT"}},
            "UpdateExpression": "ADD hits :one",
            "ExpressionAttributeValues": {":one": {"N": "1"}},
        }}])
        return "ok"
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != ERR_CANCELLED:
            raise
        reasons = exc.response.get("CancellationReasons") or []
        return exc.response["Error"].get("Message"), [
            {"Code": r.get("Code"), "Message": r.get("Message")} for r in reasons]
# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """AWS/DynamoDB TransactionConflict{TableName} sums to exactly the TransactWriteItems the client
    saw cancelled for TransactionConflict (zero is allowed), every cancellation carries the exact
    message and reason, the item counts only commits, and a serial control table reads zero.
    """
    # Exactly one attempt per call: a transparent SDK retry would hide a rejection from the
    # client tally while the server still counted it.
    ddb_once = ctx.client("dynamodb", config=Config(retries={"total_max_attempts": 1}))
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    hot = _make_table(ctx, ddb, "sim2real-xsvc-ddbm-tch-")
    control = _make_table(ctx, ddb, "sim2real-xsvc-ddbm-tcc-")
    for t in (hot, control):
        ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    start = datetime.now(timezone.utc) - timedelta(minutes=5)

    committed = 0
    conflicts = 0
    bad_cancellations = []
    barrier = threading.Barrier(_RACERS)

    def _racer():
        barrier.wait(timeout=30)
        return _txn_add(ddb_once, hot)

    want_reasons = [{"Code": REASON_CONFLICT, "Message": CONFLICT_MESSAGE}]
    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        for _ in range(_ROUNDS):
            for outcome in [f.result() for f in [pool.submit(_racer) for _ in range(_RACERS)]]:
                if outcome == "ok":
                    committed += 1
                elif outcome == (CANCELLED_MESSAGE, want_reasons):
                    conflicts += 1
                else:
                    bad_cancellations.append(outcome)
    assert not bad_cancellations, (
        f"a single-item unconditional transaction may only be cancelled with message "
        f"{CANCELLED_MESSAGE!r} and reasons {want_reasons!r}; saw {bad_cancellations[:5]!r}")
    assert committed > 0, (
        f"{_ROUNDS} rounds produced {conflicts} cancellations and no commit at all; at least one "
        f"racer must win")

    hits = ddb.get_item(TableName=hot, Key={"pk": {"S": "HOT"}}, ConsistentRead=True)["Item"]
    assert hits["hits"] == {"N": str(committed)}, (
        f"HOT.hits is {hits['hits']!r} after {committed} commits and {conflicts} cancellations; a "
        f"cancelled transaction must write nothing")

    # Control: the same transaction, serially, on an uncontended table never conflicts.
    for i in range(_CONTROL_WRITES):
        got = _txn_add(ddb_once, control)
        assert got == "ok", f"serial control transaction {i} on {control!r} was refused: {got!r}"

    deadline = time.monotonic() + _budget_s(ctx, _BUDGET_S)

    def _end():
        return datetime.now(timezone.utc) + timedelta(minutes=5)

    def _assert_zero_conflicts(table, writes, why):
        # Barrier for the absence: the table's own capacity series must have published the
        # writes it took (a single-item transactional write of a tiny item costs 2 WCU).
        _await_exact(
            lambda: [("TableName", table)] in _exact_dimension_sets(
                cw, "ConsumedWriteCapacityUnits", table),
            True, deadline=deadline, hold_s=0, interval_s=_INTERVAL_S,
            description=f"list_metrics ConsumedWriteCapacityUnits TableName={table!r}")
        _await_exact(lambda: _sum(cw, "ConsumedWriteCapacityUnits", table, start, _end()),
                     2.0 * writes, deadline=deadline, hold_s=0, interval_s=_INTERVAL_S,
                     description=f"ConsumedWriteCapacityUnits Sum for {table!r}")
        got = _sum(cw, _METRIC, table, start, _end()) or 0.0
        assert got == 0.0, (
            f"table {table!r} took {writes} transactions and {why}, yet {_METRIC} reads {got!r}")

    if conflicts:
        _await_exact(
            lambda: [("TableName", hot)] in _exact_dimension_sets(cw, _METRIC, hot),
            True, deadline=deadline, hold_s=0, interval_s=_INTERVAL_S,
            description=f"list_metrics({_NS}, {_METRIC}, TableName={hot!r}) exact dimension set")
        _await_exact(lambda: _sum(cw, _METRIC, hot, start, _end()), float(conflicts),
                     deadline=deadline, hold_s=_HOLD_S, interval_s=_INTERVAL_S,
                     description=(f"{_NS} {_METRIC} Sum for {hot!r} against {conflicts} "
                                  f"client-side TransactionConflict cancellations"))
    else:
        _assert_zero_conflicts(hot, committed, "the client saw no cancellation")
    _assert_zero_conflicts(control, _CONTROL_WRITES, "no conflict (serial)")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
