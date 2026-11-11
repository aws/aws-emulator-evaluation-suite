"""metrics-dynamodb-cancelled-transact-write-items-still-consumes-write-capacity."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-dynamodb-cancelled-transact-write-items-still-consumes-write-capacity"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

_ITEM_BYTES = 1024    # exactly 1 KB, so a plain write costs exactly 1 WCU
_CANCELLATIONS = 5
_METRIC_TIMEOUT_S = 200
_HOLD_S = 30
_CANCEL_MESSAGE = ("Transaction cancelled, please refer cancellation reasons for specific "
                  "reasons [ConditionalCheckFailed]")


# ===== helpers =====
def _item(pk: str, total_bytes: int) -> dict:
    """A {pk, b} item whose DynamoDB item size is exactly total_bytes (ASCII only)."""
    pad = total_bytes - len("pk") - len(pk) - len("b")
    assert pad > 0, f"cannot build a {total_bytes}-byte item around key {pk!r}"
    return {"pk": {"S": pk}, "b": {"S": "x" * pad}}


def _cancelled(fn):
    """(message, [(code, message), ...] cancellation reasons) of a transaction real AWS cancels.

    RAISES if the call succeeds, or if it fails any other way.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] != "TransactionCanceledException":
            raise
        assert "ConsumedCapacity" not in exc.response, (
            f"the cancelled transaction reported ConsumedCapacity "
            f"{exc.response.get('ConsumedCapacity')!r} in-band")
        reasons = [(r.get("Code"), r.get("Message")) for r in exc.response.get("CancellationReasons", [])]
        return err.get("Message"), reasons
    raise AssertionError(f"expected the transaction to be cancelled; it succeeded: {result!r}")


def _wcu_sum(cw, table, start, end):
    dps = cw.get_metric_statistics(
        Namespace="AWS/DynamoDB", MetricName="ConsumedWriteCapacityUnits",
        Dimensions=[{"Name": "TableName", "Value": table}],
        StartTime=start, EndTime=end, Period=60, Statistics=["Sum"])["Datapoints"]
    if not dps:
        return None
    return sum(d["Sum"] for d in dps)
# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics",
      "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A single-Put TransactWriteItems cancelled by a failed condition check writes nothing and
    reports no capacity in-band, yet still adds write capacity to ConsumedWriteCapacityUnits —
    measured against the same item size's cost through a committed single-Put transaction."""
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    table = ctx.unique_name("sim2real-xsvc-ddbm-txc-")

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    start = datetime.now(timezone.utc) - timedelta(minutes=2)

    # --- seed: a plain 1 KB item at the key every cancelled transaction will target ---------
    seed_item = _item("lock", _ITEM_BYTES)
    seed_wcu = ddb.put_item(TableName=table, Item=seed_item,
                            ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]
    assert seed_wcu == 1.0, f"a {_ITEM_BYTES} B seed PutItem reported {seed_wcu!r} WCU, expected 1.0"

    # --- positive control: a committed single-Put transaction on a FRESH 1 KB item ----------
    committed_item = _item("committed", _ITEM_BYTES)
    committed = ddb.transact_write_items(
        TransactItems=[{"Put": {"TableName": table, "Item": committed_item,
                                "ConditionExpression": "attribute_not_exists(pk)"}}],
        ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]
    assert len(committed) == 1 and committed[0]["TableName"] == table, (
        f"TransactWriteItems ConsumedCapacity should name exactly {table!r}, got {committed!r}")
    committed_wcu = committed[0]["CapacityUnits"]
    assert committed_wcu == 2.0, (
        f"a committed single-Put transaction on a {_ITEM_BYTES} B item reported {committed_wcu!r} "
        f"WCU in-band, expected 2.0 (a transactional write costs double a plain write)")

    # --- break exactly one thing: the condition on every attempt is refused, so the whole
    # --- transaction is cancelled before it writes anything ---------------------------------
    for i in range(_CANCELLATIONS):
        message, reasons = _cancelled(lambda i=i: ddb.transact_write_items(TransactItems=[{"Put": {
            "TableName": table, "Item": _item("lock", _ITEM_BYTES),
            "ConditionExpression": "attribute_not_exists(pk)"}}], ReturnConsumedCapacity="TOTAL"))
        assert message == _CANCEL_MESSAGE, (
            f"cancellation {i}: message was {message!r}, expected {_CANCEL_MESSAGE!r}")
        assert reasons == [("ConditionalCheckFailed", "The conditional request failed")], (
            f"cancellation {i}: CancellationReasons were {reasons!r}, expected a single "
            f"ConditionalCheckFailed reason")

    # --- effect absent: neither the lock item nor the committed item was touched by a
    # --- cancelled attempt --------------------------------------------------------------
    still_lock = ddb.get_item(TableName=table, Key={"pk": {"S": "lock"}}, ConsistentRead=True).get("Item")
    assert still_lock == seed_item, f"the lock item changed after cancelled transactions: {still_lock!r}"
    still_committed = ddb.get_item(TableName=table, Key={"pk": {"S": "committed"}},
                                   ConsistentRead=True).get("Item")
    assert still_committed == committed_item, (
        f"the committed item changed after cancelled transactions: {still_committed!r}")

    end = datetime.now(timezone.utc) + timedelta(minutes=5)

    # The table total once every write is folded in: the seed, the committed control, and
    # one committed-sized charge per cancelled transaction. Poll until the Sum equals it, then
    # require it to hold, so a late over-count fails with the reading quoted.
    accounted = seed_wcu + committed_wcu
    expected_total = accounted + _CANCELLATIONS * committed_wcu
    left = ctx.time_left()
    budget = _METRIC_TIMEOUT_S if left is None else max(1.0, min(_METRIC_TIMEOUT_S, left - 5.0 - _HOLD_S))
    deadline = time.monotonic() + budget
    while True:
        last = _wcu_sum(cw, table, start, end)
        if last == expected_total or time.monotonic() >= deadline:
            break
        time.sleep(2)
    hold_until = time.monotonic() + _HOLD_S
    while last == expected_total and time.monotonic() < hold_until:
        time.sleep(2)
        last = _wcu_sum(cw, table, start, end)

    per_cancellation = (last - accounted) / _CANCELLATIONS if last is not None else None
    assert per_cancellation == committed_wcu, (
        f"{_CANCELLATIONS} cancelled single-Put transactions on a {_ITEM_BYTES} B item added "
        f"{per_cancellation!r} WCU each to ConsumedWriteCapacityUnits (table total {last!r}, seed "
        f"{seed_wcu!r}, committed control {committed_wcu!r}); a cancelled transaction must consume "
        f"the same write capacity as the committed one it was shaped like, {committed_wcu!r} WCU, "
        f"not just its prepare phase")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
