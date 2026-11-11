"""metrics-dynamodb-refused-conditional-putitem-write-capacity-sizing."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-dynamodb-refused-conditional-putitem-write-capacity-sizing"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

_SMALL_BYTES = 20
_LARGE_BYTES = 3072   # exactly 3 KB, so the per-KB rounding lands on a whole WCU
_REFUSALS = 5
_METRIC_TIMEOUT_S = 200
_HOLD_S = 30
_CCF_MESSAGE = "The conditional request failed"


# ===== helpers =====
def _item(pk: str, total_bytes: int) -> dict:
    """A {pk, b} item whose DynamoDB item size is exactly total_bytes (ASCII only)."""
    pad = total_bytes - len("pk") - len(pk) - len("b")
    assert pad > 0, f"cannot build a {total_bytes}-byte item around key {pk!r}"
    return {"pk": {"S": pk}, "b": {"S": "x" * pad}}


def _refusal(fn):
    """(code, full error response) of a call real AWS refuses. RAISES if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response
    raise AssertionError(f"expected the conditional write to be refused; it succeeded: {result!r}")


def _make_table(ctx, ddb, prefix):
    name = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=name, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


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
    """A conditional PutItem refused with ConditionalCheckFailedException bills
    ConsumedWriteCapacityUnits by the size of the item already stored at the key, not the size
    of the attempted write; against an absent key it bills the one-unit minimum instead."""
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")

    start = datetime.now(timezone.utc) - timedelta(minutes=2)

    table_large_existing = _make_table(ctx, ddb, "sim2real-xsvc-ddbm-bigv-")
    table_small_existing = _make_table(ctx, ddb, "sim2real-xsvc-ddbm-smlv-")
    table_new_key = _make_table(ctx, ddb, "sim2real-xsvc-ddbm-newk-")

    # --- seed: one real item on each of the first two tables, sized at an extreme -----------
    large_item = _item("victim", _LARGE_BYTES)
    seed_large = ddb.put_item(TableName=table_large_existing, Item=large_item,
                              ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]
    assert seed_large == 3.0, f"a {_LARGE_BYTES} B seed PutItem reported {seed_large!r} WCU, expected 3.0"

    small_item = _item("victim", _SMALL_BYTES)
    seed_small = ddb.put_item(TableName=table_small_existing, Item=small_item,
                              ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]
    assert seed_small == 1.0, f"a {_SMALL_BYTES} B seed PutItem reported {seed_small!r} WCU, expected 1.0"

    # --- break exactly one thing per table: the attempted write's size now differs from what
    # --- is already stored at the key, and the condition refuses every attempt --------------
    for i in range(_REFUSALS):
        code, err = _refusal(lambda i=i: ddb.put_item(
            TableName=table_large_existing, Item=_item("victim", _SMALL_BYTES),
            ConditionExpression="attribute_not_exists(pk)", ReturnConsumedCapacity="TOTAL"))
        message = err["Error"].get("Message")
        assert (code, message) == ("ConditionalCheckFailedException", _CCF_MESSAGE), (
            f"refusal {i} against the {_LARGE_BYTES} B existing item: raised {(code, message)!r}, "
            f"expected {('ConditionalCheckFailedException', _CCF_MESSAGE)!r}")
        assert "ConsumedCapacity" not in err, (
            f"refusal {i}: the error response carried ConsumedCapacity {err.get('ConsumedCapacity')!r}"
            f"; real AWS reports none in-band on a refused write")

    for i in range(_REFUSALS):
        code, err = _refusal(lambda i=i: ddb.put_item(
            TableName=table_small_existing, Item=_item("victim", _LARGE_BYTES),
            ConditionExpression="attribute_not_exists(pk)", ReturnConsumedCapacity="TOTAL"))
        message = err["Error"].get("Message")
        assert (code, message) == ("ConditionalCheckFailedException", _CCF_MESSAGE), (
            f"refusal {i} against the {_SMALL_BYTES} B existing item: raised {(code, message)!r}, "
            f"expected {('ConditionalCheckFailedException', _CCF_MESSAGE)!r}")

    for i in range(_REFUSALS):
        key = f"absent{i}"
        code, err = _refusal(lambda key=key: ddb.put_item(
            TableName=table_new_key, Item=_item(key, _SMALL_BYTES),
            ConditionExpression="attribute_exists(pk)", ReturnConsumedCapacity="TOTAL"))
        message = err["Error"].get("Message")
        assert (code, message) == ("ConditionalCheckFailedException", _CCF_MESSAGE), (
            f"refusal {i} against absent key {key!r}: raised {(code, message)!r}, expected "
            f"{('ConditionalCheckFailedException', _CCF_MESSAGE)!r}")

    # --- effect absent: every refused write left its table's stored item byte-identical ------
    still_large = ddb.get_item(TableName=table_large_existing, Key={"pk": {"S": "victim"}},
                               ConsistentRead=True).get("Item")
    assert still_large == large_item, (
        f"the {_LARGE_BYTES} B existing item changed after refused writes: {still_large!r}")
    still_small = ddb.get_item(TableName=table_small_existing, Key={"pk": {"S": "victim"}},
                               ConsistentRead=True).get("Item")
    assert still_small == small_item, (
        f"the {_SMALL_BYTES} B existing item changed after refused writes: {still_small!r}")
    for i in range(_REFUSALS):
        absent = ddb.get_item(TableName=table_new_key, Key={"pk": {"S": f"absent{i}"}},
                              ConsistentRead=True).get("Item")
        assert absent is None, f"key absent{i!r} should not exist; GetItem returned {absent!r}"

    end = datetime.now(timezone.utc) + timedelta(minutes=5)

    # The three table totals once every write is folded in: each table's seed plus one charge
    # per refusal, sized by the item already stored at the key (3 KB -> 3, 20 B -> 1) or the
    # one-unit minimum for an absent key. Poll until all three equal them, then require them
    # to hold, so a late over-count fails with the readings quoted.
    expected = (seed_large + _REFUSALS * 3.0, seed_small + _REFUSALS * 1.0, _REFUSALS * 1.0)

    def _all_three():
        return (_wcu_sum(cw, table_large_existing, start, end) or 0.0,
                _wcu_sum(cw, table_small_existing, start, end) or 0.0,
                _wcu_sum(cw, table_new_key, start, end) or 0.0)

    left = ctx.time_left()
    budget = _METRIC_TIMEOUT_S if left is None else max(1.0, min(_METRIC_TIMEOUT_S, left - 5.0 - _HOLD_S))
    deadline = time.monotonic() + budget
    while True:
        last = _all_three()
        if last == expected or time.monotonic() >= deadline:
            break
        time.sleep(2)
    hold_until = time.monotonic() + _HOLD_S
    while last == expected and time.monotonic() < hold_until:
        time.sleep(2)
        last = _all_three()

    wcu_large_existing, wcu_small_existing, wcu_new_key = last

    # The per-refusal unit each table's refusals added, net of the seed write.
    per_refusal_large_existing = (wcu_large_existing - seed_large) / _REFUSALS
    per_refusal_small_existing = (wcu_small_existing - seed_small) / _REFUSALS
    per_refusal_new_key = wcu_new_key / _REFUSALS

    assert per_refusal_large_existing == 3.0, (
        f"{_REFUSALS} refusals of a {_SMALL_BYTES} B write against a {_LARGE_BYTES} B existing "
        f"item added {per_refusal_large_existing!r} WCU each (table total {wcu_large_existing!r}, "
        f"seed {seed_large!r}); a refused write is billed by the size of the item already "
        f"stored at the key, not the size of the write it attempted")
    assert per_refusal_small_existing == 1.0, (
        f"{_REFUSALS} refusals of a {_LARGE_BYTES} B write against a {_SMALL_BYTES} B existing "
        f"item added {per_refusal_small_existing!r} WCU each (table total {wcu_small_existing!r}, "
        f"seed {seed_small!r}); a refused write is billed by the size of the item already "
        f"stored at the key, not the size of the write it attempted")
    assert per_refusal_new_key == 1.0, (
        f"{_REFUSALS} refusals against an absent key added {per_refusal_new_key!r} WCU each "
        f"(table total {wcu_new_key!r}); with no existing item to size the refusal by, it must "
        f"bill the one-unit minimum")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
