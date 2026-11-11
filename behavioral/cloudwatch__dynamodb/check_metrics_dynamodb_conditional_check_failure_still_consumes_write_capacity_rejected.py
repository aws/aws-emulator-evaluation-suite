"""metrics-dynamodb-conditional-check-failure-still-consumes-write-capacity-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-dynamodb-conditional-check-failure-still-consumes-write-capacity-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

_SEEDS = 3         # conditional PutItems that SUCCEED (positive control): 1 KB -> 1 WCU each
_REFUSALS = 4      # conditional PutItems refused against an existing 1 KB item
_ITEM_BYTES = 1024
#: Measured on real AWS: a refused conditional PutItem returns NO ConsumedCapacity in its
#: error body even with ReturnConsumedCapacity=TOTAL, yet the table's ConsumedWriteCapacityUnits
#: rises by the refused write's size in WCU; refused writes are absent from
#: SuccessfulRequestLatency's PutItem SampleCount.
_EXPECTED_WCU = float(_SEEDS + _REFUSALS)       # 7.0 -- the API plane can only account for 3.0

_METRIC_TIMEOUT_S = 200
_HOLD_S = 30
_CONDITION_FAILED_MESSAGE = "The conditional request failed"


# ===== helpers =====
def _item(pk: str, marker: str, total_bytes: int) -> dict:
    """A {pk, m, b} item whose DynamoDB item size is exactly total_bytes (ASCII only)."""
    pad = total_bytes - len("pk") - len(pk) - len("m") - len(marker) - len("b")
    assert pad > 0, f"cannot build a {total_bytes}-byte item around key {pk!r}"
    return {"pk": {"S": pk}, "m": {"S": marker}, "b": {"S": "x" * pad}}


def _refusal(fn):
    """(error code, full error response) of a call real AWS refuses. RAISES if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response
    raise AssertionError(f"expected the conditional write to be refused; it succeeded: {result!r}")


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
@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics",
      "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A conditional PutItem refused with ConditionalCheckFailedException writes nothing and reports
    no ConsumedCapacity, yet still adds one WCU per refused 1 KB write to ConsumedWriteCapacityUnits,
    while ConditionalCheckFailedRequests counts the refusals and SuccessfulRequestLatency only successes."""
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    table = ctx.unique_name("sim2real-xsvc-ddbm-ccf-")

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    start = datetime.now(timezone.utc) - timedelta(minutes=2)

    # --- positive control: the same conditional write SUCCEEDS where the key is absent -------
    api_wcu = 0.0
    originals = {}
    for i in range(_SEEDS):
        item = _item(f"k{i}", "first", _ITEM_BYTES)
        resp = ddb.put_item(TableName=table, Item=item,
                            ConditionExpression="attribute_not_exists(pk)",
                            ReturnConsumedCapacity="TOTAL")
        units = resp["ConsumedCapacity"]["CapacityUnits"]
        assert units == 1.0, f"a successful conditional 1 KB PutItem reported {units!r} WCU"
        api_wcu += units
        originals[f"k{i}"] = item

    # --- break exactly one thing: the key now exists, so the same condition must fail --------
    for i in range(_REFUSALS):
        pk = f"k{i % _SEEDS}"
        code, err = _refusal(lambda pk=pk, i=i: ddb.put_item(
            TableName=table, Item=_item(pk, f"loser{i}", _ITEM_BYTES),
            ConditionExpression="attribute_not_exists(pk)",
            ReturnConsumedCapacity="TOTAL"))
        message = err["Error"].get("Message")
        assert (code, message) == ("ConditionalCheckFailedException", _CONDITION_FAILED_MESSAGE), (
            f"refusal {i}: a PutItem guarded by attribute_not_exists(pk) on existing key {pk!r} "
            f"raised {(code, message)!r}, expected "
            f"{('ConditionalCheckFailedException', _CONDITION_FAILED_MESSAGE)!r}")
        assert "ConsumedCapacity" not in err, (
            f"refusal {i}: the error response carried ConsumedCapacity {err.get('ConsumedCapacity')!r}"
            f"; real AWS reports none on a refused write, so the metric plane is the only witness")

    # --- effect absent: every refused write left the stored item byte-identical ---------------
    for pk, want in originals.items():
        got = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")
        assert got == want, (
            f"after refused writes, {pk!r} holds marker {got and got['m']['S']!r}; expected the "
            f"original 'first' item untouched")

    end = datetime.now(timezone.utc) + timedelta(minutes=5)
    t = [("TableName", table)]

    def _snapshot():
        return {
            "ConsumedWriteCapacityUnits Sum": _series(cw, "ConsumedWriteCapacityUnits", t,
                                                      start, end),
            "ConditionalCheckFailedRequests Sum": _series(cw, "ConditionalCheckFailedRequests",
                                                          t, start, end),
            "SuccessfulRequestLatency PutItem SampleCount": _series(
                cw, "SuccessfulRequestLatency", t + [("Operation", "PutItem")],
                start, end, "SampleCount"),
        }

    _await_exact(
        ctx, _snapshot,
        {"ConsumedWriteCapacityUnits Sum": _EXPECTED_WCU,
         "ConditionalCheckFailedRequests Sum": float(_REFUSALS),
         "SuccessfulRequestLatency PutItem SampleCount": float(_SEEDS)},
        timeout_s=_METRIC_TIMEOUT_S, hold_s=_HOLD_S,
        description=(f"AWS/DynamoDB accounting for {table!r}: the API plane admitted to "
                     f"{api_wcu!r} WCU over {_SEEDS} successful conditional writes; each of the "
                     f"{_REFUSALS} refused 1 KB writes must add 1 WCU the API never reported"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
