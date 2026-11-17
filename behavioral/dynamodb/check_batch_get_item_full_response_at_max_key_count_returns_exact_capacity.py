"""batch-get-item-full-response-at-max-key-count-returns-exact-capacity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-item-full-response-at-max-key-count-returns-exact-capacity"
GROUP = "batch"
SERVICES = ["dynamodb"]

# 100 keys is BatchGetItem's per-call maximum. Each item is exactly 15 of DynamoDB's 4096-byte
# read-capacity blocks (61440 bytes), so the 100-item response (about 6 MB) stays under the 16 MB
# response limit and the expected capacity is a whole number of blocks per item.
_N_ITEMS = 100
_BAND = 15 * 4096


def _pad_for(band: int, pk: str) -> str:
    """Padding that lands the whole item ("pk" name+value, "pad" name+value) at exactly ``band``
    bytes."""
    return "x" * (band - 2 - len(pk) - 3)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchGetItem for the 100-key maximum, with 60 KB items, comes back complete in one
    response with ConsumedCapacity billed as the exact sum of each item's own 4KB-rounded read
    cost, halved for an eventually consistent read.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-bginearcap-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        _teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException")
    )
    ddb.get_waiter("table_exists").wait(
        TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250}
    )

    keys = [f"k{i:03d}" for i in range(_N_ITEMS)]
    canary_pad = _pad_for(_BAND, keys[0])
    canary_put = ddb.put_item(
        TableName=table, Item={"pk": {"S": keys[0]}, "pad": {"S": canary_pad}},
        ReturnConsumedCapacity="TOTAL",
    )
    canary_wcu = canary_put["ConsumedCapacity"]["CapacityUnits"]
    assert canary_wcu == _BAND / 1024, (
        f"the canary write of the {_BAND}-byte item billed {canary_wcu!r} WCU, expected "
        f"{_BAND / 1024!r} -- the capacity math below rests on this item actually being that size"
    )
    for key in keys[1:]:
        ddb.put_item(TableName=table, Item={"pk": {"S": key}, "pad": {"S": _pad_for(_BAND, key)}})

    request_keys = [{"pk": {"S": k}} for k in keys]
    per_item_rcu = _BAND / 4096
    expected_strong_cu = per_item_rcu * _N_ITEMS

    reads = ((True, expected_strong_cu), (False, expected_strong_cu / 2))
    for consistent_read, expected_cu in reads:
        resp = ddb.batch_get_item(
            RequestItems={table: {"Keys": request_keys, "ConsistentRead": consistent_read}},
            ReturnConsumedCapacity="TOTAL",
        )
        unprocessed = resp.get("UnprocessedKeys", {})
        assert unprocessed == {}, (
            f"ConsistentRead={consistent_read!r}: expected all {_N_ITEMS} items to return in one "
            f"response with no UnprocessedKeys, got {unprocessed!r}"
        )
        items = resp["Responses"][table]
        assert len(items) == _N_ITEMS, (
            f"ConsistentRead={consistent_read!r}: expected {_N_ITEMS} items back, got {len(items)}"
        )
        returned = {item["pk"]["S"]: item["pad"]["S"] for item in items}
        assert set(returned) == set(keys), (
            f"ConsistentRead={consistent_read!r}: symmetric difference "
            f"{sorted(set(returned) ^ set(keys))!r}"
        )
        bad_lengths = {
            pk: len(pad) for pk, pad in returned.items() if len(pad) != len(canary_pad)
        }
        assert bad_lengths == {}, (
            f"ConsistentRead={consistent_read!r}: items truncated to fit the response: "
            f"{bad_lengths!r}"
        )
        cu = resp["ConsumedCapacity"][0]["CapacityUnits"]
        assert cu == expected_cu, (
            f"ConsistentRead={consistent_read!r}: BatchGetItem over {_N_ITEMS} items of {_BAND} "
            f"bytes each billed {cu!r} CapacityUnits, expected {expected_cu!r} "
            f"({_N_ITEMS} items x {per_item_rcu!r} RCU each, halved for eventual consistency)"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
