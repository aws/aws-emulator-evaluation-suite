"""batch-get-item-partial-response-capacity-bounded-by-returned-items."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-item-partial-response-capacity-bounded-by-returned-items"
GROUP = "batch"
SERVICES = ["dynamodb"]

# 44 items of 95 of DynamoDB's 4096-byte read-capacity blocks (389120 bytes) total about 17.1 MB,
# over the 16 MB BatchGetItem response ceiling, so the call answers partial.
_N_ITEMS = 44
_BAND = 95 * 4096
_PER_ITEM_RCU = _BAND / 4096


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
    """A BatchGetItem too large for one response bills ConsumedCapacity within one item's cost
    of just the items that response actually returns, never anywhere near the cost of the full
    set of keys requested.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-bgipartcap-")
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

    all_keys = [f"k{i:02d}" for i in range(_N_ITEMS)]
    canary_pad = _pad_for(_BAND, all_keys[0])
    canary_put = ddb.put_item(
        TableName=table, Item={"pk": {"S": all_keys[0]}, "pad": {"S": canary_pad}},
        ReturnConsumedCapacity="TOTAL",
    )
    canary_wcu = canary_put["ConsumedCapacity"]["CapacityUnits"]
    assert canary_wcu == _BAND / 1024, (
        f"the canary write of the {_BAND}-byte item billed {canary_wcu!r} WCU, expected "
        f"{_BAND / 1024!r} -- the capacity math below rests on every item being that size"
    )
    for key in all_keys[1:]:
        ddb.put_item(TableName=table, Item={"pk": {"S": key}, "pad": {"S": _pad_for(_BAND, key)}})

    pending = {table: {"Keys": [{"pk": {"S": k}} for k in all_keys], "ConsistentRead": True}}
    seen: list[str] = []
    rounds = 0
    while pending:
        rounds += 1
        assert rounds <= 10, (
            f"the drain loop did not converge in {rounds} rounds; {len(seen)} of {_N_ITEMS} seen"
        )
        page = ddb.batch_get_item(RequestItems=pending, ReturnConsumedCapacity="TOTAL")
        page_items = page["Responses"][table]
        page_pks = [i["pk"]["S"] for i in page_items]
        if rounds == 1:
            assert len(page_pks) < _N_ITEMS, (
                f"{_N_ITEMS} items of {_BAND} bytes must not fit one response, but the "
                f"first page returned all of them"
            )
        lower = _PER_ITEM_RCU * len(page_pks)
        upper = _PER_ITEM_RCU * (len(page_pks) + 1)
        full_request_cu = _PER_ITEM_RCU * _N_ITEMS
        page_cu = page["ConsumedCapacity"][0]["CapacityUnits"]
        assert lower <= page_cu < upper, (
            f"round {rounds}: a page returning {len(page_pks)} item(s) of {_BAND} bytes each "
            f"billed {page_cu!r} CapacityUnits, expected it within [{lower!r}, {upper!r}) -- the "
            f"cost of just the returned items, plus at most one more item's worth of slack"
        )
        assert page_cu < full_request_cu, (
            f"round {rounds}: a page returning {len(page_pks)} of the {_N_ITEMS} requested items "
            f"billed {page_cu!r} CapacityUnits, which must stay below the full request's "
            f"{full_request_cu!r} -- the partial response must not be billed as if it answered "
            f"every requested key"
        )
        seen += page_pks
        pending = {
            t: spec for t, spec in (page.get("UnprocessedKeys") or {}).items() if spec.get("Keys")
        }

    assert sorted(seen) == sorted(all_keys), (
        f"draining UnprocessedKeys did not yield exactly the requested set: symmetric difference "
        f"{sorted(set(seen) ^ set(all_keys))!r}"
    )
    assert len(seen) == _N_ITEMS, (
        f"the drain returned an item more than once: {len(seen) - len(set(seen))} duplicates in "
        f"{len(seen)} results"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
