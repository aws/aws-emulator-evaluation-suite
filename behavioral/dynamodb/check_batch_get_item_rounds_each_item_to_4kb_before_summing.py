"""batch-get-item-rounds-each-item-to-4kb-before-summing."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-item-rounds-each-item-to-4kb-before-summing"
GROUP = "capacity"
SERVICES = ["dynamodb"]

_KB = 1024
_SMALL_BAND = 1 * _KB
_LARGE_BAND = 5 * _KB


def _pad_for(band: int, pk: str) -> str:
    """Padding that lands the whole item just inside `band` bytes.

    Overhead accounted for: the "pk" name (2) + its value, and the "pad" name (3).
    """
    return "x" * (band - 2 - len(pk) - 3)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetItem rounds each item up to its own 4KB block and then totals the blocks, rather
    than summing bytes first and rounding once; INDEXES reports the same total under Table.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbbgiround-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 90})

    small_pk, large_pk = "small", "large"
    for pk, band in ((small_pk, _SMALL_BAND), (large_pk, _LARGE_BAND)):
        put = ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "pad": {"S": _pad_for(band, pk)}},
                           ReturnConsumedCapacity="TOTAL")
        got_wcu = put["ConsumedCapacity"]["CapacityUnits"]
        assert got_wcu == band / _KB, (
            f"the canary write of the {band}-byte {pk!r} item billed {got_wcu!r} WCU, expected "
            f"{band / _KB!r} -- the read assertions below rest on this item actually being that size"
        )

    keys = [{"pk": {"S": small_pk}}, {"pk": {"S": large_pk}}]

    for rcc in ("TOTAL", "INDEXES"):
        strong = ddb.batch_get_item(
            RequestItems={table: {"Keys": keys, "ConsistentRead": True}}, ReturnConsumedCapacity=rcc,
        )
        eventual = ddb.batch_get_item(
            RequestItems={table: {"Keys": keys, "ConsistentRead": False}}, ReturnConsumedCapacity=rcc,
        )
        for label, resp in (("strong", strong), ("eventual", eventual)):
            unprocessed = resp.get("UnprocessedKeys") or {}
            assert not unprocessed, (
                f"{rcc} {label} BatchGetItem left UnprocessedKeys {unprocessed!r}; its capacity "
                f"number therefore covers fewer than both items and cannot be compared"
            )
            returned = {item["pk"]["S"] for item in resp["Responses"][table]}
            assert returned == {small_pk, large_pk}, (
                f"{rcc} {label} BatchGetItem returned {sorted(returned)!r}, expected both items"
            )

        strong_cu = strong["ConsumedCapacity"][0]["CapacityUnits"]
        eventual_cu = eventual["ConsumedCapacity"][0]["CapacityUnits"]
        assert strong_cu == 3.0, (
            f"{rcc}: a strongly consistent BatchGetItem over a 1KB and a 5KB item billed "
            f"{strong_cu!r}, expected 3.0 (1 block for the 1KB item plus 2 for the 5KB item, "
            f"each item rounded up on its own) -- 2.0 would mean the 6KB combined total was "
            f"summed first and rounded once"
        )
        assert eventual_cu == 1.5, (
            f"{rcc}: an eventually consistent BatchGetItem over the same two items billed "
            f"{eventual_cu!r}, expected 1.5 (half of the strongly consistent 3.0)"
        )

        if rcc == "INDEXES":
            strong_table_cu = strong["ConsumedCapacity"][0]["Table"]["CapacityUnits"]
            eventual_table_cu = eventual["ConsumedCapacity"][0]["Table"]["CapacityUnits"]
            assert strong_table_cu == strong_cu, (
                f"INDEXES strong Table.CapacityUnits was {strong_table_cu!r}, expected it to equal "
                f"the overall total {strong_cu!r}"
            )
            assert eventual_table_cu == eventual_cu, (
                f"INDEXES eventual Table.CapacityUnits was {eventual_table_cu!r}, expected it to "
                f"equal the overall total {eventual_cu!r}"
            )

    # Positive control: a Query over the lone 1KB item bills the single block BatchGetItem
    # charged that item above.
    query_strong = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p", ConsistentRead=True,
        ExpressionAttributeValues={":p": {"S": small_pk}}, ReturnConsumedCapacity="TOTAL",
    )
    assert query_strong["ConsumedCapacity"]["CapacityUnits"] == 1.0, (
        f"a Query over the lone 1KB item billed {query_strong['ConsumedCapacity']['CapacityUnits']!r}, "
        f"expected 1.0"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
