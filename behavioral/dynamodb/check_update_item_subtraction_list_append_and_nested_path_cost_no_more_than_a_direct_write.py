"""update-item-subtraction-list-append-and-nested-path-cost-no-more-than-a-direct-write."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-subtraction-list-append-and-nested-path-cost-no-more-than-a-direct-write"
GROUP = "capacity"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own not-found
    code means it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_table(ctx, ddb, name: str) -> str:
    table = ctx.unique_name(name)
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return table


def _search(fn, lo: int, hi: int) -> int:
    """Largest ``filler_len`` in ``[lo, hi]`` for which ``fn`` is True, given ``fn(hi + 1)`` is False."""
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if fn(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


def _one_wcu(ddb, table: str, item_extra: dict, **update_kwargs) -> bool:
    """Put ``{pk, f: filler}`` plus ``item_extra``, run the update, and report whether it cost
    1.0 CapacityUnits (as opposed to 2.0)."""
    update_kwargs.setdefault("ReturnConsumedCapacity", "TOTAL")
    resp = ddb.update_item(TableName=table, Key={"pk": {"S": "p"}}, **update_kwargs)
    cap = resp["ConsumedCapacity"]["CapacityUnits"]
    assert cap in (1.0, 2.0), f"update on {table!r} cost {cap!r} CapacityUnits"
    return cap == 1.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """UpdateItem's ConsumedCapacity for a subtraction (``x - y``), a ``list_append`` and a
    nested-path source (``SET c = m.z``) matches, byte for byte, a plain SET of the literal value
    each one computes: none of the three costs anything beyond the resulting item's own size.
    """
    ddb = ctx.client("dynamodb")

    # --- subtraction vs. a direct assignment of the same result ---
    table_direct = _create_table(ctx, ddb, "sim2real-behav-subdir-")
    table_sub = _create_table(ctx, ddb, "sim2real-behav-subop-")

    def reset_num(table: str, filler_len: int) -> None:
        ddb.put_item(
            TableName=table,
            Item={"pk": {"S": "p"}, "f": {"S": "x" * filler_len}, "num": {"N": "5"}},
        )

    def direct_1wcu(filler_len: int) -> bool:
        reset_num(table_direct, filler_len)
        return _one_wcu(
            ddb, table_direct, {}, UpdateExpression="SET num = :v",
            ExpressionAttributeValues={":v": {"N": "5"}},
        )

    def sub_1wcu(filler_len: int) -> bool:
        reset_num(table_sub, filler_len)
        return _one_wcu(
            ddb, table_sub, {}, UpdateExpression="SET num = :a - :b",
            ExpressionAttributeValues={":a": {"N": "10"}, ":b": {"N": "5"}},
        )

    max_direct = _search(direct_1wcu, 0, 2000)
    max_sub = _search(sub_1wcu, 0, 2000)
    assert max_sub == max_direct, (
        f"max filler at 1.0 CapacityUnits was {max_direct!r} for a direct SET and {max_sub!r} for "
        f"a subtraction producing the identical result; expected the same boundary"
    )
    got = ddb.get_item(TableName=table_sub, Key={"pk": {"S": "p"}}, ConsistentRead=True)["Item"]
    assert got["num"] == {"N": "5"}, f"subtraction result read back as {got['num']!r}, expected N '5'"

    # --- list_append vs. a direct assignment of the appended list ---
    table_lapd = _create_table(ctx, ddb, "sim2real-behav-lapdir-")
    table_lap = _create_table(ctx, ddb, "sim2real-behav-lapop-")

    def reset_list(table: str, filler_len: int) -> None:
        ddb.put_item(
            TableName=table,
            Item={"pk": {"S": "p"}, "f": {"S": "x" * filler_len}, "l": {"L": [{"S": "a"}]}},
        )

    def lapd_1wcu(filler_len: int) -> bool:
        reset_list(table_lapd, filler_len)
        return _one_wcu(
            ddb, table_lapd, {}, UpdateExpression="SET l = :v",
            ExpressionAttributeValues={":v": {"L": [{"S": "a"}, {"S": "b"}]}},
        )

    def lap_1wcu(filler_len: int) -> bool:
        reset_list(table_lap, filler_len)
        return _one_wcu(
            ddb, table_lap, {}, UpdateExpression="SET l = list_append(l, :v)",
            ExpressionAttributeValues={":v": {"L": [{"S": "b"}]}},
        )

    max_lapd = _search(lapd_1wcu, 0, 2000)
    max_lap = _search(lap_1wcu, 0, 2000)
    assert max_lap == max_lapd, (
        f"max filler at 1.0 CapacityUnits was {max_lapd!r} for a direct SET of the final list and "
        f"{max_lap!r} for list_append producing the identical list; expected the same boundary"
    )
    got = ddb.get_item(TableName=table_lap, Key={"pk": {"S": "p"}}, ConsistentRead=True)["Item"]
    assert got["l"] == {"L": [{"S": "a"}, {"S": "b"}]}, (
        f"list_append result read back as {got['l']!r}, expected ['a', 'b']"
    )

    # --- nested-path source vs. a direct assignment of the same value ---
    table_nestd = _create_table(ctx, ddb, "sim2real-behav-nestdir-")
    table_nest = _create_table(ctx, ddb, "sim2real-behav-nestop-")

    def reset_nest(table: str, filler_len: int) -> None:
        ddb.put_item(
            TableName=table,
            Item={
                "pk": {"S": "p"}, "f": {"S": "x" * filler_len},
                "m": {"M": {"z": {"S": "zzzzzzzzzz"}}}, "c": {"S": "orig"},
            },
        )

    def nestd_1wcu(filler_len: int) -> bool:
        reset_nest(table_nestd, filler_len)
        return _one_wcu(
            ddb, table_nestd, {}, UpdateExpression="SET c = :v",
            ExpressionAttributeValues={":v": {"S": "zzzzzzzzzz"}},
        )

    def nest_1wcu(filler_len: int) -> bool:
        reset_nest(table_nest, filler_len)
        return _one_wcu(ddb, table_nest, {}, UpdateExpression="SET c = m.z")

    max_nestd = _search(nestd_1wcu, 0, 2000)
    max_nest = _search(nest_1wcu, 0, 2000)
    assert max_nest == max_nestd, (
        f"max filler at 1.0 CapacityUnits was {max_nestd!r} for a direct SET of the literal value "
        f"and {max_nest!r} for copying it from a nested path; expected the same boundary"
    )
    got = ddb.get_item(TableName=table_nest, Key={"pk": {"S": "p"}}, ConsistentRead=True)["Item"]
    assert got["c"] == {"S": "zzzzzzzzzz"}, f"nested-path copy read back as {got['c']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
