"""update-item-reused-document-value-and-add-to-set-bill-exactly-their-real-growth."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-reused-document-value-and-add-to-set-bill-exactly-their-real-growth"
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


def _one_wcu(ddb, table: str, **update_kwargs) -> bool:
    update_kwargs.setdefault("ReturnConsumedCapacity", "TOTAL")
    resp = ddb.update_item(TableName=table, Key={"pk": {"S": "p"}}, **update_kwargs)
    cap = resp["ConsumedCapacity"]["CapacityUnits"]
    assert cap in (1.0, 2.0), f"update on {table!r} cost {cap!r} CapacityUnits"
    return cap == 1.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A document value bound once and SET into two attributes is billed for its full stored size
    at each place it lands, never deduplicated; ADD to a set bills by the resulting membership, so
    adding an already-present member costs the same as adding that member to a set without it.
    """
    ddb = ctx.client("dynamodb")

    # --- a document :v used once vs. the same :v used at two targets ---
    table_once = _create_table(ctx, ddb, "sim2real-behav-docreuse1-")
    table_twice = _create_table(ctx, ddb, "sim2real-behav-docreuse2-")
    _DOC = {"M": {"x": {"S": "y"}}}

    def reset_pair(table: str, filler_len: int) -> None:
        ddb.put_item(
            TableName=table,
            Item={
                "pk": {"S": "p"}, "f": {"S": "x" * filler_len},
                "a": {"S": "orig"}, "b": {"S": "orig"},
            },
        )

    def once_1wcu(filler_len: int) -> bool:
        reset_pair(table_once, filler_len)
        return _one_wcu(
            ddb, table_once, UpdateExpression="SET a = :v", ExpressionAttributeValues={":v": _DOC},
        )

    def twice_1wcu(filler_len: int) -> bool:
        reset_pair(table_twice, filler_len)
        return _one_wcu(
            ddb, table_twice, UpdateExpression="SET a = :v, b = :v",
            ExpressionAttributeValues={":v": _DOC},
        )

    max_once = _search(once_1wcu, 0, 2000)
    max_twice = _search(twice_1wcu, 0, 2000)
    assert max_twice < max_once, (
        f"max filler at 1.0 CapacityUnits was {max_once!r} writing the document once and "
        f"{max_twice!r} writing it at two targets; expected the second use to cost strictly more"
    )

    # The only real difference between the two updates is that "b" changes from the 5-byte
    # string "orig" to the 7-byte document, a net growth of 2 bytes -- exactly the boundary shift.
    assert max_once - max_twice == 2, (
        f"the boundary shifted by {max_once - max_twice!r} bytes between using the document once "
        f"and twice, expected exactly 2 (the real growth of the second attribute alone)"
    )

    got = ddb.get_item(TableName=table_twice, Key={"pk": {"S": "p"}}, ConsistentRead=True)["Item"]
    assert got["a"] == _DOC and got["b"] == _DOC, (
        f"both targets must hold the reused document; got a={got['a']!r} b={got['b']!r}"
    )

    # --- ADD to a set: a brand-new member vs. a member already present (a no-op) ---
    table_new = _create_table(ctx, ddb, "sim2real-behav-addnew-")
    table_noop = _create_table(ctx, ddb, "sim2real-behav-addnoop-")
    _NEW_MEMBER = "cccccccccc"

    def reset_without_member(table: str, filler_len: int) -> None:
        ddb.put_item(
            TableName=table,
            Item={"pk": {"S": "p"}, "f": {"S": "x" * filler_len}, "s": {"SS": ["a", "b"]}},
        )

    def reset_with_member(table: str, filler_len: int) -> None:
        ddb.put_item(
            TableName=table,
            Item={
                "pk": {"S": "p"}, "f": {"S": "x" * filler_len},
                "s": {"SS": ["a", "b", _NEW_MEMBER]},
            },
        )

    def add_new_1wcu(filler_len: int) -> bool:
        reset_without_member(table_new, filler_len)
        return _one_wcu(
            ddb, table_new, UpdateExpression="ADD s :v",
            ExpressionAttributeValues={":v": {"SS": [_NEW_MEMBER]}},
        )

    def add_noop_1wcu(filler_len: int) -> bool:
        reset_with_member(table_noop, filler_len)
        return _one_wcu(
            ddb, table_noop, UpdateExpression="ADD s :v",
            ExpressionAttributeValues={":v": {"SS": [_NEW_MEMBER]}},
        )

    max_new = _search(add_new_1wcu, 0, 2000)
    max_noop = _search(add_noop_1wcu, 0, 2000)
    assert max_new == max_noop, (
        f"max filler at 1.0 CapacityUnits was {max_new!r} adding a brand-new member and "
        f"{max_noop!r} adding a member already present; expected the same boundary, since the "
        f"resulting membership is identical either way"
    )

    got_new = ddb.get_item(TableName=table_new, Key={"pk": {"S": "p"}}, ConsistentRead=True)["Item"]
    assert got_new["s"]["SS"] and set(got_new["s"]["SS"]) == {"a", "b", _NEW_MEMBER}, (
        f"ADD of a new member left the set as {got_new['s']!r}"
    )
    got_noop = ddb.get_item(TableName=table_noop, Key={"pk": {"S": "p"}}, ConsistentRead=True)["Item"]
    assert set(got_noop["s"]["SS"]) == {"a", "b", _NEW_MEMBER}, (
        f"ADD of an already-present member left the set as {got_noop['s']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
