"""update-item-remove-list-index-cost-is-independent-of-index-digit-count."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-remove-list-index-cost-is-independent-of-index-digit-count"
GROUP = "capacity"
SERVICES = ["dynamodb"]

_LIST_LEN = 100


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


def _remove_costs_1wcu(ddb, table: str, index: int, filler_len: int) -> bool:
    """Reset a fixed 100-element list plus an ``f`` filler, REMOVE l[index], and report whether
    that write cost 1.0 CapacityUnits (as opposed to 2.0)."""
    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "p"}, "f": {"S": "x" * filler_len}, "l": {"L": [{"S": "a"}] * _LIST_LEN}},
    )
    resp = ddb.update_item(
        TableName=table, Key={"pk": {"S": "p"}}, UpdateExpression=f"REMOVE l[{index}]",
        ReturnConsumedCapacity="TOTAL",
    )
    cap = resp["ConsumedCapacity"]["CapacityUnits"]
    assert cap in (1.0, 2.0), f"REMOVE l[{index!r}] at filler {filler_len!r} cost {cap!r} CapacityUnits"
    return cap == 1.0


def _search(fn, lo: int, hi: int) -> int:
    """Largest ``filler_len`` in ``[lo, hi]`` for which ``fn`` is True, given ``fn(hi + 1)`` is False."""
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if fn(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """UpdateItem's ConsumedCapacity for ``REMOVE l[i]`` is the same whether the index is a single
    digit or two digits: both removals leave an identical resulting list, and both cost the same
    CapacityUnits right up to the shared byte-exact boundary.
    """
    ddb = ctx.client("dynamodb")
    table_one_digit = _create_table(ctx, ddb, "sim2real-behav-rmix-one-")
    table_two_digit = _create_table(ctx, ddb, "sim2real-behav-rmix-two-")

    # Index 0 is one digit; index 99 is two digits. Each table keeps its own partition history so
    # neither search's write volume can bias the other's measured boundary.
    max_one_digit = _search(lambda f: _remove_costs_1wcu(ddb, table_one_digit, 0, f), 0, 2000)
    max_two_digit = _search(lambda f: _remove_costs_1wcu(ddb, table_two_digit, 99, f), 0, 2000)

    assert max_two_digit == max_one_digit, (
        f"max filler at 1.0 CapacityUnits was {max_one_digit!r} for a one-digit index and "
        f"{max_two_digit!r} for a two-digit index; expected the same boundary for both"
    )

    # One byte past the shared boundary, both must now cost 2.0.
    assert _remove_costs_1wcu(ddb, table_one_digit, 0, max_one_digit + 1) is False, (
        "the one-digit index did not cost 2.0 CapacityUnits one byte past the measured boundary"
    )
    assert _remove_costs_1wcu(ddb, table_two_digit, 99, max_two_digit + 1) is False, (
        "the two-digit index did not cost 2.0 CapacityUnits one byte past the measured boundary"
    )

    # Positive control: both removals actually ran, each leaving 99 identical elements behind.
    for table in (table_one_digit, table_two_digit):
        got = ddb.get_item(TableName=table, Key={"pk": {"S": "p"}}, ConsistentRead=True)["Item"]
        elements = got["l"]["L"]
        assert elements == [{"S": "a"}] * (_LIST_LEN - 1), (
            f"table {table!r} list after REMOVE has {elements!r}, expected 99 copies of {{'S': 'a'}}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
