"""transact-write-items-near-4mb-aggregate-commits."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-near-4mb-aggregate-commits"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_FILLER_BYTES = 350 * 1024
_ITEM_COUNT = 10
_FOUR_MB = 4 * 1024 * 1024


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found means it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_table(ctx, ddb, prefix):
    name = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _item(pk):
    """An item of one short key and one ~350 KB string attribute."""
    return {"pk": {"S": pk}, "data": {"S": "x" * _FILLER_BYTES}}


def _item_size(item):
    """The DynamoDB size of an all-string item: attribute-name bytes plus value bytes."""
    return sum(len(name.encode()) + len(value["S"].encode()) for name, value in item.items())


def _get(ddb, table, key):
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactWriteItems whose aggregate payload sits just under the 4 MB transaction ceiling
    commits every item, and each is readable afterward with its exact content.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-tw4mb-")

    items = [_item(f"big-{i:02d}") for i in range(_ITEM_COUNT)]
    aggregate = sum(_item_size(it) for it in items)
    assert aggregate < _FOUR_MB, f"the near-limit items already total {aggregate!r} bytes, at or over 4 MB"
    assert aggregate > _FOUR_MB * 0.75, f"the near-limit items total only {aggregate!r} bytes, not near 4 MB"

    ddb.transact_write_items(TransactItems=[{"Put": {"TableName": table, "Item": it}} for it in items])

    for it in items:
        got = _get(ddb, table, {"pk": it["pk"]})
        assert got == it, (
            f"item {it['pk']!r} read back as {got!r}, expected the exact {_FILLER_BYTES!r}-byte item "
            f"committed in a {aggregate!r}-byte transaction"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
