"""transact-write-items-update-attribute-not-exists-upserts."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-update-attribute-not-exists-upserts"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_CANCELED = "TransactionCanceledException"
_CCF_MESSAGE = "The conditional request failed"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {status!r}")


def _get(ddb, table, key):
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A transact Update conditioned on attribute_not_exists upserts an absent item with its SET
    attributes and key; once the item exists, replaying the same transaction cancels instead of
    overwriting it.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-upsert-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    upsert_key = {"pk": {"S": "new-item"}}
    sibling_key = {"pk": {"S": "sibling-ok"}}

    def upsert(value):
        return ddb.transact_write_items(TransactItems=[
            {"Update": {
                "TableName": table, "Key": upsert_key,
                "UpdateExpression": "SET v = :v, note = :n",
                "ConditionExpression": "attribute_not_exists(pk)",
                "ExpressionAttributeValues": {":v": {"S": value}, ":n": {"S": "via-upsert"}},
            }},
            {"Put": {"TableName": table, "Item": {**sibling_key, "v": {"S": "sibling"}}}},
        ])

    upsert("created")
    created = _get(ddb, table, upsert_key)
    assert created == {**upsert_key, "v": {"S": "created"}, "note": {"S": "via-upsert"}}, (
        f"expected the upsert to create the item with its SET attributes and key, got {created!r}"
    )
    sibling_got = _get(ddb, table, sibling_key)
    assert sibling_got == {**sibling_key, "v": {"S": "sibling"}}, (
        f"expected the sibling Put in the same transaction to land, got {sibling_got!r}"
    )

    # Replaying the same upsert now finds pk present: attribute_not_exists is false and the
    # transaction cancels instead of overwriting the item.
    try:
        result = upsert("overwritten")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == _CANCELED, f"expected {_CANCELED}, got {err!r}"
        assert err.get("Message") == (
            "Transaction cancelled, please refer cancellation reasons for specific reasons "
            "[ConditionalCheckFailed, None]"
        ), f"unexpected message {err.get('Message')!r}"
        reasons = [(r.get("Code"), r.get("Message")) for r in exc.response.get("CancellationReasons", [])]
        assert reasons == [("ConditionalCheckFailed", _CCF_MESSAGE), ("None", None)], (
            f"unexpected cancellation reasons {reasons!r}"
        )
    else:
        raise AssertionError(f"replaying the upsert against an existing item was ACCEPTED: {result!r}")

    unchanged = _get(ddb, table, upsert_key)
    assert unchanged == created, (
        f"the cancelled replay must not overwrite the upserted item; got {unchanged!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
