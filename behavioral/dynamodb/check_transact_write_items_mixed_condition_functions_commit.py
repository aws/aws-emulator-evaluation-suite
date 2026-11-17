"""transact-write-items-mixed-condition-functions-commit."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-mixed-condition-functions-commit"
GROUP = "transactions"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _wait_active(ddb, table, timeout_s=120.0) -> None:
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"table {table} not ACTIVE within {timeout_s:.0f}s; last status {status!r}")
        time.sleep(2)


def _expect_canceled(fn):
    """Call fn() and return its ClientError's response; an accepted call fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the transaction to be cancelled, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems with a ConditionCheck (contains), a Put (attribute_type), a Delete
    (begins_with), and an Update whose condition ANDs contains, attribute_type and size, commits
    every member once all four hold, and cancels when the Update's size clause alone fails.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-mixed-fn-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    cc_key = {"pk": {"S": "cc-target"}}
    cc_item = {**cc_key, "roles": {"SS": ["admin"]}}

    put_key = {"pk": {"S": "put-target"}}
    put_item = {**put_key, "kind": {"S": "legacy"}}
    put_overwrite = {**put_key, "kind": {"S": "legacy-v2"}}

    delete_key = {"pk": {"S": "delete-target"}}
    delete_item = {**delete_key, "code": {"S": "abc-123"}}

    update_key = {"pk": {"S": "update-target"}}
    update_item = {
        **update_key,
        "flags": {"SS": ["x", "y"]},
        "kind": {"S": "doc"},
        "notes": {"L": [{"S": "a"}, {"S": "b"}, {"S": "c"}]},
    }

    for item in (cc_item, put_item, delete_item, update_item):
        ddb.put_item(TableName=table, Item=item)

    def attempt(size_floor):
        return ddb.transact_write_items(TransactItems=[
            {"ConditionCheck": {
                "TableName": table, "Key": cc_key,
                "ConditionExpression": "contains(#r, :v)",
                "ExpressionAttributeNames": {"#r": "roles"},
                "ExpressionAttributeValues": {":v": {"S": "admin"}},
            }},
            {"Put": {
                "TableName": table, "Item": put_overwrite,
                "ConditionExpression": "attribute_type(#k, :t)",
                "ExpressionAttributeNames": {"#k": "kind"},
                "ExpressionAttributeValues": {":t": {"S": "S"}},
            }},
            {"Delete": {
                "TableName": table, "Key": delete_key,
                "ConditionExpression": "begins_with(#c, :p)",
                "ExpressionAttributeNames": {"#c": "code"},
                "ExpressionAttributeValues": {":p": {"S": "abc"}},
            }},
            {"Update": {
                "TableName": table, "Key": update_key,
                "UpdateExpression": "SET #s = :s",
                "ConditionExpression": "contains(#f, :v) AND attribute_type(#k, :t) AND size(#n) > :cnt",
                "ExpressionAttributeNames": {"#f": "flags", "#k": "kind", "#n": "notes", "#s": "status"},
                "ExpressionAttributeValues": {
                    ":v": {"S": "x"}, ":t": {"S": "S"}, ":cnt": {"N": str(size_floor)}, ":s": {"S": "touched"},
                },
            }},
        ])

    # --- control: the size clause alone fails (notes has 3 elements, floor is 5) and cancels ---
    resp = _expect_canceled(lambda: attempt(5))
    assert resp["Error"]["Code"] == "TransactionCanceledException", f"got {resp['Error']['Code']!r}"
    reasons = [r.get("Code") for r in resp["CancellationReasons"]]
    assert reasons == ["None", "None", "None", "ConditionalCheckFailed"], f"got reasons {reasons!r}"
    for item in (cc_item, put_item, delete_item, update_item):
        key = {"pk": item["pk"]}
        got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        assert got == item, f"the cancelled transaction must leave {key!r} unchanged, got {got!r}"

    # --- all four conditions hold (floor 2 < size 3): the transaction commits ---
    attempt(2)

    got_put = ddb.get_item(TableName=table, Key=put_key, ConsistentRead=True)["Item"]
    assert got_put == put_overwrite, f"Put under attribute_type must commit, got {got_put!r}"
    got_delete = ddb.get_item(TableName=table, Key=delete_key, ConsistentRead=True).get("Item")
    assert got_delete is None, f"Delete under begins_with must commit, got {got_delete!r}"
    got_update = ddb.get_item(TableName=table, Key=update_key, ConsistentRead=True)["Item"]
    assert got_update == {**update_item, "status": {"S": "touched"}}, (
        f"Update under contains AND attribute_type AND size must commit, got {got_update!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
