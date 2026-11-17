"""transact-write-items-put-delete-update-function-conditions-cancel-in-order."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-put-delete-update-function-conditions-cancel-in-order"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_CCF = {"Code": "ConditionalCheckFailed", "Message": "The conditional request failed"}
_NONE = {"Code": "None"}
_CANCELED = "TransactionCanceledException"
_CANCELED_MSG = ("Transaction cancelled, please refer cancellation reasons for specific "
                 "reasons [ConditionalCheckFailed, ConditionalCheckFailed, ConditionalCheckFailed, None]")


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


def _reasons(resp):
    return [{k: v for k, v in r.items() if k in ("Code", "Message")} for r in resp["CancellationReasons"]]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems whose Put, Delete and Update each fail a different condition function
    (begins_with on binary, contains on a set, begins_with on a string) cancels with per-item
    reasons [ConditionalCheckFailed, ConditionalCheckFailed, ConditionalCheckFailed, None].

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-multi-fail-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    put_key = {"pk": {"S": "put-target"}}
    put_item = {**put_key, "blob": {"B": b"xyz-binary"}}
    put_overwrite = {**put_key, "blob": {"B": b"new-binary"}}

    delete_key = {"pk": {"S": "delete-target"}}
    delete_item = {**delete_key, "roles": {"SS": ["admin"]}}

    update_key = {"pk": {"S": "update-target"}}
    update_item = {**update_key, "code": {"S": "xyz-code"}}

    cc_key = {"pk": {"S": "cc-target"}}
    cc_item = {**cc_key, "status": {"S": "active"}}

    for item in (put_item, delete_item, update_item, cc_item):
        ddb.put_item(TableName=table, Item=item)

    def attempt(put_prefix, delete_value, update_prefix):
        return ddb.transact_write_items(TransactItems=[
            {"Put": {
                "TableName": table, "Item": put_overwrite,
                "ConditionExpression": "begins_with(#b, :p)",
                "ExpressionAttributeNames": {"#b": "blob"},
                "ExpressionAttributeValues": {":p": {"B": put_prefix}},
            }},
            {"Delete": {
                "TableName": table, "Key": delete_key,
                "ConditionExpression": "contains(#r, :v)",
                "ExpressionAttributeNames": {"#r": "roles"},
                "ExpressionAttributeValues": {":v": {"S": delete_value}},
            }},
            {"Update": {
                "TableName": table, "Key": update_key,
                "UpdateExpression": "SET #s = :s",
                "ConditionExpression": "begins_with(#c, :p)",
                "ExpressionAttributeNames": {"#c": "code", "#s": "status"},
                "ExpressionAttributeValues": {":p": {"S": update_prefix}, ":s": {"S": "touched"}},
            }},
            {"ConditionCheck": {
                "TableName": table, "Key": cc_key,
                "ConditionExpression": "attribute_exists(#s)",
                "ExpressionAttributeNames": {"#s": "status"},
            }},
        ])

    resp = _expect_canceled(lambda: attempt(b"abc", "owner", "abc"))
    assert resp["Error"]["Code"] == _CANCELED, f"got {resp['Error']['Code']!r}"
    assert resp["Error"].get("Message") == _CANCELED_MSG, f"got message {resp['Error'].get('Message')!r}"
    reasons = _reasons(resp)
    assert reasons == [_CCF, _CCF, _CCF, _NONE], f"got reasons {reasons!r}"

    for item in (put_item, delete_item, update_item, cc_item):
        key = {"pk": item["pk"]}
        got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        assert got == item, f"the cancelled transaction must leave {key!r} unchanged, got {got!r}"

    # --- control: the same shape with every condition holding commits all three writes ---
    attempt(b"xyz", "admin", "xyz")
    got_put = ddb.get_item(TableName=table, Key=put_key, ConsistentRead=True)["Item"]
    assert got_put == put_overwrite, f"Put must commit, got {got_put!r}"
    got_delete = ddb.get_item(TableName=table, Key=delete_key, ConsistentRead=True).get("Item")
    assert got_delete is None, f"Delete must commit, got {got_delete!r}"
    got_update = ddb.get_item(TableName=table, Key=update_key, ConsistentRead=True)["Item"]
    assert got_update == {**update_item, "status": {"S": "touched"}}, f"Update must commit, got {got_update!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
