"""transact-write-items-condition-check-list-index-and-nested-path-cancels."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-condition-check-list-index-and-nested-path-cancels"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_CCF = ("ConditionalCheckFailed", "The conditional request failed")
_CANCELED = "TransactionCanceledException"
_CANCELED_MSG = ("Transaction cancelled, please refer cancellation reasons for specific "
                 "reasons [ConditionalCheckFailed, None]")


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


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems ConditionCheck on an out-of-range list index, or on a map path whose
    parent key is absent, evaluates false and cancels with reasons [ConditionalCheckFailed, None].

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-cc-path-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    owner_key = {"pk": {"S": "owner"}}
    owner = {
        **owner_key,
        "tags": {"L": [{"S": "red"}, {"S": "blue"}]},
        "profile": {"M": {"name": {"S": "Jane Doe"}}},
    }
    ddb.put_item(TableName=table, Item=owner)

    # --- an out-of-range list index: tags has 2 elements, index 5 does not exist ---
    companion_a = {"pk": {"S": "companion-list-index"}}
    resp = _expect_canceled(lambda: ddb.transact_write_items(TransactItems=[
        {"ConditionCheck": {
            "TableName": table, "Key": owner_key,
            "ConditionExpression": "#t[5] = :v",
            "ExpressionAttributeNames": {"#t": "tags"},
            "ExpressionAttributeValues": {":v": {"S": "red"}},
        }},
        {"Put": {"TableName": table, "Item": companion_a}},
    ]))
    assert resp["Error"]["Code"] == _CANCELED, f"got {resp['Error']['Code']!r}"
    assert resp["Error"].get("Message") == _CANCELED_MSG, f"got message {resp['Error'].get('Message')!r}"
    reasons = [(r.get("Code"), r.get("Message")) for r in resp["CancellationReasons"]]
    assert reasons == [_CCF, ("None", None)], f"out-of-range list index: got reasons {reasons!r}"
    got = ddb.get_item(TableName=table, Key=companion_a, ConsistentRead=True).get("Item")
    assert got is None, f"the cancelled transaction must not have created {companion_a}, got {got!r}"

    # --- a missing nested map path: profile has no 'contact' key ---
    companion_b = {"pk": {"S": "companion-nested-path"}}
    resp = _expect_canceled(lambda: ddb.transact_write_items(TransactItems=[
        {"ConditionCheck": {
            "TableName": table, "Key": owner_key,
            "ConditionExpression": "attribute_exists(#p.#c)",
            "ExpressionAttributeNames": {"#p": "profile", "#c": "contact"},
        }},
        {"Put": {"TableName": table, "Item": companion_b}},
    ]))
    assert resp["Error"]["Code"] == _CANCELED, f"got {resp['Error']['Code']!r}"
    assert resp["Error"].get("Message") == _CANCELED_MSG, f"got message {resp['Error'].get('Message')!r}"
    reasons = [(r.get("Code"), r.get("Message")) for r in resp["CancellationReasons"]]
    assert reasons == [_CCF, ("None", None)], f"missing nested map path: got reasons {reasons!r}"
    got = ddb.get_item(TableName=table, Key=companion_b, ConsistentRead=True).get("Item")
    assert got is None, f"the cancelled transaction must not have created {companion_b}, got {got!r}"

    # --- control: the same shapes with a holding condition commit both members ---
    companion_c = {"pk": {"S": "companion-commits"}}
    ddb.transact_write_items(TransactItems=[
        {"ConditionCheck": {
            "TableName": table, "Key": owner_key,
            "ConditionExpression": "#t[0] = :v AND attribute_exists(#p.#n)",
            "ExpressionAttributeNames": {"#t": "tags", "#p": "profile", "#n": "name"},
            "ExpressionAttributeValues": {":v": {"S": "red"}},
        }},
        {"Put": {"TableName": table, "Item": companion_c}},
    ])
    got = ddb.get_item(TableName=table, Key=companion_c, ConsistentRead=True).get("Item")
    assert got == companion_c, f"a holding ConditionCheck must let the companion Put commit, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
