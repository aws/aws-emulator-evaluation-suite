"""putitem-condition-contains-partial-map-in-list-is-false."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "putitem-condition-contains-partial-map-in-list-is-false"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_ROLE = {"M": {"name": {"S": "Jane Doe"}, "title": {"S": "admin"}}}
_SEED = {
    "id": {"S": "roster"},
    "roles": {"L": [_ROLE, {"S": "sentinel"}]},
    "version": {"N": "1"},
}


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """contains(list, map) requires an exact element match: a map operand holding only a subset
    of a list element's keys evaluates false and fails the PutItem condition; the same operand
    completed to an exact match evaluates true and the write goes through."""
    ddb = ctx.client("dynamodb")
    name = _table(ctx, ddb)
    key = {"id": {"S": "roster"}}

    ddb.put_item(TableName=name, Item=_SEED)
    seeded = ddb.get_item(TableName=name, Key=key, ConsistentRead=True)["Item"]
    assert seeded == _SEED, f"seed GetItem returned {seeded!r}, expected {_SEED!r}"

    partial = {"M": {"name": {"S": "Jane Doe"}}}
    replacement = {"id": {"S": "roster"}, "version": {"N": "2"}, "updated": {"BOOL": True}}
    code, msg = _error(lambda: ddb.put_item(
        TableName=name, Item=replacement, ConditionExpression="contains(#r, :v)",
        ExpressionAttributeNames={"#r": "roles"}, ExpressionAttributeValues={":v": partial}))
    assert code == "ConditionalCheckFailedException", (
        f"PutItem under contains(roles, {partial!r}) raised {code!r}, expected "
        "ConditionalCheckFailedException")
    expected_msg = "The conditional request failed"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    unchanged = ddb.get_item(TableName=name, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == _SEED, (
        f"PutItem under a failing partial-map contains() left {unchanged!r}, expected the "
        f"unchanged seed {_SEED!r}")

    # Positive control: the same operand completed into an exact match of the list element.
    full = _ROLE
    ddb.put_item(TableName=name, Item=replacement, ConditionExpression="contains(#r, :v)",
                ExpressionAttributeNames={"#r": "roles"}, ExpressionAttributeValues={":v": full})
    written = ddb.get_item(TableName=name, Key=key, ConsistentRead=True)["Item"]
    assert written == replacement, (
        f"PutItem under a holding exact-map contains() left {written!r}, expected {replacement!r}")


def _error(fn) -> tuple[str, str]:
    """The AWS error (code, message) ``fn`` raises; a call that succeeds raises instead."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _drop(ddb, name: str) -> None:
    """Delete a table; one already gone counts as deleted, any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _table(ctx, ddb) -> str:
    """Create an on-demand table with a string ``id`` hash key and wait for ACTIVE."""
    name = ctx.unique_name("sim2real-ddb-contains-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _drop(ddb, name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
