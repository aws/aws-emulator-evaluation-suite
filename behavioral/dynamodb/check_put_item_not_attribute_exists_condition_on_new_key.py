"""put-item-not-attribute-exists-condition-on-new-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-not-attribute-exists-condition-on-new-key"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCF = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """The (Code, Message) fn() raises. Raises when fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem's ConditionExpression "NOT attribute_exists(pk)" holds for a key never
    written and the write applies; once the key exists the same condition fails the
    next PutItem with ConditionalCheckFailedException and leaves the item unchanged.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbnotex-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "ddb-notexists-cond"}}

    def read():
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")

    assert read() is None, f"expected no prior item at the key, got {read()!r}"

    # NOT attribute_exists(pk) holds for a key that has never been written: the put applies.
    item_v1 = {**key, "marker": {"S": "first"}}
    ddb.put_item(TableName=table, Item=item_v1, ConditionExpression="NOT attribute_exists(pk)")
    got = read()
    assert got == item_v1, f"PutItem under a holding NOT attribute_exists(pk) left {got!r}, expected {item_v1!r}"

    # The same condition now fails: the key exists, so attribute_exists(pk) is true and
    # NOT negates it to false. The item is left unchanged.
    item_v2 = {**key, "marker": {"S": "second"}}
    code, msg = _error(lambda: ddb.put_item(
        TableName=table, Item=item_v2, ConditionExpression="NOT attribute_exists(pk)",
    ))
    assert (code, msg) == _CCF, f"PutItem under a failing NOT attribute_exists(pk) gave {code!r}: {msg!r}"
    after = read()
    assert after == item_v1, f"a rejected PutItem must leave {item_v1!r} unchanged, got {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
