"""put-item-condition-attribute-exists-and-contains-set-member."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-condition-attribute-exists-and-contains-set-member"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_CCF = ("ConditionalCheckFailedException", "The conditional request failed")


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


def _error(fn):
    """The (Code, Message) fn() raises. Raises when fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _unordered(item):
    """``item`` with each top-level set's members sorted; DynamoDB sets carry no member order."""
    if item is None:
        return None
    return {
        name: {kind: sorted(members)} if kind in ("SS", "NS", "BS") else {kind: members}
        for name, value in item.items() for kind, members in value.items()
    }


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem's `attribute_exists(pk) AND contains(members, :v)` replaces the item only when it
    already exists and its string set holds :v by value and type; it is refused with
    ConditionalCheckFailedException, item unchanged, when the item is absent or the set lacks :v.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-put-exists-contains-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    names = {"#m": "members"}
    cond = "attribute_exists(pk) AND contains(#m, :v)"

    def read(key):
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")

    # --- the item does not exist yet: attribute_exists(pk) is false, so the AND is refused
    # without raising a type error for evaluating contains() against a missing attribute.
    absent_key = {"pk": {"S": "absent"}}
    code, msg = _error(lambda: ddb.put_item(
        TableName=table, Item={**absent_key, "members": {"SS": ["ignored"]}, "written": {"BOOL": True}},
        ConditionExpression=cond, ExpressionAttributeNames=names,
        ExpressionAttributeValues={":v": {"S": "ignored"}},
    ))
    assert (code, msg) == _CCF, f"PutItem on an absent item under {cond!r} gave {code!r}: {msg!r}"
    assert read(absent_key) is None, "PutItem under a failing condition must not create the item"

    # --- the item exists but :v is not a member of the set: contains() is false.
    present_key = {"pk": {"S": "present"}}
    original = {**present_key, "members": {"SS": ["admin", "viewer"]}}
    ddb.put_item(TableName=table, Item=original)

    code, msg = _error(lambda: ddb.put_item(
        TableName=table, Item={**present_key, "members": {"SS": ["admin", "viewer"]}, "written": {"BOOL": True}},
        ConditionExpression=cond, ExpressionAttributeNames=names,
        ExpressionAttributeValues={":v": {"S": "owner"}},
    ))
    assert (code, msg) == _CCF, f"PutItem under a failing contains() condition gave {code!r}: {msg!r}"
    got = read(present_key)
    assert _unordered(got) == _unordered(original), f"PutItem under a failing contains() condition left {got!r}, expected {original!r}"

    # --- positive control: the item exists and :v is a member of the set by value and type,
    # so both arms hold and the write replaces the item.
    replacement = {**present_key, "members": {"SS": ["admin", "viewer"]}, "written": {"BOOL": True}}
    ddb.put_item(
        TableName=table, Item=replacement, ConditionExpression=cond, ExpressionAttributeNames=names,
        ExpressionAttributeValues={":v": {"S": "admin"}},
    )
    got = read(present_key)
    assert _unordered(got) == _unordered(replacement), f"PutItem under a holding condition left {got!r}, expected {replacement!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
