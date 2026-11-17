"""delete-item-condition-nested-map-member-existence-gates-the-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-nested-map-member-existence-gates-the-delete"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")


def _names(*keys):
    """The subset of the full name map these expression placeholders use."""
    full = {"#doc": "doc", "#present": "present", "#absent": "absent"}
    return {k: full[k] for k in keys}


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem's ConditionExpression attribute_exists/attribute_not_exists reach into a nested
    map member, not only a top-level attribute, to gate the delete.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # attribute_exists on a present nested map member.
    present_key = {"pk": {"S": "di-nested-exists-present"}}
    ddb.put_item(
        TableName=table,
        Item={**present_key, "doc": {"M": {"present": {"S": "here"}}}},
    )
    # Break: the nested member named does not exist, so attribute_exists must refuse the delete.
    expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key=present_key, ConditionExpression="attribute_exists(#doc.#absent)",
            ExpressionAttributeNames=_names("#doc", "#absent"),
        ),
        *_CCFE,
    )
    still_there = ddb.get_item(TableName=table, Key=present_key, ConsistentRead=True).get("Item")
    assert still_there is not None and still_there.get("doc") == {"M": {"present": {"S": "here"}}}, (
        f"rejected delete must not remove the item, got {still_there!r}"
    )
    # Positive control: the condition on the member that IS present holds, and the delete applies.
    ddb.delete_item(
        TableName=table, Key=present_key, ConditionExpression="attribute_exists(#doc.#present)",
        ExpressionAttributeNames=_names("#doc", "#present"),
    )
    gone = ddb.get_item(TableName=table, Key=present_key, ConsistentRead=True).get("Item")
    assert gone is None, (
        f"expected item absent after attribute_exists on a present nested member, got {gone!r}"
    )

    # attribute_not_exists on an absent nested map member.
    absent_key = {"pk": {"S": "di-nested-not-exists-absent"}}
    ddb.put_item(
        TableName=table,
        Item={**absent_key, "doc": {"M": {"present": {"S": "here"}}}},
    )
    # Break: the nested member named IS present, so attribute_not_exists must refuse the delete.
    expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key=absent_key, ConditionExpression="attribute_not_exists(#doc.#present)",
            ExpressionAttributeNames=_names("#doc", "#present"),
        ),
        *_CCFE,
    )
    still_there = ddb.get_item(TableName=table, Key=absent_key, ConsistentRead=True).get("Item")
    assert still_there is not None and still_there.get("doc") == {"M": {"present": {"S": "here"}}}, (
        f"rejected delete must not remove the item, got {still_there!r}"
    )
    # Positive control: the condition on the member that is absent holds, and the delete applies.
    ddb.delete_item(
        TableName=table, Key=absent_key, ConditionExpression="attribute_not_exists(#doc.#absent)",
        ExpressionAttributeNames=_names("#doc", "#absent"),
    )
    gone = ddb.get_item(TableName=table, Key=absent_key, ConsistentRead=True).get("Item")
    assert gone is None, (
        f"expected item absent after attribute_not_exists on an absent nested member, got {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
