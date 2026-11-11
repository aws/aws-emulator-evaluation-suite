"""delete-item-condition-expression-attribute-not-exists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-expression-attribute-not-exists"
GROUP = 'conditions'
SERVICES = ['dynamodb']
_CCFE = ('ConditionalCheckFailedException', 'The conditional request failed')


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
    """DeleteItem with ConditionExpression attribute_not_exists fails with
    ConditionalCheckFailedException while the named attribute is present on the
    item, and succeeds once the item carries no such attribute."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    present_key = {'pk': {'S': 'di-present'}}
    ddb.put_item(TableName=table, Item={**present_key, 'flag': {'S': 'active'}})

    # Break: 'flag' is present on the item, so attribute_not_exists(flag) must reject the delete.
    expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key=present_key, ConditionExpression='attribute_not_exists(flag)'
        ),
        *_CCFE,
    )

    # Effect absent: an independent read shows the rejected delete never landed.
    still_there = ddb.get_item(TableName=table, Key=present_key, ConsistentRead=True).get('Item')
    assert still_there is not None and still_there.get('flag') == {'S': 'active'}, (
        f"rejected delete must not remove the item, got {still_there!r}"
    )

    # Positive control: a sibling item with no 'flag' attribute satisfies the
    # identical condition, so the delete must succeed.
    absent_key = {'pk': {'S': 'di-absent'}}
    ddb.put_item(TableName=table, Item={**absent_key, 'other': {'S': 'x'}})
    ddb.delete_item(TableName=table, Key=absent_key, ConditionExpression='attribute_not_exists(flag)')

    gone = ddb.get_item(TableName=table, Key=absent_key, ConsistentRead=True).get('Item')
    assert gone is None, f"expected item absent after the satisfied-condition delete, got {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
