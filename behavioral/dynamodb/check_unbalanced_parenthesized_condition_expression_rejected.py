"""unbalanced-parenthesized-condition-expression-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'unbalanced-parenthesized-condition-expression-rejected'
GROUP = 'conditions'
SERVICES = ['dynamodb']

_SYNTAX_ERROR = (
    'ValidationException',
    '1 validation error detected: Invalid ConditionExpression: Syntax error; '
    'token: "<EOF>", near: ":bb"',
)
_UNBALANCED = '(a < :ab AND b > :bb'
_BALANCED = '(a < :ab AND (b > :bb))'
_VALUES = {':ab': {'N': '10'}, ':bb': {'N': '5'}}


def _expect_error(fn, code: str, message: str) -> None:
    """Raises on an unexpected success; otherwise asserts the exact (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        assert err.get('Code') == code, f"expected code {code!r}, got {err.get('Code')!r}"
        assert err.get('Message') == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused with {code}, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ConditionExpression with an unbalanced open paren is a ValidationException on
    PutItem, DeleteItem and UpdateItem, and the targeted item is left unchanged.
    """
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

    def read(pk):
        return ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True).get('Item')

    base = {'a': {'N': '5'}, 'b': {'N': '10'}}

    # PutItem: the balanced form is a positive control that succeeds; the unbalanced
    # form never reaches evaluation, so it is rejected whether or not it would hold.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'put-target'}, **base})
    ddb.put_item(
        TableName=table, Item={'pk': {'S': 'put-target'}, **base, 'written': {'BOOL': True}},
        ConditionExpression=_BALANCED, ExpressionAttributeValues=_VALUES,
    )
    assert read('put-target') == {'pk': {'S': 'put-target'}, **base, 'written': {'BOOL': True}}, (
        "the balanced control PutItem did not apply"
    )
    _expect_error(
        lambda: ddb.put_item(
            TableName=table, Item={'pk': {'S': 'put-target'}, **base, 'written': {'BOOL': False}},
            ConditionExpression=_UNBALANCED, ExpressionAttributeValues=_VALUES,
        ),
        *_SYNTAX_ERROR,
    )
    assert read('put-target') == {'pk': {'S': 'put-target'}, **base, 'written': {'BOOL': True}}, (
        "put-target changed despite the rejected unbalanced PutItem"
    )

    # DeleteItem: same control/rejection pair.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'delete-target'}, **base})
    _expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key={'pk': {'S': 'delete-target'}},
            ConditionExpression=_UNBALANCED, ExpressionAttributeValues=_VALUES,
        ),
        *_SYNTAX_ERROR,
    )
    assert read('delete-target') == {'pk': {'S': 'delete-target'}, **base}, (
        "delete-target was removed despite the rejected unbalanced DeleteItem"
    )
    ddb.delete_item(
        TableName=table, Key={'pk': {'S': 'delete-target'}},
        ConditionExpression=_BALANCED, ExpressionAttributeValues=_VALUES,
    )
    assert read('delete-target') is None, "the balanced control DeleteItem did not apply"

    # UpdateItem: same control/rejection pair.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'update-target'}, **base})
    _expect_error(
        lambda: ddb.update_item(
            TableName=table, Key={'pk': {'S': 'update-target'}}, UpdateExpression='SET c = :v',
            ConditionExpression=_UNBALANCED, ExpressionAttributeValues={**_VALUES, ':v': {'S': 'x'}},
        ),
        *_SYNTAX_ERROR,
    )
    assert read('update-target') == {'pk': {'S': 'update-target'}, **base}, (
        "update-target changed despite the rejected unbalanced UpdateItem"
    )
    ddb.update_item(
        TableName=table, Key={'pk': {'S': 'update-target'}}, UpdateExpression='SET c = :v',
        ConditionExpression=_BALANCED, ExpressionAttributeValues={**_VALUES, ':v': {'S': 'x'}},
    )
    assert read('update-target')['c'] == {'S': 'x'}, "the balanced control UpdateItem did not apply"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
