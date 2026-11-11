"""update-item-set-empty-string-set-rejected-top-and-nested."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-empty-string-set-rejected-top-and-nested"
GROUP = 'representation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error_code(fn, what: str) -> tuple[str, str]:
    """The AWS error code and message `fn` raises; an unexpected success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it, got {result!r}')


@tags("axis:rejection", "cap:c2", "concern:representation", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem SET of a zero-member string set is refused ValidationException with AWS's
    exact message, at the top level and at a nested document path, leaving the item unchanged.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={'pk': {'S': 'x'}, 'wrapper': {'M': {}}})

    expected_message = (
        '1 validation error detected: One or more parameter values were invalid: '
        'An string set  may not be empty'
    )

    code, message = _error_code(
        lambda: ddb.update_item(
            TableName=t, Key={'pk': {'S': 'x'}},
            UpdateExpression='SET #tg = :e',
            ExpressionAttributeNames={'#tg': 'tags'},
            ExpressionAttributeValues={':e': {'SS': []}},
        ),
        'UpdateItem SET of a top-level zero-member string set',
    )
    assert code == ERR_VALIDATION, (
        f'a zero-member string set at the top level must be refused {ERR_VALIDATION}, got {code!r}'
    )
    assert message == expected_message, (
        f'expected the message {expected_message!r}, got {message!r}'
    )

    code, message = _error_code(
        lambda: ddb.update_item(
            TableName=t, Key={'pk': {'S': 'x'}},
            UpdateExpression='SET #w.#tg = :e',
            ExpressionAttributeNames={'#tg': 'tags', '#w': 'wrapper'},
            ExpressionAttributeValues={':e': {'SS': []}},
        ),
        'UpdateItem SET of a nested zero-member string set',
    )
    assert code == ERR_VALIDATION, (
        f'a zero-member string set at a nested path must be refused {ERR_VALIDATION}, got {code!r}'
    )
    assert message == expected_message, (
        f'expected the message {expected_message!r}, got {message!r}'
    )

    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'x'}}, ConsistentRead=True).get('Item', {})
    assert 'tags' not in got, (
        f'the refused top-level write must leave no "tags" attribute behind, got {got!r}'
    )
    assert got.get('wrapper') == {'M': {}}, (
        f'the refused nested write must leave the wrapper map unchanged, got {got.get("wrapper")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
