"""transact-write-items-condition-expression-defects-match-putitem-message."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-condition-expression-defects-match-putitem-message"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
_PREFIX = '1 validation error detected: '
_EXPECTED_PUT_MESSAGE = {
    'empty': _PREFIX + 'Invalid ConditionExpression: The expression can not be empty;',
    'malformed': _PREFIX + 'Invalid ConditionExpression: Syntax error; token: "<EOF>", near: "("',
    'over-4kb': _PREFIX + 'Invalid ConditionExpression: Expression size has exceeded the maximum allowed size;',
}


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'call unexpectedly SUCCEEDED where ValidationException was required: {result!r}')


@tags('axis:rejection', 'cap:c2', 'concern:negative-classes', 'dp:api', 'plane:data')
def run(ctx) -> None:
    """A malformed ConditionExpression on a TransactWriteItems Put is a top-level ValidationException
    whose message is the single-item PutItem message for the same defect, minus the single-item
    "1 validation error detected: " prefix; neither call writes its item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    # Positive control: a transaction whose ConditionExpression is well-formed commits.
    ddb.transact_write_items(TransactItems=[
        {'Put': {
            'TableName': table, 'Item': {'pk': {'S': 'control'}},
            'ConditionExpression': 'attribute_not_exists(pk)',
        }},
    ])
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'control'}}, ConsistentRead=True)
    assert 'Item' in got, 'positive control: a well-formed ConditionExpression must commit'

    over_4kb = 'attribute_exists(pk)' + ' ' * (4097 - len('attribute_exists(pk)'))
    assert len(over_4kb) == 4097

    defects = {
        'empty': '',
        'malformed': 'attribute_exists((',
        'over-4kb': over_4kb,
    }
    for label, expr in defects.items():
        put_key = f'single-{label}'
        put_code, put_message = _error(lambda expr=expr, k=put_key: ddb.put_item(
            TableName=table, Item={'pk': {'S': k}}, ConditionExpression=expr,
        ))
        assert put_code == ERR_VALIDATION, (
            f'single-item PutItem with a {label} ConditionExpression answered {put_code!r} '
            f'({put_message!r}), expected {ERR_VALIDATION}'
        )
        assert put_message.startswith(_PREFIX), (
            f'single-item PutItem message for a {label} ConditionExpression does not start with '
            f'{_PREFIX!r}: {put_message!r}'
        )
        assert put_message == _EXPECTED_PUT_MESSAGE[label], (
            f'single-item PutItem message for a {label} ConditionExpression must be the exact '
            f'AWS message, got {put_message!r}'
        )

        tx_key = f'transact-{label}'
        tx_code, tx_message = _error(lambda expr=expr, k=tx_key: ddb.transact_write_items(TransactItems=[
            {'Put': {'TableName': table, 'Item': {'pk': {'S': k}}, 'ConditionExpression': expr}},
        ]))
        assert tx_code == ERR_VALIDATION, (
            f'TransactWriteItems with a {label} ConditionExpression answered {tx_code!r} '
            f'({tx_message!r}), expected {ERR_VALIDATION}'
        )

        assert _PREFIX + tx_message == put_message, (
            f'for the {label} defect, TransactWriteItems message {tx_message!r} prefixed with '
            f'{_PREFIX!r} does not equal the PutItem message {put_message!r}'
        )

        for key in (put_key, tx_key):
            got = ddb.get_item(TableName=table, Key={'pk': {'S': key}}, ConsistentRead=True)
            assert 'Item' not in got, (
                f'a rejected {label} ConditionExpression write must not write {key!r}, '
                f'got {got.get("Item")!r}'
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
