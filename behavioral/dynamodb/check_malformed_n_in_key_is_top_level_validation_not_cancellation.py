"""malformed-n-in-key-is-top-level-validation-not-cancellation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "malformed-n-in-key-is-top-level-validation-not-cancellation"
GROUP = 'negative-classes'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

# Each form is malformed in a different way: unparsable mantissa, an empty string, and a
# mantissa that parses but overflows the documented magnitude range.
_MALFORMED = ['abc', '', '1e99999']


def _message_for(mv: str) -> str:
    if mv == '1e99999':
        return 'Number overflow. Attempting to store a number with magnitude larger than supported range'
    return f'The parameter cannot be converted to a numeric value: {mv}'


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error']['Message'], exc.response
    raise AssertionError(f'expected the call to be rejected, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A malformed N in the key of GetItem, DeleteItem, Query, BatchGetItem, TransactGetItems
    and TransactWriteItems is a top-level ValidationException with no CancellationReasons, never
    a per-item cancellation, and nothing is written.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes.Number
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'N'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    ddb.put_item(TableName=table, Item={'pk': {'S': 'k1'}, 'sk': {'N': '5'}, 'v': {'S': 'orig'}})

    def unchanged():
        item = ddb.get_item(TableName=table, Key={'pk': {'S': 'k1'}, 'sk': {'N': '5'}}, ConsistentRead=True)['Item']
        assert item == {'pk': {'S': 'k1'}, 'sk': {'N': '5'}, 'v': {'S': 'orig'}}, (
            f'item must be untouched by every rejected call, got {item!r}'
        )

    # --- positive control: GetItem on the real key succeeds ---
    ok = ddb.get_item(TableName=table, Key={'pk': {'S': 'k1'}, 'sk': {'N': '5'}}, ConsistentRead=True)['Item']
    assert ok['v'] == {'S': 'orig'}, f'control GetItem must still succeed, got {ok!r}'

    for mv in _MALFORMED:
        expected = _message_for(mv)

        code, message, _resp = _error(lambda mv=mv: ddb.get_item(
            TableName=table, Key={'pk': {'S': 'k1'}, 'sk': {'N': mv}},
        ))
        assert code == ERR_VALIDATION, f'GetItem key N {mv!r} must be {ERR_VALIDATION}, got {code}'
        assert message == expected, f"expected AWS's exact GetItem message, got {message!r}"

        code, message, _resp = _error(lambda mv=mv: ddb.delete_item(
            TableName=table, Key={'pk': {'S': 'k1'}, 'sk': {'N': mv}},
        ))
        assert code == ERR_VALIDATION, f'DeleteItem key N {mv!r} must be {ERR_VALIDATION}, got {code}'
        assert message == f'1 validation error detected: {expected}', (
            f"expected AWS's exact DeleteItem message, got {message!r}"
        )
        unchanged()

        code, message, _resp = _error(lambda mv=mv: ddb.query(
            TableName=table,
            KeyConditionExpression='pk = :pk and sk = :sk',
            ExpressionAttributeValues={':pk': {'S': 'k1'}, ':sk': {'N': mv}},
        ))
        assert code == ERR_VALIDATION, f'Query key condition N {mv!r} must be {ERR_VALIDATION}, got {code}'
        assert message == expected, f"expected AWS's exact Query message, got {message!r}"

        code, message, _resp = _error(lambda mv=mv: ddb.batch_get_item(
            RequestItems={table: {'Keys': [{'pk': {'S': 'k1'}, 'sk': {'N': mv}}]}},
        ))
        assert code == ERR_VALIDATION, f'BatchGetItem key N {mv!r} must be {ERR_VALIDATION}, got {code}'
        assert message == expected, f"expected AWS's exact BatchGetItem message, got {message!r}"

        code, message, resp = _error(lambda mv=mv: ddb.transact_get_items(
            TransactItems=[{'Get': {'TableName': table, 'Key': {'pk': {'S': 'k1'}, 'sk': {'N': mv}}}}],
        ))
        assert code == ERR_VALIDATION, f'TransactGetItems key N {mv!r} must be {ERR_VALIDATION}, got {code}'
        assert message == expected, f"expected AWS's exact TransactGetItems message, got {message!r}"
        assert 'CancellationReasons' not in resp, (
            f'TransactGetItems with a malformed-N key must be a top-level ValidationException with '
            f'no CancellationReasons, got {resp!r}'
        )

        # The sibling Put in the same transaction must not land either -- this is a top-level
        # rejection of the whole request, not a per-item cancellation.
        sibling_key = {'pk': {'S': 'k2'}, 'sk': {'N': '1'}}
        code, message, resp = _error(lambda mv=mv: ddb.transact_write_items(
            TransactItems=[
                {'Put': {'TableName': table, 'Item': {**sibling_key, 'v': {'S': 'new'}}}},
                {'Update': {
                    'TableName': table,
                    'Key': {'pk': {'S': 'k1'}, 'sk': {'N': mv}},
                    'UpdateExpression': 'SET v = :v',
                    'ExpressionAttributeValues': {':v': {'S': 'updated'}},
                }},
            ],
        ))
        assert code == ERR_VALIDATION, f'TransactWriteItems key N {mv!r} must be {ERR_VALIDATION}, got {code}'
        assert message == expected, f"expected AWS's exact TransactWriteItems message, got {message!r}"
        assert 'CancellationReasons' not in resp, (
            f'TransactWriteItems with a malformed-N key must be a top-level ValidationException with '
            f'no CancellationReasons, got {resp!r}'
        )
        sibling = ddb.get_item(TableName=table, Key=sibling_key, ConsistentRead=True)
        assert 'Item' not in sibling, (
            f'the sibling Put must not land when the transaction is rejected top-level, found {sibling.get("Item")}'
        )

        unchanged()

    # Control still works after every rejection.
    ddb.delete_item(TableName=table, Key={'pk': {'S': 'k1'}, 'sk': {'N': '5'}})
    gone = ddb.get_item(TableName=table, Key={'pk': {'S': 'k1'}, 'sk': {'N': '5'}}, ConsistentRead=True)
    assert 'Item' not in gone, f'control DeleteItem must still succeed, found {gone.get("Item")}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
