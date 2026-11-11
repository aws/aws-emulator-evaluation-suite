"""conc-ddb-optimistic-transact-check-and-update-same-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-ddb-optimistic-transact-check-and-update-same-key-rejected"
GROUP = 'transactions'
SERVICES = ['dynamodb']

ERR_VALIDATION = 'ValidationException'
ERR_CANCELED = 'TransactionCanceledException'


def _make_table(ctx):
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name('sim2real-conc-ddb-opt-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _error(fn):
    """(code, response) for a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response
    raise AssertionError(f'real AWS refuses this transaction, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A transaction with a ConditionCheck and an Update on the same item fails with ValidationException
    "... multiple operations on one item" before any member applies, the folded Update-with-condition
    commits, and the same folded form with a stale version is cancelled and applies nothing."""
    ddb = ctx.client('dynamodb')
    table = _make_table(ctx)
    key = {'pk': {'S': 'order'}}
    ddb.put_item(TableName=table, Item={'pk': {'S': 'order'}, 'version': {'N': '1'}})

    def _get(pk):
        return ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True).get('Item')

    def _folded(expected, marker):
        return lambda: ddb.transact_write_items(TransactItems=[
            {'Update': {'TableName': table, 'Key': key,
                        'UpdateExpression': 'SET version = :next',
                        'ConditionExpression': 'version = :expected',
                        'ExpressionAttributeValues': {':expected': {'N': str(expected)},
                                                      ':next': {'N': str(expected + 1)}}}},
            {'Put': {'TableName': table, 'Item': {'pk': {'S': marker}}}},
        ])

    # --- the refused shape: a TRUE condition, split from its update onto the same key ----------
    code, resp = _error(lambda: ddb.transact_write_items(TransactItems=[
        {'ConditionCheck': {'TableName': table, 'Key': key,
                            'ConditionExpression': 'version = :expected',
                            'ExpressionAttributeValues': {':expected': {'N': '1'}}}},
        {'Update': {'TableName': table, 'Key': key,
                    'UpdateExpression': 'SET version = :next',
                    'ExpressionAttributeValues': {':next': {'N': '2'}}}},
        {'Put': {'TableName': table, 'Item': {'pk': {'S': 'marker-split'}}}},
    ]))
    assert code == ERR_VALIDATION, f'ConditionCheck+Update on one key: expected {ERR_VALIDATION}, got {code!r}'
    message = resp.get('Error', {}).get('Message')
    assert message == 'Transaction request cannot include multiple operations on one item', (
        f'ConditionCheck+Update on one key: got message {message!r}'
    )
    assert 'CancellationReasons' not in resp, (
        f'a request-level validation refusal must not report per-item reasons; got '
        f'{resp.get("CancellationReasons")!r}'
    )
    assert _get('order') == {'pk': {'S': 'order'}, 'version': {'N': '1'}}, (
        f'the rejected transaction moved the version: {_get("order")!r}'
    )
    assert _get('marker-split') is None, (
        f'the rejected transaction wrote its unrelated Put: {_get("marker-split")!r}'
    )

    # --- positive control: condition folded into the Update commits, both members apply ---------
    ddb_resp = _folded(1, 'marker-folded')()
    assert ddb_resp['ResponseMetadata']['HTTPStatusCode'] == 200, f'folded transaction: {ddb_resp!r}'
    assert _get('order')['version'] == {'N': '2'}, f'folded commit did not bump: {_get("order")!r}'
    assert _get('marker-folded') is not None, 'folded commit did not write its second member'

    # --- and the folded form with a STALE version is cancelled (a different refusal) ------------
    code, resp = _error(_folded(1, 'marker-stale'))
    assert code == ERR_CANCELED, f'stale folded transaction: expected {ERR_CANCELED}, got {code!r}'
    message = resp.get('Error', {}).get('Message')
    expected_msg = ('Transaction cancelled, please refer cancellation reasons for specific reasons '
                    '[ConditionalCheckFailed, None]')
    assert message == expected_msg, f'stale folded transaction: expected {expected_msg!r}, got {message!r}'
    reasons = resp.get('CancellationReasons', [])
    assert reasons == [{'Code': 'ConditionalCheckFailed', 'Message': 'The conditional request failed'},
                       {'Code': 'None'}], f'stale folded reasons {reasons!r}'
    assert _get('order')['version'] == {'N': '2'} and _get('marker-stale') is None, (
        f'stale cancelled transaction applied something: order={_get("order")!r} '
        f'marker={_get("marker-stale")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
