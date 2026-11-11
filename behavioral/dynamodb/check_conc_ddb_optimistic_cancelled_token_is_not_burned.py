"""conc-ddb-optimistic-cancelled-token-is-not-burned."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-ddb-optimistic-cancelled-token-is-not-burned"
GROUP = 'transactions'
SERVICES = ['dynamodb']

ERR_CANCELED = 'TransactionCanceledException'
ERR_MISMATCH = 'IdempotentParameterMismatchException'
MSG_CANCELED = ('Transaction cancelled, please refer cancellation reasons for specific reasons '
                '[ConditionalCheckFailed, None]')
MSG_MISMATCH = ('Specified idempotent token was used with different request parameters within the '
                'idempotency window')


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
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A ClientRequestToken whose first TransactWriteItems was cancelled is not consumed: the identical
    request later commits under it, a further replay applies nothing again, and reuse with a refreshed
    version fails with IdempotentParameterMismatchException; each refusal carries AWS's exact message."""
    ddb = ctx.client('dynamodb')
    table = _make_table(ctx)
    ddb.put_item(TableName=table, Item={'pk': {'S': 'acct'}, 'version': {'N': '1'},
                                        'n': {'N': '0'}})
    token = str(uuid.uuid4())

    def _tx(expected):
        return lambda: ddb.transact_write_items(ClientRequestToken=token, TransactItems=[
            {'Update': {'TableName': table, 'Key': {'pk': {'S': 'acct'}},
                        'UpdateExpression': 'SET version = :next ADD n :one',
                        'ConditionExpression': 'version = :expected',
                        'ExpressionAttributeValues': {':expected': {'N': str(expected)},
                                                      ':next': {'N': str(expected + 1)},
                                                      ':one': {'N': '1'}}}},
            {'Put': {'TableName': table, 'Item': {'pk': {'S': 'receipt'}}}},
        ])

    def _state():
        acct = ddb.get_item(TableName=table, Key={'pk': {'S': 'acct'}}, ConsistentRead=True)['Item']
        receipt = ddb.get_item(TableName=table, Key={'pk': {'S': 'receipt'}},
                               ConsistentRead=True).get('Item')
        return int(acct['version']['N']), int(acct['n']['N']), receipt is not None

    # 1. first use expects version 2 while the item is at 1: cancelled, nothing applies.
    code, resp = _error(_tx(2))
    assert code == ERR_CANCELED, f'first use: expected {ERR_CANCELED}, got {code!r}'
    message = resp.get('Error', {}).get('Message')
    assert message == MSG_CANCELED, f'first use: expected {MSG_CANCELED!r}, got {message!r}'
    reasons = resp.get('CancellationReasons', [])
    assert reasons == [{'Code': 'ConditionalCheckFailed', 'Message': 'The conditional request failed'},
                       {'Code': 'None'}], f'first use reasons {reasons!r}'
    assert _state() == (1, 0, False), f'cancelled first use applied something: {_state()!r}'

    # 2. another writer moves the item to the version the request expects.
    ddb.update_item(TableName=table, Key={'pk': {'S': 'acct'}}, UpdateExpression='SET version = :v',
                    ExpressionAttributeValues={':v': {'N': '2'}})

    # 3. same token, same bytes: the cancelled use did not burn it, so this COMMITS.
    _tx(2)()
    assert _state() == (3, 1, True), (
        f'same-token retry after the fix must apply once (version 3, n 1, receipt); got {_state()!r} '
        f'-- a token remembered from a cancelled call swallows the retry'
    )

    # 4. replay of the committed request: success, NOT applied again.
    _tx(2)()
    assert _state() == (3, 1, True), f'replay of a committed token re-applied: {_state()!r}'

    # 5. same token, refreshed version (different parameters): refused, nothing applies.
    code, _resp = _error(_tx(3))
    assert code == ERR_MISMATCH, f'token reuse with a refreshed version: expected {ERR_MISMATCH}, got {code!r}'
    message = _resp.get('Error', {}).get('Message')
    assert message == MSG_MISMATCH, f'token reuse with a refreshed version: expected {MSG_MISMATCH!r}, got {message!r}'
    assert _state() == (3, 1, True), f'mismatched token reuse applied something: {_state()!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
