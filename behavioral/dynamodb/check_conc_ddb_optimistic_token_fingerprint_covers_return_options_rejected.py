"""conc-ddb-optimistic-token-fingerprint-covers-return-options-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-ddb-optimistic-token-fingerprint-covers-return-options-rejected"
GROUP = 'transactions'
SERVICES = ['dynamodb']

ERR_MISMATCH = 'IdempotentParameterMismatchException'


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


def _error_code(fn):
    """The error Code and Message for a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS refuses this replay, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems token replay that changes ReturnConsumedCapacity or
    ReturnItemCollectionMetrics is refused IdempotentParameterMismatchException; the exact replay
    succeeds billed as a read, and the ADD stays applied exactly once.
    """
    ddb = ctx.client('dynamodb')
    table = _make_table(ctx)
    ddb.put_item(TableName=table, Item={'pk': {'S': 'ctr'}, 'n': {'N': '0'}})
    token = str(uuid.uuid4())
    items = [{'Update': {'TableName': table, 'Key': {'pk': {'S': 'ctr'}},
                         'UpdateExpression': 'ADD n :one',
                         'ExpressionAttributeValues': {':one': {'N': '1'}}}}]

    def _n():
        return ddb.get_item(TableName=table, Key={'pk': {'S': 'ctr'}},
                            ConsistentRead=True)['Item']['n']

    def _tx(**extra):
        return lambda: ddb.transact_write_items(ClientRequestToken=token, TransactItems=items, **extra)

    first = _tx(ReturnConsumedCapacity='TOTAL')()
    first_cc = first['ConsumedCapacity'][0]
    assert first_cc.get('WriteCapacityUnits', 0) > 0, f'first use was not billed as a write: {first_cc!r}'
    assert _n() == {'N': '1'}, f'first use did not apply the ADD: {_n()!r}'

    # Positive control: the exact replay is accepted, billed as a read, and does not re-apply.
    replay = _tx(ReturnConsumedCapacity='TOTAL')()
    replay_cc = replay['ConsumedCapacity'][0]
    assert 'WriteCapacityUnits' not in replay_cc and replay_cc.get('ReadCapacityUnits', 0) > 0, (
        f'an exact replay must be billed as a read with no write units; got {replay_cc!r}'
    )
    assert _n() == {'N': '1'}, f'exact replay re-applied the ADD: {_n()!r}'

    # Same TransactItems, capacity reporting turned OFF: a different request.
    code, message = _error_code(_tx(ReturnConsumedCapacity='NONE'))
    assert code == ERR_MISMATCH, f'ReturnConsumedCapacity changed on replay: expected {ERR_MISMATCH}, got {code!r}'
    assert message == "Specified idempotent token was used with different request parameters within the idempotency window", (
        f"expected AWS's exact IdempotentParameterMismatchException message, got {message!r}"
    )
    assert _n() == {'N': '1'}, f'mismatched replay applied the ADD: {_n()!r}'

    # Same TransactItems and capacity option, collection metrics ADDED: also a different request.
    code, message = _error_code(_tx(ReturnConsumedCapacity='TOTAL', ReturnItemCollectionMetrics='SIZE'))
    assert code == ERR_MISMATCH, (
        f'ReturnItemCollectionMetrics added on replay: expected {ERR_MISMATCH}, got {code!r}'
    )
    assert message == "Specified idempotent token was used with different request parameters within the idempotency window", (
        f"expected AWS's exact IdempotentParameterMismatchException message, got {message!r}"
    )
    assert _n() == {'N': '1'}, f'mismatched replay applied the ADD: {_n()!r}'

    # And a fresh token with the same items is new work: it applies.
    ddb.transact_write_items(ClientRequestToken=str(uuid.uuid4()), TransactItems=items)
    assert _n() == {'N': '2'}, f'a fresh token must apply the ADD again: {_n()!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
