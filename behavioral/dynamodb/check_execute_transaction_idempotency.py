"""execute-transaction-idempotency."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-transaction-idempotency"
GROUP = 'partiql'
SERVICES = ['dynamodb']
ERR_IDEMPOTENT_MISMATCH = 'IdempotentParameterMismatchException'


def _error_code(fn):
    """Return fn()'s error code and message; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected a rejection but the call SUCCEEDED and returned {result!r}')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ExecuteTransaction replay with the same ClientRequestToken and payload is deduplicated and
    billed as a read, not a write; the same token with a different payload fails with
    IdempotentParameterMismatchException and writes nothing under the mismatched key."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'execute-transaction-idempotency'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    token = uuid.uuid4().hex
    key = {'S': 'et-idem-1'}
    statements = [
        {
            'Statement': f'INSERT INTO "{t}" VALUE {{\'pk\': ?, \'v\': ?}}',
            'Parameters': [key, {'N': '1'}],
        }
    ]

    resp1 = ddb.execute_transaction(
        TransactStatements=statements, ClientRequestToken=token, ReturnConsumedCapacity='TOTAL')
    cc1 = resp1['ConsumedCapacity'][0]
    assert cc1.get('WriteCapacityUnits', 0) > 0, f'the first use of a fresh token must bill a write: {cc1!r}'
    item = ddb.get_item(TableName=t, Key={'pk': key}, ConsistentRead=True)['Item']
    assert item['v'] == {'N': '1'}, item

    resp2 = ddb.execute_transaction(
        TransactStatements=statements, ClientRequestToken=token, ReturnConsumedCapacity='TOTAL')
    cc2 = resp2['ConsumedCapacity'][0]
    assert cc2.get('WriteCapacityUnits', 0) == 0, f'a deduplicated replay must bill no write capacity: {cc2!r}'
    assert cc2.get('ReadCapacityUnits', 0) > 0, f'a deduplicated replay must be served by reading the ledger: {cc2!r}'
    item2 = ddb.get_item(TableName=t, Key={'pk': key}, ConsistentRead=True)['Item']
    assert item2['v'] == {'N': '1'}, 'deduplicated call must not alter state'

    mismatched_key = {'S': 'et-idem-DIFFERENT'}
    mismatched = [
        {
            'Statement': f'INSERT INTO "{t}" VALUE {{\'pk\': ?, \'v\': ?}}',
            'Parameters': [mismatched_key, {'N': '1'}],
        }
    ]
    code, message = _error_code(
        lambda: ddb.execute_transaction(TransactStatements=mismatched, ClientRequestToken=token)
    )
    assert code == ERR_IDEMPOTENT_MISMATCH, code
    assert message == "Specified idempotent token was used with different request parameters within the idempotency window", (
        f"expected the exact IdempotentParameterMismatchException message AWS returns, got {message!r}"
    )

    absent = ddb.get_item(TableName=t, Key={'pk': mismatched_key}, ConsistentRead=True)
    assert 'Item' not in absent, f'rejected mismatched payload must not be applied: {absent.get("Item")!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
