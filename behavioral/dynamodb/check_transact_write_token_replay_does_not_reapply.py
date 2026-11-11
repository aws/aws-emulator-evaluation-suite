"""transact-write-token-replay-does-not-reapply."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "transact-write-token-replay-does-not-reapply"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_TRANSACTION_CANCELED = 'TransactionCanceledException'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems replay under the same ClientRequestToken returns the first outcome without re-executing:
    an ADD counter stays at 1 and a now-failing condition still succeeds; a fresh token re-applies the ADD and
    raises TransactionCanceledException with the exact message for the failing condition.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def counter():
        item = ddb.get_item(TableName=t, Key={'pk': {'S': 'ctr'}}, ConsistentRead=True).get('Item')
        return None if item is None else item['n']['N']

    increment = [{'Update': {
        'TableName': t,
        'Key': {'pk': {'S': 'ctr'}},
        'UpdateExpression': 'ADD n :one',
        'ExpressionAttributeValues': {':one': {'N': '1'}},
    }}]

    # --- a non-idempotent ADD proves the replay was NOT re-executed ---
    token = str(uuid.uuid4())
    ddb.transact_write_items(TransactItems=increment, ClientRequestToken=token)
    assert counter() == '1', f'first call must set the counter to 1, got {counter()}'

    for attempt in range(3):
        ddb.transact_write_items(TransactItems=increment, ClientRequestToken=token)
        assert counter() == '1', (
            f'replay {attempt + 1} with the SAME ClientRequestToken must be deduplicated, not '
            f're-executed; counter is {counter()} (expected 1)'
        )

    # --- a DIFFERENT token is a different transaction and does apply ---
    ddb.transact_write_items(TransactItems=increment, ClientRequestToken=str(uuid.uuid4()))
    assert counter() == '2', f'a fresh token must apply the ADD again, got {counter()}'

    # --- replaying a create-once transaction must return the cached SUCCESS, not the
    #     ConditionalCheckFailed that a re-execution would now produce ---
    create_once_token = str(uuid.uuid4())
    create_once = [{'Put': {
        'TableName': t,
        'Item': {'pk': {'S': 'once'}, 'payload': {'S': 'first'}},
        'ConditionExpression': 'attribute_not_exists(pk)',
    }}]
    ddb.transact_write_items(TransactItems=create_once, ClientRequestToken=create_once_token)
    created = ddb.get_item(TableName=t, Key={'pk': {'S': 'once'}}, ConsistentRead=True)['Item']
    assert created == {'pk': {'S': 'once'}, 'payload': {'S': 'first'}}, created

    # This is the assertion an SDK retry depends on: it must NOT raise.
    ddb.transact_write_items(TransactItems=create_once, ClientRequestToken=create_once_token)
    unchanged = ddb.get_item(TableName=t, Key={'pk': {'S': 'once'}}, ConsistentRead=True)['Item']
    assert unchanged == {'pk': {'S': 'once'}, 'payload': {'S': 'first'}}, (
        f'the deduplicated replay must leave the item untouched, got {unchanged}'
    )

    # And a fresh token for the same create-once transaction DOES hit the condition, proving the
    # condition itself is still being evaluated (the dedup is token-scoped, not condition-blind).
    try:
        ddb.transact_write_items(TransactItems=create_once, ClientRequestToken=str(uuid.uuid4()))
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
    assert code == ERR_TRANSACTION_CANCELED, (
        f'with a NEW token the attribute_not_exists condition must fail, proving dedup is '
        f'token-scoped; got {code}'
    )
    assert message == "Transaction cancelled, please refer cancellation reasons for specific reasons [ConditionalCheckFailed]", (
        f"expected AWS's exact TransactionCanceledException message, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
