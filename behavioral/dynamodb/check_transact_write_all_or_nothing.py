"""transact-write-all-or-nothing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-all-or-nothing"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_TRANSACTION_CANCELED = 'TransactionCanceledException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactWriteItems is atomic: if one condition fails, nothing is written."""
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
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'tw-existing'}, 'v': {'N': '1'}})

    # Positive control: an unconditioned multi-item transaction with no conflicting
    # condition commits every member. Without this, a target that rejects every
    # multi-item TransactWriteItems call would pass the negative below for the wrong
    # reason.
    ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': table, 'Item': {'pk': {'S': 'tw-control-a'}, 'v': {'N': '1'}}}},
        {'Put': {'TableName': table, 'Item': {'pk': {'S': 'tw-control-b'}, 'v': {'N': '1'}}}},
    ])
    control_a = ddb.get_item(TableName=table, Key={'pk': {'S': 'tw-control-a'}}, ConsistentRead=True).get('Item')
    control_b = ddb.get_item(TableName=table, Key={'pk': {'S': 'tw-control-b'}}, ConsistentRead=True).get('Item')
    assert control_a is not None and control_b is not None, (
        f'positive control: expected both members committed, got a={control_a} b={control_b}'
    )

    try:
        ddb.transact_write_items(TransactItems=[{'Put': {'TableName': table, 'Item': {'pk': {'S': 'tw-new'}, 'v': {'N': '2'}}}}, {'Put': {'TableName': table, 'Item': {'pk': {'S': 'tw-existing'}, 'v': {'N': '99'}}, 'ConditionExpression': 'attribute_not_exists(pk)'}}])
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
    assert code == ERR_TRANSACTION_CANCELED, (
        f'expected {ERR_TRANSACTION_CANCELED} when one member\'s condition fails, got {code}'
    )
    assert message == "Transaction cancelled, please refer cancellation reasons for specific reasons [None, ConditionalCheckFailed]", (
        f"expected AWS's exact TransactionCanceledException message, got {message!r}"
    )
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'tw-new'}}, ConsistentRead=True).get('Item')
    assert got is None, f'transaction was canceled, so tw-new must not have been written, got {got}'
    got_existing = ddb.get_item(TableName=table, Key={'pk': {'S': 'tw-existing'}}, ConsistentRead=True).get('Item')
    assert got_existing['v'] == {'N': '1'}, (
        f'transaction was canceled, so tw-existing must remain at v=1, got {got_existing}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
