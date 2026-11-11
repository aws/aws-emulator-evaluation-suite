"""execute-transaction-duplicate-insert-rolls-back-sibling-insert."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-transaction-duplicate-insert-rolls-back-sibling-insert"
GROUP = 'partiql'
SERVICES = ['dynamodb']
ERR_TRANSACTION_CANCELED = 'TransactionCanceledException'


def _partiql_table(ctx) -> str:
    """A pk/sk table for PartiQL statements."""
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda n=name: ddb.delete_table(TableName=n))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteTransaction cancels on a DuplicateItem INSERT and rolls back a sibling INSERT in
    the same transaction that would have succeeded on its own, leaving both keys as they were
    before the call.
    """
    ddb = ctx.client('dynamodb')
    t = _partiql_table(ctx)

    # positive control: two fresh-key INSERTs in one ExecuteTransaction both commit
    ddb.execute_transaction(TransactStatements=[
        {'Statement': f'''INSERT INTO "{t}" VALUE {{'pk':'control-a','sk':'s1'}}'''},
        {'Statement': f'''INSERT INTO "{t}" VALUE {{'pk':'control-b','sk':'s1'}}'''},
    ])
    control_a = ddb.get_item(TableName=t, Key={'pk': {'S': 'control-a'}, 'sk': {'S': 's1'}}, ConsistentRead=True)
    control_b = ddb.get_item(TableName=t, Key={'pk': {'S': 'control-b'}, 'sk': {'S': 's1'}}, ConsistentRead=True)
    assert control_a.get('Item') == {'pk': {'S': 'control-a'}, 'sk': {'S': 's1'}}, (
        f'positive control: the first ExecuteTransaction INSERT should have committed, got {control_a!r}'
    )
    assert control_b.get('Item') == {'pk': {'S': 'control-b'}, 'sk': {'S': 's1'}}, (
        f'positive control: the second ExecuteTransaction INSERT should have committed, got {control_b!r}'
    )

    # establish an existing item that the first statement will collide with
    ddb.execute_statement(Statement=f'''INSERT INTO "{t}" VALUE {{'pk':'existing','sk':'s1','tag':'original'}}''')

    duplicate_statement = f'''INSERT INTO "{t}" VALUE {{'pk':'existing','sk':'s1','tag':'should-not-persist'}}'''
    sibling_statement = f'''INSERT INTO "{t}" VALUE {{'pk':'sibling','sk':'s1'}}'''
    try:
        ddb.execute_transaction(TransactStatements=[
            {'Statement': duplicate_statement},
            {'Statement': sibling_statement},
        ])
        err = None
    except ClientError as exc:
        err = exc.response
    assert err is not None, 'expected TransactionCanceledException, got success'
    assert err['Error']['Code'] == ERR_TRANSACTION_CANCELED, (
        f"expected {ERR_TRANSACTION_CANCELED}, got {err['Error'].get('Code')}"
    )
    expected_message = (
        'Transaction cancelled, please refer cancellation reasons for specific reasons '
        '[DuplicateItem, None]'
    )
    assert err['Error'].get('Message') == expected_message, (
        f'expected message {expected_message!r}, got {err["Error"].get("Message")!r}'
    )
    reasons = err.get('CancellationReasons')
    assert reasons and len(reasons) == 2, f'expected 2 positionally-aligned cancellation reasons, got {reasons}'
    assert reasons[0]['Code'] == 'DuplicateItem', (
        f'expected the duplicate INSERT at index 0 to report DuplicateItem, got {reasons[0]}'
    )
    assert reasons[1] == {'Code': 'None'}, (
        f'the rolled-back sibling must carry Code "None" and no Message, got {reasons[1]!r}'
    )

    # effect absent: the sibling INSERT's key never appears
    sibling_after = ddb.get_item(TableName=t, Key={'pk': {'S': 'sibling'}, 'sk': {'S': 's1'}}, ConsistentRead=True)
    assert 'Item' not in sibling_after, f"canceled transaction's sibling INSERT wrote anyway: {sibling_after.get('Item')}"

    # existing item unchanged: the collided-with item still carries its original tag
    existing_after = ddb.get_item(TableName=t, Key={'pk': {'S': 'existing'}, 'sk': {'S': 's1'}}, ConsistentRead=True)
    assert existing_after.get('Item', {}).get('tag') == {'S': 'original'}, (
        f"canceled transaction must leave the existing item untouched, got {existing_after.get('Item')}"
    )

    # restore: remove the collision, then the identical transaction commits both statements
    ddb.delete_item(TableName=t, Key={'pk': {'S': 'existing'}, 'sk': {'S': 's1'}})
    ddb.execute_transaction(TransactStatements=[
        {'Statement': duplicate_statement},
        {'Statement': sibling_statement},
    ])
    restored_existing = ddb.get_item(TableName=t, Key={'pk': {'S': 'existing'}, 'sk': {'S': 's1'}}, ConsistentRead=True)
    restored_sibling = ddb.get_item(TableName=t, Key={'pk': {'S': 'sibling'}, 'sk': {'S': 's1'}}, ConsistentRead=True)
    assert restored_existing.get('Item', {}).get('tag') == {'S': 'should-not-persist'}, (
        f'expected the identical duplicate statement to succeed after restore, got {restored_existing.get("Item")}'
    )
    assert restored_sibling.get('Item') == {'pk': {'S': 'sibling'}, 'sk': {'S': 's1'}}, (
        f'expected the sibling INSERT to commit once the collision is removed, got {restored_sibling}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
