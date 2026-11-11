"""execute-transaction-condition-failure-cancels-and-bills-nothing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-transaction-condition-failure-cancels-and-bills-nothing"
GROUP = 'partiql'
SERVICES = ['dynamodb']
ERR_CANCELED = 'TransactionCanceledException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReturnConsumedCapacity=INDEXES on an ExecuteTransaction whose UPDATE condition fails
    returns TransactionCanceledException with no ConsumedCapacity, and the item is unchanged;
    the same write with a true condition commits and is billed."""
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

    key = {'pk': {'S': 'et-cancel-1'}}
    ddb.put_item(TableName=t, Item={**key, 'v': {'N': '0'}})

    # Positive control: the condition holds, the write commits and is billed.
    update_stmt = f'UPDATE "{t}" SET v = ? WHERE pk = ? AND v = ?'
    committed = ddb.execute_transaction(
        TransactStatements=[{'Statement': update_stmt, 'Parameters': [{'N': '1'}, key['pk'], {'N': '0'}]}],
        ReturnConsumedCapacity='INDEXES',
    )
    cc = committed['ConsumedCapacity']
    assert len(cc) == 1 and cc[0]['TableName'] == t, (
        f'a committed write transaction must report one ConsumedCapacity entry for the table, got {cc!r}'
    )
    assert cc[0]['CapacityUnits'] == 2.0 and cc[0]['WriteCapacityUnits'] == 2.0, (
        f'a committed 1-item transactional UPDATE must bill 2.0 write capacity units, got {cc[0]!r}'
    )
    after_commit = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert after_commit['v'] == {'N': '1'}, f'the true condition must let the UPDATE commit, got {after_commit!r}'

    # Break exactly one thing: the condition no longer matches the current value.
    try:
        ddb.execute_transaction(
            TransactStatements=[{'Statement': update_stmt, 'Parameters': [{'N': '2'}, key['pk'], {'N': '0'}]}],
            ReturnConsumedCapacity='INDEXES',
        )
        response = None
    except ClientError as exc:
        response = exc.response

    assert response is not None, 'a false condition must cancel the transaction'
    assert response['Error']['Code'] == ERR_CANCELED, (
        f'expected {ERR_CANCELED}, got {response["Error"].get("Code")!r}'
    )
    expected_message = (
        'Transaction cancelled, please refer cancellation reasons for specific reasons '
        '[ConditionalCheckFailed]'
    )
    assert response['Error'].get('Message') == expected_message, (
        f'expected message {expected_message!r}, got {response["Error"].get("Message")!r}'
    )
    assert 'ConsumedCapacity' not in response, (
        f'a canceled transaction must report no ConsumedCapacity, got {response!r}'
    )

    unchanged = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert unchanged['v'] == {'N': '1'}, (
        f'a canceled transaction must not have applied its UPDATE, got {unchanged!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
