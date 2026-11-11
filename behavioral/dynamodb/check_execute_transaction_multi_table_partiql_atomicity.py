"""execute-transaction-multi-table-partiql-atomicity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-transaction-multi-table-partiql-atomicity"
GROUP = 'partiql'
SERVICES = ['dynamodb']
ERR_TRANSACTION_CANCELED = 'TransactionCanceledException'


def _error_code(fn):
    """Return fn()'s error code and message; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected the transaction to be canceled, but it SUCCEEDED: {result!r}')


def _simple_table(ctx, ddb, prefix):
    name = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda n=name: ddb.delete_table(TableName=n))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL ExecuteTransaction statements spanning two tables commit together, and when one
    statement's WHERE condition fails the transaction is cancelled and the other table's
    unconditional UPDATE rolls back too."""
    ddb = ctx.client('dynamodb')
    table_a = _simple_table(ctx, ddb, 'sim2real-behav-etma-a-')
    table_b = _simple_table(ctx, ddb, 'sim2real-behav-etma-b-')
    key_val = {'S': 'shared-id'}
    ddb.put_item(TableName=table_a, Item={'pk': key_val, 'v': {'N': '1'}})
    ddb.put_item(TableName=table_b, Item={'pk': key_val, 'v': {'N': '1'}})

    ddb.execute_transaction(
        TransactStatements=[
            {'Statement': f'UPDATE "{table_a}" SET v = ? WHERE pk = ?', 'Parameters': [{'N': '9'}, key_val]},
            {'Statement': f'UPDATE "{table_b}" SET v = ? WHERE pk = ?', 'Parameters': [{'N': '9'}, key_val]},
        ]
    )
    a_after = ddb.get_item(TableName=table_a, Key={'pk': key_val}, ConsistentRead=True)['Item']
    b_after = ddb.get_item(TableName=table_b, Key={'pk': key_val}, ConsistentRead=True)['Item']
    assert a_after['v'] == {'N': '9'}, f"expected table_a v=9 after commit, got {a_after!r}"
    assert b_after['v'] == {'N': '9'}, f"expected table_b v=9 after commit, got {b_after!r}"

    code, message = _error_code(
        lambda: ddb.execute_transaction(
            TransactStatements=[
                {
                    'Statement': f'UPDATE "{table_a}" SET v = ? WHERE pk = ?',
                    'Parameters': [{'N': '100'}, key_val],
                },
                {
                    'Statement': f'UPDATE "{table_b}" SET v = ? WHERE pk = ? AND v = ?',
                    'Parameters': [{'N': '100'}, key_val, {'N': '999'}],
                },
            ]
        )
    )
    assert code == ERR_TRANSACTION_CANCELED, f'expected {ERR_TRANSACTION_CANCELED}, got {code}'
    assert message == "Transaction cancelled, please refer cancellation reasons for specific reasons [None, ConditionalCheckFailed]", (
        f"expected the exact TransactionCanceledException message AWS returns, got {message!r}"
    )

    a_unchanged = ddb.get_item(TableName=table_a, Key={'pk': key_val}, ConsistentRead=True)['Item']
    b_unchanged = ddb.get_item(TableName=table_b, Key={'pk': key_val}, ConsistentRead=True)['Item']
    assert a_unchanged['v'] == {'N': '9'}, (
        f"cross-table sibling statement must roll back with the txn: expected table_a v=9, got {a_unchanged!r}"
    )
    assert b_unchanged['v'] == {'N': '9'}, f"expected table_b v=9 (unchanged), got {b_unchanged!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
