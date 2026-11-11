"""batch-get-item-unknown-table-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-item-unknown-table-rejected"
GROUP = 'batch'
SERVICES = ['dynamodb']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be rejected, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchGetItem whose RequestItems map names one real table and one syntactically valid but
    nonexistent table is ResourceNotFoundException for the whole call; the real table's own item is
    still readable by a plain GetItem after the refusal.
    """
    ddb = ctx.client('dynamodb')
    real_table = ctx.unique_name('sim2real-behav-bgiunk-')
    missing_table = ctx.unique_name('sim2real-behav-bgiunk-missing-')
    ddb.create_table(
        TableName=real_table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=real_table))
    ddb.get_waiter('table_exists').wait(TableName=real_table, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    seed = {'pk': {'S': 'seed'}, 'v': {'S': 'kept'}}
    ddb.put_item(TableName=real_table, Item=seed)

    # Positive control: BatchGetItem over the real table alone works, so the rejection below is
    # attributable to the missing table and not to a broken request.
    control = ddb.batch_get_item(
        RequestItems={real_table: {'Keys': [{'pk': {'S': 'seed'}}], 'ConsistentRead': True}},
    )
    assert control['Responses'][real_table] == [seed], (
        f'positive control BatchGetItem on the real table alone did not return the seed, got '
        f'{control["Responses"]!r}'
    )

    code, message = _error(lambda: ddb.batch_get_item(RequestItems={
        real_table: {'Keys': [{'pk': {'S': 'seed'}}], 'ConsistentRead': True},
        missing_table: {'Keys': [{'pk': {'S': 'x'}}], 'ConsistentRead': True},
    }))
    assert code == 'ResourceNotFoundException', (
        f'BatchGetItem naming one real table and one nonexistent table must fail with '
        f'ResourceNotFoundException for the whole call, got {code!r}: {message!r}'
    )
    assert message == 'Requested resource not found', f'unexpected message {message!r}'

    after = ddb.get_item(TableName=real_table, Key={'pk': {'S': 'seed'}}, ConsistentRead=True)
    assert after.get('Item') == seed, (
        f'the refused BatchGetItem must have left the real table untouched, got {after.get("Item")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
