"""batch-write-duplicate-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-duplicate-key-rejected"
GROUP = 'batch'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error(fn):
    """The (Code, Message) of a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem MUST reject a single call that targets the SAME primary key twice (two
    PutRequests for the same pk) with ValidationException -- the whole call is invalidated up
    front, and NEITHER write (nor any other, unrelated write in the same batch) is applied.
    """
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

    # Positive control: a batch with no duplicate keys applies its writes. Without this, a
    # target that rejects every BatchWriteItem call would pass the negative below for the wrong
    # reason.
    control_key = {'S': 'control-target'}
    ddb.batch_write_item(
        RequestItems={t: [{'PutRequest': {'Item': {'pk': control_key, 'v': {'N': '0'}}}}]}
    )
    control_after = ddb.get_item(TableName=t, Key={'pk': control_key}, ConsistentRead=True)
    assert control_after.get('Item', {}).get('v') == {'N': '0'}, (
        f'positive control: a batch with no duplicate keys must apply its write, got {control_after}'
    )

    dup_key_val = {'S': 'dup-target'}
    code, message = _error(
        lambda: ddb.batch_write_item(
            RequestItems={
                t: [
                    {'PutRequest': {'Item': {'pk': dup_key_val, 'v': {'N': '1'}}}},
                    {'PutRequest': {'Item': {'pk': dup_key_val, 'v': {'N': '2'}}}},
                    {'PutRequest': {'Item': {'pk': {'S': 'unrelated'}, 'v': {'N': '3'}}}},
                ]
            }
        )
    )
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}'
    assert message == 'Provided list of item keys contains duplicates', (
        f'expected the duplicate-keys refusal message, got {message!r}'
    )

    dup_after = ddb.get_item(TableName=t, Key={'pk': dup_key_val}, ConsistentRead=True)
    assert 'Item' not in dup_after, 'a rejected duplicate-key batch must write nothing for that key'
    unrelated_after = ddb.get_item(TableName=t, Key={'pk': {'S': 'unrelated'}}, ConsistentRead=True)
    assert 'Item' not in unrelated_after, (
        'a rejected batch must apply NONE of its writes, including unrelated ones'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
