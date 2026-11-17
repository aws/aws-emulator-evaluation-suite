"""query-exclusive-start-key-never-written-item-returns-empty-page-and-missing-sort-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-exclusive-start-key-never-written-item-returns-empty-page-and-missing-sort-key-rejected"
GROUP = 'access_path'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error(fn):
    """``(Code, Message)`` for the ``ClientError`` ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query against the base table accepts an ExclusiveStartKey naming a sort key value
    that was never written, past the last real item, and returns an empty page; the same
    call with an ExclusiveStartKey missing the table's sort key is a ValidationException.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Query.html#DDB-Query-request-ExclusiveStartKey
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'true'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 90})

    for i in range(10):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'x'}, 'sk': {'S': f'{i:03d}'}})

    key_condition = {
        'KeyConditionExpression': 'pk = :p',
        'ExpressionAttributeValues': {':p': {'S': 'x'}},
    }

    # Positive control: an ExclusiveStartKey resuming mid-range from a sort key that was never
    # written still continues forward from that position, returning the real items after it.
    mid = ddb.query(
        TableName=table, ExclusiveStartKey={'pk': {'S': 'x'}, 'sk': {'S': '004a'}},
        ConsistentRead=True, **key_condition,
    )
    mid_sks = [i['sk']['S'] for i in mid['Items']]
    assert mid_sks == ['005', '006', '007', '008', '009'], (
        f'positive control: expected a never-written mid-range key to resume with '
        f"['005'..'009'], got {mid_sks!r}"
    )

    # Behaviour under test: an ExclusiveStartKey naming a sort key past the last real item,
    # never written, is accepted and returns an empty page -- not an error.
    past_end = ddb.query(
        TableName=table, ExclusiveStartKey={'pk': {'S': 'x'}, 'sk': {'S': '999'}},
        ConsistentRead=True, **key_condition,
    )
    assert past_end['Items'] == [], (
        f"expected an empty page resuming past the last item, got {past_end['Items']!r}"
    )
    assert past_end['Count'] == 0, f"expected Count 0, got {past_end['Count']!r}"
    assert 'LastEvaluatedKey' not in past_end, (
        f"expected no LastEvaluatedKey on the final empty page, got {past_end.get('LastEvaluatedKey')!r}"
    )

    # Negative: an ExclusiveStartKey missing the table's sort key is rejected outright.
    code, message = _error(lambda: ddb.query(
        TableName=table, ExclusiveStartKey={'pk': {'S': 'x'}}, **key_condition,
    ))
    assert code == ERR_VALIDATION, f'Query with ExclusiveStartKey missing sk: expected {ERR_VALIDATION}, got {code}'
    assert message == 'The provided starting key is invalid', (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # Every call above was a read: confirm none of them wrote, deleted or corrupted an item.
    final = ddb.query(TableName=table, ConsistentRead=True, **key_condition)
    final_sks = {i['sk']['S'] for i in final['Items']}
    assert final_sks == {f'{i:03d}' for i in range(10)}, (
        f'expected the original 10 items unchanged after the calls above, got {sorted(final_sks)!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
