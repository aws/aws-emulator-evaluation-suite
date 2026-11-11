"""exclusive-start-key-outside-range-and-missing-attribute-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "exclusive-start-key-outside-range-and-missing-attribute-rejected"
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
    """Query rejects an ExclusiveStartKey whose sort key falls outside the
    KeyConditionExpression's range, in both scan directions, and Scan rejects one
    missing a key attribute -- both ValidationException, and neither call writes.

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
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 1, 'MaxAttempts': 60})

    for i in range(10):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'x'}, 'sk': {'S': f'{i:03d}'}})

    key_condition = {
        'KeyConditionExpression': 'pk = :p AND sk BETWEEN :lo AND :hi',
        'ExpressionAttributeValues': {':p': {'S': 'x'}, ':lo': {'S': '003'}, ':hi': {'S': '006'}},
    }

    # Positive control, forward: an ExclusiveStartKey inside the BETWEEN range continues normally.
    forward_ok = ddb.query(
        TableName=table, ExclusiveStartKey={'pk': {'S': 'x'}, 'sk': {'S': '004'}},
        ConsistentRead=True, **key_condition,
    )
    forward_sks = [i['sk']['S'] for i in forward_ok['Items']]
    assert forward_sks == ['005', '006'], (
        f'positive control: expected an in-range ExclusiveStartKey to continue forward with '
        f"['005', '006'], got {forward_sks!r}"
    )

    # Negative, forward: an ExclusiveStartKey above the range's upper bound is rejected.
    code, message = _error(lambda: ddb.query(
        TableName=table, ExclusiveStartKey={'pk': {'S': 'x'}, 'sk': {'S': '020'}}, **key_condition,
    ))
    assert code == ERR_VALIDATION, f'forward out-of-range ExclusiveStartKey: expected {ERR_VALIDATION}, got {code}'
    assert message == 'The provided starting key does not match the range key predicate', (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # Positive control, backward: an in-range ExclusiveStartKey continues normally descending.
    backward_ok = ddb.query(
        TableName=table, ExclusiveStartKey={'pk': {'S': 'x'}, 'sk': {'S': '005'}},
        ConsistentRead=True, ScanIndexForward=False, **key_condition,
    )
    backward_sks = [i['sk']['S'] for i in backward_ok['Items']]
    assert backward_sks == ['004', '003'], (
        f'positive control: expected an in-range ExclusiveStartKey to continue backward with '
        f"['004', '003'], got {backward_sks!r}"
    )

    # Negative, backward: an ExclusiveStartKey below the range's lower bound is rejected too.
    code, message = _error(lambda: ddb.query(
        TableName=table, ExclusiveStartKey={'pk': {'S': 'x'}, 'sk': {'S': '002'}},
        ScanIndexForward=False, **key_condition,
    ))
    assert code == ERR_VALIDATION, f'backward out-of-range ExclusiveStartKey: expected {ERR_VALIDATION}, got {code}'
    assert message == 'The provided starting key does not match the range key predicate', (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # Positive control: Scan accepts a well-formed, complete ExclusiveStartKey.
    scan_ok = ddb.scan(TableName=table, ExclusiveStartKey={'pk': {'S': 'x'}, 'sk': {'S': '003'}})
    assert 'Items' in scan_ok, f'positive control: expected a complete ExclusiveStartKey to be accepted, got {scan_ok}'

    # Negative: Scan rejects an ExclusiveStartKey missing the table's range key attribute.
    code, message = _error(lambda: ddb.scan(TableName=table, ExclusiveStartKey={'pk': {'S': 'x'}}))
    assert code == ERR_VALIDATION, f'Scan with an ExclusiveStartKey missing sk: expected {ERR_VALIDATION}, got {code}'
    assert message == 'The provided starting key is invalid', (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # Every rejected call above is a read: confirm none of them wrote, deleted or corrupted an item.
    final = ddb.scan(TableName=table, ConsistentRead=True)
    final_sks = {i['sk']['S'] for i in final['Items']}
    assert final_sks == {f'{i:03d}' for i in range(10)}, (
        f'expected the original 10 items unchanged after the rejected calls, got {sorted(final_sks)!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
