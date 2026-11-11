"""query-scan-exclusive-start-key-empty-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-scan-exclusive-start-key-empty-value-rejected"
GROUP = 'access_path'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be rejected, but it succeeded: {result!r}')


def _poll_for_lek(ctx, fn, poll_s: float = 1.0) -> dict:
    """Poll fn() (an eventually consistent Limit=1 page) until it carries a LastEvaluatedKey."""
    while True:
        page = fn()
        if 'LastEvaluatedKey' in page:
            return page['LastEvaluatedKey']
        left = ctx.time_left()
        if left is not None and left <= poll_s:
            raise AssertionError(f'no second item became visible in time; last page: {page!r}')
        time.sleep(poll_s)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query/Scan reject an ExclusiveStartKey whose hash or range key is an empty string or
    binary value, with ValidationException. Query always names the key alone; Scan always
    names a secondary index on the table instead, for any key attribute, once one exists.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'B'},
            {'AttributeName': 'gpk', 'AttributeType': 'B'},
            {'AttributeName': 'gsk', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}, {'AttributeName': 'gsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    item1 = {'pk': {'S': 'x'}, 'sk': {'B': b'1'}, 'gpk': {'B': b'g'}, 'gsk': {'S': 'h'}}
    item2 = {'pk': {'S': 'x'}, 'sk': {'B': b'2'}, 'gpk': {'B': b'g'}, 'gsk': {'S': 'i'}}
    ddb.put_item(TableName=table, Item=item1)
    ddb.put_item(TableName=table, Item=item2)

    # Positive controls: a real, freshly minted ExclusiveStartKey continues each path.
    page = ddb.query(TableName=table, KeyConditionExpression='pk = :p',
                      ExpressionAttributeValues={':p': {'S': 'x'}}, Limit=1, ConsistentRead=True)
    table_esk = page['LastEvaluatedKey']
    cont = ddb.query(TableName=table, KeyConditionExpression='pk = :p',
                      ExpressionAttributeValues={':p': {'S': 'x'}}, ExclusiveStartKey=table_esk,
                      ConsistentRead=True)
    assert cont['Items'], 'positive control: query continuation with a real ExclusiveStartKey returned nothing'

    page = ddb.scan(TableName=table, Limit=1, ConsistentRead=True)
    scan_esk = page['LastEvaluatedKey']
    cont = ddb.scan(TableName=table, ExclusiveStartKey=scan_esk, ConsistentRead=True)
    assert 'Items' in cont, f'positive control: scan continuation returned {cont!r}'

    # The GSI is eventually consistent: poll Limit=1 until the second item is visible, so
    # pagination here reflects two items rather than racing the index's own propagation.
    gsi_query_esk = _poll_for_lek(ctx, lambda: ddb.query(
        TableName=table, IndexName='gsi1', KeyConditionExpression='gpk = :g',
        ExpressionAttributeValues={':g': {'B': b'g'}}, Limit=1))
    cont = ddb.query(TableName=table, IndexName='gsi1', KeyConditionExpression='gpk = :g',
                      ExpressionAttributeValues={':g': {'B': b'g'}}, ExclusiveStartKey=gsi_query_esk)
    assert cont['Items'], 'positive control: GSI query continuation returned nothing'

    gsi_scan_esk = _poll_for_lek(ctx, lambda: ddb.scan(TableName=table, IndexName='gsi1', Limit=1))
    cont = ddb.scan(TableName=table, IndexName='gsi1', ExclusiveStartKey=gsi_scan_esk)
    assert 'Items' in cont, f'positive control: GSI scan continuation returned {cont!r}'

    # Query never names an index: every empty key attribute reports "Key: <name>" alone,
    # whether it is the table's hash key, its range key, the GSI's hash key or its range key.
    for label, bad_key, attr in [
        ('table hash (pk, S)', {**table_esk, 'pk': {'S': ''}}, 'pk'),
        ('table range (sk, B)', {**table_esk, 'sk': {'B': b''}}, 'sk'),
        ('GSI hash (gpk, B)', {**gsi_query_esk, 'gpk': {'B': b''}}, 'gpk'),
        ('GSI range (gsk, S)', {**gsi_query_esk, 'gsk': {'S': ''}}, 'gsk'),
    ]:
        empty_kind = 'string' if bad_key[attr].get('S') == '' else 'binary'
        if attr in ('gpk', 'gsk'):
            code, message = _error(lambda bad_key=bad_key: ddb.query(
                TableName=table, IndexName='gsi1', KeyConditionExpression='gpk = :g',
                ExpressionAttributeValues={':g': {'B': b'g'}}, ExclusiveStartKey=bad_key))
        else:
            code, message = _error(lambda bad_key=bad_key: ddb.query(
                TableName=table, KeyConditionExpression='pk = :p',
                ExpressionAttributeValues={':p': {'S': 'x'}}, ExclusiveStartKey=bad_key))
        assert code == ERR_VALIDATION, f'Query/{label}: expected {ERR_VALIDATION}, got {code}: {message!r}'
        expected = (
            'One or more parameter values are not valid. The AttributeValue for a key attribute '
            f'cannot contain an empty {empty_kind} value. Key: {attr}'
        )
        assert message == expected, f'Query/{label}: expected {expected!r}, got {message!r}'

    # Scan always names a secondary index -- gsi1, the only one on this table -- for every
    # empty key attribute, even one (the base table's own key) that index does not contain.
    for label, bad_key, attr, use_index in [
        ('table hash (pk, S)', {**scan_esk, 'pk': {'S': ''}}, 'pk', False),
        ('table range (sk, B)', {**scan_esk, 'sk': {'B': b''}}, 'sk', False),
        ('GSI hash (gpk, B)', {**gsi_scan_esk, 'gpk': {'B': b''}}, 'gpk', True),
        ('GSI range (gsk, S)', {**gsi_scan_esk, 'gsk': {'S': ''}}, 'gsk', True),
    ]:
        empty_kind = 'string' if bad_key[attr].get('S') == '' else 'binary'
        if use_index:
            code, message = _error(lambda bad_key=bad_key: ddb.scan(
                TableName=table, IndexName='gsi1', ExclusiveStartKey=bad_key))
        else:
            code, message = _error(lambda bad_key=bad_key: ddb.scan(
                TableName=table, ExclusiveStartKey=bad_key))
        assert code == ERR_VALIDATION, f'Scan/{label}: expected {ERR_VALIDATION}, got {code}: {message!r}'
        expected = (
            'One or more parameter values are not valid. A value specified for a secondary '
            'index key is not supported. The AttributeValue for a key attribute cannot contain '
            f'an empty {empty_kind} value. IndexName: gsi1, IndexKey: {attr}'
        )
        assert message == expected, f'Scan/{label}: expected {expected!r}, got {message!r}'

    # Nothing any of the eight rejected reads could write: the table still holds only the seed.
    final = ddb.scan(TableName=table, ConsistentRead=True)['Items']
    assert sorted(final, key=lambda i: i['sk']['B']) == [item1, item2], (
        f'expected only the two seed items to remain, got {final!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
