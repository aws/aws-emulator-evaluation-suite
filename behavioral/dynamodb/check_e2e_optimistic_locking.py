"""e2e-optimistic-locking."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-optimistic-locking"
GROUP = 'e2e_workflows'
SERVICES = ['dynamodb']
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Optimistic locking: conditional update with version check, stale version rejected."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': 'e2e-optimistic-locking'}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'id': {'S': 'doc-1'}, 'version': {'N': '1'}, 'data': {'S': 'initial'}})
    ddb.update_item(TableName=table, Key={'id': {'S': 'doc-1'}}, UpdateExpression='SET version = version + :inc, #d = :data', ConditionExpression='version = :v', ExpressionAttributeNames={'#d': 'data'}, ExpressionAttributeValues={':inc': {'N': '1'}, ':v': {'N': '1'}, ':data': {'S': 'updated-v2'}})
    got = ddb.get_item(TableName=table, Key={'id': {'S': 'doc-1'}}, ConsistentRead=True).get('Item')
    assert got['version'] == {'N': '2'}, f"Expected version 2, got {got['version']}"
    assert got['data'] == {'S': 'updated-v2'}, f"Expected data 'updated-v2', got {got['data']}"
    exc = _expect_error(lambda: ddb.update_item(TableName=table, Key={'id': {'S': 'doc-1'}}, UpdateExpression='SET version = version + :inc, #d = :data', ConditionExpression='version = :v', ExpressionAttributeNames={'#d': 'data'}, ExpressionAttributeValues={':inc': {'N': '1'}, ':v': {'N': '1'}, ':data': {'S': 'stale-update'}}), (ERR_CONDITIONAL_CHECK_FAILED,))
    message = exc.response['Error'].get('Message')
    assert message == 'The conditional request failed', f"the stale update: got the message {message!r}"
    got2 = ddb.get_item(TableName=table, Key={'id': {'S': 'doc-1'}}, ConsistentRead=True).get('Item')
    assert got2['version'] == {'N': '2'}, f"Expected version to stay 2 after rejected stale update, got {got2['version']}"
    assert got2['data'] == {'S': 'updated-v2'}, f"Expected data to stay 'updated-v2' after rejected stale update, got {got2['data']}"
    ddb.update_item(TableName=table, Key={'id': {'S': 'doc-1'}}, UpdateExpression='SET version = version + :inc, #d = :data', ConditionExpression='version = :v', ExpressionAttributeNames={'#d': 'data'}, ExpressionAttributeValues={':inc': {'N': '1'}, ':v': {'N': '2'}, ':data': {'S': 'updated-v3'}})
    got3 = ddb.get_item(TableName=table, Key={'id': {'S': 'doc-1'}}, ConsistentRead=True).get('Item')
    assert got3['version'] == {'N': '3'}, f"Expected version 3 after retrying with the current version, got {got3['version']}"
    assert got3['data'] == {'S': 'updated-v3'}, f"Expected data 'updated-v3' after retrying with the current version, got {got3['data']}"

    # Item-level gone beats: the deleted item reads absent, queries empty, and is not resurrected.
    ddb.delete_item(TableName=table, Key={'id': {'S': 'doc-1'}})
    gone = ddb.get_item(TableName=table, Key={'id': {'S': 'doc-1'}}, ConsistentRead=True)
    assert 'Item' not in gone, f"deleted item doc-1 still readable: {gone.get('Item')!r}"
    q = ddb.query(TableName=table, KeyConditionExpression='id = :id', ExpressionAttributeValues={':id': {'S': 'doc-1'}}, ConsistentRead=True)
    assert q['Count'] == 0, f"expected Query for deleted doc-1 to return Count 0, got {q['Count']}: {q.get('Items')!r}"
    exc = _expect_error(lambda: ddb.update_item(TableName=table, Key={'id': {'S': 'doc-1'}}, UpdateExpression='SET #d = :data', ConditionExpression='attribute_exists(id)', ExpressionAttributeNames={'#d': 'data'}, ExpressionAttributeValues={':data': {'S': 'resurrected'}}), (ERR_CONDITIONAL_CHECK_FAILED,))
    message = exc.response['Error'].get('Message')
    assert message == 'The conditional request failed', f"the resurrecting update: got the message {message!r}"
    after = ddb.get_item(TableName=table, Key={'id': {'S': 'doc-1'}}, ConsistentRead=True)
    assert 'Item' not in after, f"refused conditional update resurrected doc-1: {after.get('Item')!r}"


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status class, a non-empty message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx with {code}, got {got_status!r}"
    )
    assert msg.strip(), f"expected a non-empty message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
