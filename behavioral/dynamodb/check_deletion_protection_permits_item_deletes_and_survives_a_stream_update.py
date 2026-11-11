"""deletion-protection-permits-item-deletes-and-survives-a-stream-update."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletion-protection-permits-item-deletes-and-survives-a-stream-update"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
#: Bound on each asynchronous table transition; below the harness ceiling.
POLL_BUDGET_S = 40.0
PROTECTED_MESSAGE = ('Resource cannot be deleted as it is currently protected against deletion. '
                     'Disable deletion protection first.')


def _poll_until(probe, predicate, *, timeout_s=POLL_BUDGET_S, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _assert_error(exc, codes, *, status=400) -> None:
    """Grade a ClientError on code, HTTP status class, and a non-empty message."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx with {code}, got {got_status!r}"
    )
    assert msg.strip(), f"expected a non-empty message with {code}"


def _expect_error(fn, codes, *, status=400):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _wait_table_deleted(ddb, name, timeout_s=POLL_BUDGET_S):
    def probe():
        try:
            return ddb.describe_table(TableName=name)['Table']['TableStatus']
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                return 'GONE'
            raise
    _poll_until(probe, lambda s: s == 'GONE', timeout_s=timeout_s, interval_s=1.0, description=f'table {name} deleted')


def _settled(ddb, t, protected):
    """DescribeTable once the table is ACTIVE with the wanted deletion-protection flag."""
    return _poll_until(
        lambda: ddb.describe_table(TableName=t)['Table'],
        lambda tbl: tbl['TableStatus'] == 'ACTIVE' and tbl.get('DeletionProtectionEnabled') is protected,
        interval_s=2.0,
        description=f'table ACTIVE with DeletionProtectionEnabled={protected}',
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Deletion protection guards the table, not its items: DeleteItem and a BatchWriteItem delete
    still remove items, an UpdateTable enabling a stream keeps the flag set and DeleteTable refused,
    and only clearing the flag lets the table go.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        DeletionProtectionEnabled=True,
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )

    def _cleanup():
        try:
            ddb.update_table(TableName=t, DeletionProtectionEnabled=False)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                return
            raise
        _settled(ddb, t, False)
        try:
            ddb.delete_table(TableName=t)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
                raise
    ctx.on_cleanup(_cleanup)
    _wait_table_active(ddb, t)
    flag = _settled(ddb, t, True)['DeletionProtectionEnabled']
    assert flag is True, f'a table created protected reports DeletionProtectionEnabled={flag!r}'

    keys = [f'row-{i}' for i in range(4)]
    for k in keys:
        ddb.put_item(TableName=t, Item={'pk': {'S': k}, 'v': {'S': k.upper()}})
    old = ddb.delete_item(TableName=t, Key={'pk': {'S': keys[0]}}, ReturnValues='ALL_OLD')['Attributes']
    assert old == {'pk': {'S': keys[0]}, 'v': {'S': 'ROW-0'}}, f"DeleteItem ALL_OLD returned {old!r}"
    unprocessed = ddb.batch_write_item(RequestItems={t: [
        {'DeleteRequest': {'Key': {'pk': {'S': k}}}} for k in keys[1:3]]}).get('UnprocessedItems')
    assert not unprocessed, f"BatchWriteItem left deletes unprocessed: {unprocessed!r}"
    left = sorted(i['pk']['S'] for i in ddb.scan(TableName=t, ConsistentRead=True)['Items'])
    assert left == [keys[3]], f"expected only {keys[3]!r} left after the item deletes, got {left!r}"

    ddb.update_table(TableName=t, StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'KEYS_ONLY'})
    tbl = _poll_until(
        lambda: ddb.describe_table(TableName=t)['Table'],
        lambda d: d['TableStatus'] == 'ACTIVE' and d.get('StreamSpecification', {}).get('StreamEnabled') is True,
        interval_s=2.0, description='stream enabled and table ACTIVE',
    )
    assert tbl['DeletionProtectionEnabled'] is True, f"enabling a stream cleared deletion protection: {tbl!r}"
    assert tbl['StreamSpecification'] == {'StreamEnabled': True, 'StreamViewType': 'KEYS_ONLY'}, tbl
    stream_arn = tbl['LatestStreamArn']
    assert stream_arn.startswith(tbl['TableArn'] + '/stream/'), f"unexpected stream ARN shape for {t}"

    exc = _expect_error(lambda: ddb.delete_table(TableName=t), ('ValidationException',))
    message = exc.response['Error'].get('Message')
    assert message == PROTECTED_MESSAGE, f'the protected DeleteTable: got the message {message!r}'
    kept = ddb.get_item(TableName=t, Key={'pk': {'S': keys[3]}}, ConsistentRead=True).get('Item')
    assert kept == {'pk': {'S': keys[3]}, 'v': {'S': 'ROW-3'}}, f"the remaining item changed: {kept!r}"

    ddb.update_table(TableName=t, DeletionProtectionEnabled=False)
    _settled(ddb, t, False)
    ddb.delete_table(TableName=t)
    _wait_table_deleted(ddb, t)
    exc = _expect_error(lambda: ddb.describe_table(TableName=t), ('ResourceNotFoundException',))
    message = exc.response['Error'].get('Message')
    assert message == f'Requested resource not found: Table: {t} not found', (
        f'DescribeTable on the deleted table: got the message {message!r}'
    )
    exc = _expect_error(lambda: ddb.delete_item(TableName=t, Key={'pk': {'S': keys[3]}}),
                        ('ResourceNotFoundException',))
    message = exc.response['Error'].get('Message')
    assert message == 'Requested resource not found', f'DeleteItem on the deleted table: got the message {message!r}'


#: Bound on each wait; a target that needs longer fails with the last answer it gave.
_WAIT_S = 40.0


def _wait_table_active(ddb, table, timeout_s=_WAIT_S) -> None:
    """Poll DescribeTable until the table is ACTIVE; on expiry fail with the last status read."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"table {table} not ACTIVE within {timeout_s:.0f}s; last TableStatus {status!r}")
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
