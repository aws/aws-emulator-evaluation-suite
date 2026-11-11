"""deletion-protection-blocks-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletion-protection-blocks-delete"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
#: Bound on each asynchronous table transition; below the harness ceiling.
POLL_BUDGET_S = 180.0


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A deletion-protected table rejects DeleteTable with ValidationException and keeps its
    data; disabling the flag via UpdateTable then lets DeleteTable succeed."""
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
    # Cleanup must clear deletion protection before it can delete the table.
    def _cleanup():
        try:
            ddb.update_table(TableName=t, DeletionProtectionEnabled=False)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                return
            raise
        try:
            ddb.delete_table(TableName=t)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
                raise
    ctx.on_cleanup(_cleanup)
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 90})

    described = ddb.describe_table(TableName=t)['Table']
    assert described['DeletionProtectionEnabled'] is True, described
    live_names = [n for page in ddb.get_paginator('list_tables').paginate() for n in page.get('TableNames', [])]
    assert t in live_names, f'live table {t} not listed by ListTables'

    item = {'pk': {'S': 'kept'}, 'v': {'S': ctx.unique_name('v-')}}
    ddb.put_item(TableName=t, Item=item)

    exc = _expect_error(lambda: ddb.delete_table(TableName=t), ('ValidationException',))
    message = exc.response['Error'].get('Message')
    assert message == (
        'Resource cannot be deleted as it is currently protected against deletion. '
        'Disable deletion protection first.'
    ), f'the protected DeleteTable: got the message {message!r}'

    # Table and its data must still exist, untouched, after the rejected delete attempt.
    still_active = ddb.describe_table(TableName=t)['Table']
    assert still_active['TableStatus'] == 'ACTIVE', still_active
    kept = ddb.get_item(TableName=t, Key={'pk': {'S': 'kept'}}, ConsistentRead=True).get('Item')
    assert kept == item, f"the item changed across the rejected DeleteTable: expected {item!r}, got {kept!r}"

    ddb.update_table(TableName=t, DeletionProtectionEnabled=False)
    _poll_until(
        lambda: ddb.describe_table(TableName=t)['Table'],
        lambda tbl: tbl['DeletionProtectionEnabled'] is False,
        interval_s=2.0,
        description='DeletionProtectionEnabled cleared',
    )

    ddb.delete_table(TableName=t)
    _wait_table_deleted(ddb, t)
    exc = _expect_error(lambda: ddb.describe_table(TableName=t), ('ResourceNotFoundException',))
    message = exc.response['Error'].get('Message')
    assert message == f'Requested resource not found: Table: {t} not found', (
        f'DescribeTable on the deleted table: got the message {message!r}'
    )
    names = [n for page in ddb.get_paginator('list_tables').paginate() for n in page.get('TableNames', [])]
    assert t not in names, f'deleted table {t} still listed by ListTables'
    exc = _expect_error(lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'after-delete'}}),
                        ('ResourceNotFoundException',))
    message = exc.response['Error'].get('Message')
    assert message == 'Requested resource not found', (
        f'PutItem on the deleted table: got the message {message!r}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
