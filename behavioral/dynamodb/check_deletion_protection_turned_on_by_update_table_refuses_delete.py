"""deletion-protection-turned-on-by-update-table-refuses-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletion-protection-turned-on-by-update-table-refuses-delete"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A composite-key table created unprotected deletes only after its flag is cleared again:
    UpdateTable turning protection on makes DeleteTable fail with ValidationException and keeps every
    item, and turning it off lets the same DeleteTable succeed.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'owner', 'KeyType': 'HASH'},
                   {'AttributeName': 'seq', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'owner', 'AttributeType': 'S'},
                              {'AttributeName': 'seq', 'AttributeType': 'N'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )

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
    _wait_table_active(ddb, t)
    flag = _settled(ddb, t, False)['DeletionProtectionEnabled']
    assert flag is False, f'a table created without the flag reports DeletionProtectionEnabled={flag!r}'

    items = [{'owner': {'S': 'u-1'}, 'seq': {'N': str(n)}, 'v': {'S': f'v{n}'}} for n in (3, 1, 2)]
    for item in items:
        ddb.put_item(TableName=t, Item=item)

    ddb.update_table(TableName=t, DeletionProtectionEnabled=True)
    flag = _settled(ddb, t, True)['DeletionProtectionEnabled']
    assert flag is True, f'after UpdateTable turned it on, DeletionProtectionEnabled={flag!r}'

    for attempt in ('first', 'repeated'):
        exc = _expect_error(lambda: ddb.delete_table(TableName=t), ('ValidationException',))
        message = exc.response['Error'].get('Message')
        assert message == PROTECTED_MESSAGE, f'the {attempt} protected DeleteTable: got the message {message!r}'

    still = ddb.describe_table(TableName=t)['Table']
    assert (still['TableStatus'], still['DeletionProtectionEnabled']) == ('ACTIVE', True), still
    kept = ddb.query(TableName=t, KeyConditionExpression='#o = :o',
                     ExpressionAttributeNames={'#o': 'owner'},
                     ExpressionAttributeValues={':o': {'S': 'u-1'}}, ConsistentRead=True)['Items']
    want = sorted(items, key=lambda i: int(i['seq']['N']))
    assert kept == want, f"the items changed across the rejected DeleteTable: expected {want!r}, got {kept!r}"

    ddb.update_table(TableName=t, DeletionProtectionEnabled=False)
    _settled(ddb, t, False)
    ddb.delete_table(TableName=t)
    _wait_table_deleted(ddb, t)
    exc = _expect_error(lambda: ddb.describe_table(TableName=t), ('ResourceNotFoundException',))
    message = exc.response['Error'].get('Message')
    assert message == f'Requested resource not found: Table: {t} not found', (
        f'DescribeTable on the deleted table: got the message {message!r}'
    )
    exc = _expect_error(lambda: ddb.update_table(TableName=t, DeletionProtectionEnabled=True),
                        ('ResourceNotFoundException',))
    message = exc.response['Error'].get('Message')
    assert message == f'Requested resource not found: Table: {t} not found', (
        f'UpdateTable on the deleted table: got the message {message!r}'
    )


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
