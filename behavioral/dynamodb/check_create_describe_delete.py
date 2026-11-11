"""create-describe-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-describe-delete"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
ERR_RESOURCE_NOT_FOUND = 'ResourceNotFoundException'
#: Bound on each asynchronous table transition; below the harness ceiling.
POLL_BUDGET_S = 180.0
#: table_exists waiter bound: 2 s x 90 attempts.
_WAITER = {'Delay': 2, 'MaxAttempts': 90}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTable reports its schema and billing mode; a typed item round-trips and UpdateItem
    applies SET/ADD/REMOVE; the deleted table reads not-found, is unlisted and refuses writes."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig=_WAITER)
    desc = ddb.describe_table(TableName=table)['Table']
    assert desc['TableName'] == table, f"expected TableName {table!r}, got {desc['TableName']!r}"
    assert desc['TableStatus'] == 'ACTIVE', f"expected TableStatus ACTIVE, got {desc['TableStatus']!r}"
    key_schema = {ks['AttributeName']: ks['KeyType'] for ks in desc['KeySchema']}
    assert key_schema == {'id': 'HASH'}, f"expected key schema {{'id': 'HASH'}}, got {key_schema!r}"
    assert 'BillingModeSummary' in desc, (
        f"expected BillingModeSummary on a PAY_PER_REQUEST table, got keys {sorted(desc)!r}"
    )
    billing = desc['BillingModeSummary']['BillingMode']
    assert billing == 'PAY_PER_REQUEST', f"expected BillingMode PAY_PER_REQUEST, got {billing!r}"

    # Use beat: one item of every common attribute type round-trips under a consistent read.
    # Numbers are written as canonical literals, so the string DynamoDB returns must match exactly.
    nonce = ctx.unique_name('nonce-')
    key = {'id': {'S': nonce}}
    item = {
        'id': {'S': nonce},
        's': {'S': 'first'},
        'n': {'N': '15'},
        'f': {'N': '1.5'},
        'b': {'B': b'\x00\xff\x10\x80'},
        'flag': {'BOOL': True},
        'nul': {'NULL': True},
        'l': {'L': [{'S': 'a'}, {'N': '2'}]},
        'm': {'M': {'k': {'S': 'v'}, 'neg': {'N': '-3'}}},
        'ss': {'SS': ['x', 'y', 'z']},
    }
    ddb.put_item(TableName=table, Item=item)
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert _norm(got) == _norm(item), f"expected the typed item back, got {got!r}"

    # UpdateItem SET a string, ADD to a number, REMOVE an attribute; ALL_NEW and a consistent
    # read both report exactly the updated item.
    updated = ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression='SET #s = :s ADD #n :inc REMOVE #flag',
        ExpressionAttributeNames={'#s': 's', '#n': 'n', '#flag': 'flag'},
        ExpressionAttributeValues={':s': {'S': 'second'}, ':inc': {'N': '5'}},
        ReturnValues='ALL_NEW',
    ).get('Attributes')
    expected = {k: v for k, v in item.items() if k != 'flag'}
    expected['s'] = {'S': 'second'}
    expected['n'] = {'N': '20'}
    assert _norm(updated) == _norm(expected), f"UpdateItem ALL_NEW: expected {expected!r}, got {updated!r}"
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert _norm(got) == _norm(expected), f"GetItem after UpdateItem: expected {expected!r}, got {got!r}"

    assert table in [n for page in ddb.get_paginator('list_tables').paginate() for n in page.get('TableNames', [])], f"table {table} not listed by ListTables before the delete"
    ddb.delete_table(TableName=table)
    # Gone beat 1: DescribeTable reaches ResourceNotFoundException (the delete is asynchronous).
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as exc:
            if exc.response['Error']['Code'] != ERR_RESOURCE_NOT_FOUND:
                raise
            _assert_error(exc, (ERR_RESOURCE_NOT_FOUND,))
            message = exc.response['Error'].get('Message')
            assert message == f'Requested resource not found: Table: {table} not found', (
                f'DescribeTable on the deleted table: got the message {message!r}'
            )
            break
        if time.monotonic() > deadline:
            raise AssertionError(f'table {table} still describable after DeleteTable')
        time.sleep(1)

    # Gone beat 2: the paginated listing no longer contains the table.
    names = [n for page in ddb.get_paginator('list_tables').paginate() for n in page.get('TableNames', [])]
    assert table not in names, f"deleted table {table} still listed by ListTables"

    # Gone beat 3: a write to the dead table is refused, and so is a second delete.
    put_exc = _expect_error(lambda: ddb.put_item(TableName=table, Item={'id': {'S': nonce}}),
                            (ERR_RESOURCE_NOT_FOUND,))
    put_message = put_exc.response['Error'].get('Message')
    assert put_message == 'Requested resource not found', (
        f'PutItem on the deleted table: got the message {put_message!r}'
    )
    delete_exc = _expect_error(lambda: ddb.delete_table(TableName=table),
                               (ERR_RESOURCE_NOT_FOUND,))
    delete_message = delete_exc.response['Error'].get('Message')
    assert delete_message == f'Requested resource not found: Table: {table} not found', (
        f'a second DeleteTable: got the message {delete_message!r}'
    )


def _norm(value):
    """An item or attribute value with string and number sets as sets (DynamoDB keeps no set
    order); every other type, numbers included, compares exactly."""
    if isinstance(value, dict):
        return {k: (frozenset(v) if k in ('SS', 'NS', 'BS') else _norm(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_norm(v) for v in value]
    return value


def _safe_delete_table(ddb, table_name) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response['Error']['Code'] != ERR_RESOURCE_NOT_FOUND:
            raise


def _assert_error(exc, codes, *, status=400) -> None:
    """Grade a ClientError on code, HTTP status class (4xx vs 5xx), and a non-empty message."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    lo = status // 100 * 100
    assert isinstance(got_status, int) and lo <= got_status < lo + 100, (
        f"expected an HTTP {lo // 100}xx (AWS answers {status}) with {code}, got {got_status!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
