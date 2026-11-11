"""binary-range-key-item-set-and-nested-path-updates-then-table-refuses-reads."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "binary-range-key-item-set-and-nested-path-updates-then-table-refuses-reads"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
ERR_RESOURCE_NOT_FOUND = 'ResourceNotFoundException'
#: Bound on each asynchronous table transition; below the harness ceiling.
POLL_BUDGET_S = 40.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A provisioned N-hash/B-range table reports its schema and capacity; an item of sets, empty and
    nested values round-trips, set ADD/DELETE, nested SET/REMOVE and list_append apply with exact
    UPDATED_NEW/UPDATED_OLD answers; the deleted table refuses reads, queries and updates.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'tenant', 'KeyType': 'HASH'},
                   {'AttributeName': 'blob', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'tenant', 'AttributeType': 'N'},
                              {'AttributeName': 'blob', 'AttributeType': 'B'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 2, 'WriteCapacityUnits': 3},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table))
    _wait_table_active(ddb, table)
    desc = ddb.describe_table(TableName=table)['Table']
    assert desc['TableStatus'] == 'ACTIVE', f"expected TableStatus ACTIVE, got {desc['TableStatus']!r}"
    key_schema = [(ks['AttributeName'], ks['KeyType']) for ks in desc['KeySchema']]
    assert key_schema == [('tenant', 'HASH'), ('blob', 'RANGE')], f"unexpected key schema {key_schema!r}"
    attrs = {a['AttributeName']: a['AttributeType'] for a in desc['AttributeDefinitions']}
    assert attrs == {'tenant': 'N', 'blob': 'B'}, f"unexpected attribute definitions {attrs!r}"
    thr = desc['ProvisionedThroughput']
    assert (thr['ReadCapacityUnits'], thr['WriteCapacityUnits']) == (2, 3), (
        f"expected provisioned 2 read / 3 write units, got {thr!r}"
    )

    key = {'tenant': {'N': '42'}, 'blob': {'B': b'\x00\x01\xfe' + ctx.unique_name('k-').encode()}}
    item = {
        **key,
        's': {'S': ''},
        'small': {'N': '-0.000123'},
        'ns': {'NS': ['1', '2.5', '-3']},
        'bs': {'BS': [b'a', b'\xff\x00']},
        'ss': {'SS': ['é', 'z']},
        'el': {'L': []},
        'em': {'M': {}},
        'deep': {'M': {'tags': {'L': [{'S': 't0'}, {'S': 't1'}]}, 'n': {'N': '1'}}},
        'flag': {'BOOL': False},
    }
    ddb.put_item(TableName=table, Item=item)
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert _norm(got) == _norm(item), f"expected the typed item back, got {got!r}"

    # Set union and difference, a nested counter, a nested list element removal and an append to
    # an empty list; UPDATED_NEW reports only the touched attributes after the update.
    new = ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression=('SET deep.n = deep.n + :two, el = list_append(el, :more), s = :s '
                          'REMOVE deep.tags[0] ADD ns :ns2, ss :ss2 DELETE bs :bs1'),
        ExpressionAttributeValues={
            ':two': {'N': '2'}, ':more': {'L': [{'N': '7'}, {'NULL': True}]}, ':s': {'S': 'filled'},
            ':ns2': {'NS': ['2.5', '10']}, ':ss2': {'SS': ['a']}, ':bs1': {'BS': [b'a']},
        },
        ReturnValues='UPDATED_NEW',
    ).get('Attributes')
    want_new = {
        'deep': {'M': {'n': {'N': '3'}, 'tags': {'L': [{'S': 't1'}]}}},
        'el': {'L': [{'N': '7'}, {'NULL': True}]},
        's': {'S': 'filled'},
        'ns': {'NS': ['1', '2.5', '-3', '10']},
        'ss': {'SS': ['é', 'z', 'a']},
        'bs': {'BS': [b'\xff\x00']},
    }
    assert _norm(new) == _norm(want_new), f"UpdateItem UPDATED_NEW: expected {want_new!r}, got {new!r}"

    old = ddb.update_item(
        TableName=table, Key=key, UpdateExpression='REMOVE flag, ss',
        ReturnValues='UPDATED_OLD',
    ).get('Attributes')
    want_old = {'flag': {'BOOL': False}, 'ss': {'SS': ['é', 'z', 'a']}}
    assert _norm(old) == _norm(want_old), f"UpdateItem UPDATED_OLD: expected {want_old!r}, got {old!r}"

    expected = {k: v for k, v in item.items() if k not in ('flag', 'ss', 'deep')}
    expected.update({'deep': want_new['deep'], 'el': want_new['el'], 's': want_new['s'],
                     'ns': want_new['ns'], 'bs': want_new['bs']})
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert _norm(got) == _norm(expected), f"GetItem after the updates: expected {expected!r}, got {got!r}"

    ddb.delete_table(TableName=table)
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            last = ddb.describe_table(TableName=table)['Table']['TableStatus']
        except ClientError as exc:
            if exc.response['Error']['Code'] != ERR_RESOURCE_NOT_FOUND:
                raise
            message = exc.response['Error'].get('Message')
            assert message == f'Requested resource not found: Table: {table} not found', (
                f'DescribeTable on the deleted table: got the message {message!r}'
            )
            break
        if time.monotonic() > deadline:
            raise AssertionError(f'table {table} still describable after DeleteTable; last TableStatus {last!r}')
        time.sleep(1)

    names = [n for page in ddb.get_paginator('list_tables').paginate() for n in page.get('TableNames', [])]
    assert table not in names, f"deleted table {table} still listed by ListTables"
    get_exc = _expect_error(lambda: ddb.get_item(TableName=table, Key=key, ConsistentRead=True),
                            (ERR_RESOURCE_NOT_FOUND,))
    get_message = get_exc.response['Error'].get('Message')
    assert get_message == 'Requested resource not found', (
        f'GetItem on the deleted table: got the message {get_message!r}'
    )
    query_exc = _expect_error(
        lambda: ddb.query(TableName=table, KeyConditionExpression='tenant = :t',
                          ExpressionAttributeValues={':t': {'N': '42'}}),
        (ERR_RESOURCE_NOT_FOUND,))
    query_message = query_exc.response['Error'].get('Message')
    assert query_message == 'Requested resource not found', (
        f'Query on the deleted table: got the message {query_message!r}'
    )
    update_exc = _expect_error(
        lambda: ddb.update_item(TableName=table, Key=key, UpdateExpression='SET s = :s',
                                ExpressionAttributeValues={':s': {'S': 'after-delete'}}),
        (ERR_RESOURCE_NOT_FOUND,))
    update_message = update_exc.response['Error'].get('Message')
    assert update_message == 'Requested resource not found', (
        f'UpdateItem on the deleted table: got the message {update_message!r}'
    )


def _norm(value):
    """An item or attribute value with string, number and binary sets as sets (DynamoDB keeps no
    set order); every other type, numbers included, compares exactly.
    """
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
