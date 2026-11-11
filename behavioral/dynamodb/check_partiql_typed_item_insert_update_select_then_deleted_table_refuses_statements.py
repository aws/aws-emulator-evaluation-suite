"""partiql-typed-item-insert-update-select-then-deleted-table-refuses-statements."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-typed-item-insert-update-select-then-deleted-table-refuses-statements"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
ERR_RESOURCE_NOT_FOUND = 'ResourceNotFoundException'
#: Bound on each asynchronous table transition; below the harness ceiling.
POLL_BUDGET_S = 40.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A typed item inserted by PartiQL reads back exactly through GetItem and SELECT, a second
    INSERT of its key is refused, UPDATE ... RETURNING ALL NEW applies SET/REMOVE on nested paths;
    the deleted table refuses SELECT and INSERT statements.
    """
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
    _wait_table_active(ddb, table)

    nonce = ctx.unique_name('doc-')
    item = {
        'id': {'S': nonce},
        'n': {'N': '-12.5'},
        'b': {'B': b'\x80\x00\xff'},
        'flag': {'BOOL': False},
        'nul': {'NULL': True},
        'l': {'L': [{'S': 'p'}, {'N': '0'}, {'M': {'x': {'S': 'y'}}}]},
        'm': {'M': {'sub': {'M': {'lvl': {'N': '2'}}}, 'k': {'S': 'v'}}},
        'ns': {'NS': ['4', '8']},
        'bs': {'BS': [b'\x01', b'\x02']},
    }
    order = list(item)
    ddb.execute_statement(
        Statement=f'INSERT INTO "{table}" VALUE {{' + ', '.join(f"'{k}': ?" for k in order) + '}',
        Parameters=[item[k] for k in order],
    )
    got = ddb.get_item(TableName=table, Key={'id': {'S': nonce}}, ConsistentRead=True).get('Item')
    assert _norm(got) == _norm(item), f"GetItem after the PartiQL INSERT: expected {item!r}, got {got!r}"

    dup = _expect_error(lambda: ddb.execute_statement(
        Statement=f'INSERT INTO "{table}" VALUE {{\'id\': ?, \'n\': ?}}',
        Parameters=[{'S': nonce}, {'N': '1'}]), ('DuplicateItemException',))
    dup_message = dup.response['Error'].get('Message')
    assert dup_message == 'Duplicate primary key exists in table', (
        f'a second INSERT of the same key: got the message {dup_message!r}'
    )

    updated = ddb.execute_statement(
        Statement=(f'UPDATE "{table}" SET n = n + ? SET m.sub.lvl = ? SET l[1] = ? '
                   f'REMOVE flag REMOVE l[2] WHERE id = ? RETURNING ALL NEW *'),
        Parameters=[{'N': '0.5'}, {'S': 'replaced'}, {'BOOL': True}, {'S': nonce}],
    )['Items']
    expected = {k: v for k, v in item.items() if k != 'flag'}
    expected['n'] = {'N': '-12'}
    expected['m'] = {'M': {'sub': {'M': {'lvl': {'S': 'replaced'}}}, 'k': {'S': 'v'}}}
    expected['l'] = {'L': [{'S': 'p'}, {'BOOL': True}]}
    assert [_norm(i) for i in updated] == [_norm(expected)], (
        f"UPDATE RETURNING ALL NEW: expected [{expected!r}], got {updated!r}"
    )
    selected = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE id = ?', Parameters=[{'S': nonce}],
        ConsistentRead=True,
    )['Items']
    assert [_norm(i) for i in selected] == [_norm(expected)], (
        f"SELECT after the UPDATE: expected [{expected!r}], got {selected!r}"
    )

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

    sel_exc = _expect_error(lambda: ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE id = ?', Parameters=[{'S': nonce}],
        ConsistentRead=True), (ERR_RESOURCE_NOT_FOUND,))
    sel_message = sel_exc.response['Error'].get('Message')
    assert sel_message == 'Requested resource not found', (
        f'SELECT on the deleted table: got the message {sel_message!r}'
    )
    ins_exc = _expect_error(lambda: ddb.execute_statement(
        Statement=f'INSERT INTO "{table}" VALUE {{\'id\': ?}}', Parameters=[{'S': nonce}]),
        (ERR_RESOURCE_NOT_FOUND,))
    ins_message = ins_exc.response['Error'].get('Message')
    assert ins_message == 'Requested resource not found', (
        f'INSERT on the deleted table: got the message {ins_message!r}'
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
