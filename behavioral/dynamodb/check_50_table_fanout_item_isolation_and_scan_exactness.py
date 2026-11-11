"""50-table-fanout-item-isolation-and-scan-exactness."""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "50-table-fanout-item-isolation-and-scan-exactness"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

_N = 50
_WORKERS = 25
_DUPES = 10
_PAGE = 10
_KEY = {'pk': {'S': 'ITEM'}}          # deliberately IDENTICAL in all 51 tables
_RESIDUAL_DEADLINE_S = 300.0
_ACTIVE_WAIT_S = 300.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_active(ctx, ddb, name):
    """Poll DescribeTable every second until the table is ACTIVE, bounded by the budget."""
    bound = _budget_s(ctx, _ACTIVE_WAIT_S)
    deadline = time.monotonic() + bound
    status = None
    while True:
        try:
            status = ddb.describe_table(TableName=name)['Table']['TableStatus']
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
                raise
            status = None
        if status == 'ACTIVE':
            return
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f'{name} ACTIVE: the run budget ended first; not graded')
        assert time.monotonic() < deadline, (
            f'{name} did not reach ACTIVE within {bound:.0f}s (last status {status!r})'
        )
        time.sleep(1.0)


def _error(fn, what):
    """Return the (Code, Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'{what} succeeded; real AWS refuses it')


def _drop_table(ddb, name):
    """Delete a table, tolerating only an already-absent one."""
    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Fifty concurrently created tables each hold one item under the SAME key, read back only from
    its own table with Scan Count == ScannedCount == 1; duplicate creates and post-delete calls fail
    Item storage must be keyed by (TableName, key), not by key alone.
    """
    # ItemCount is refreshed only about every six hours, so it is never asserted.
    ddb = ctx.client('dynamodb', config=Config(max_pool_connections=_WORKERS + 16,
                                               retries={'mode': 'standard', 'max_attempts': 5}))
    stem = ctx.unique_name('sim2real-behav-d1-tbl-')

    def _make(name: str) -> None:
        ddb.create_table(
            TableName=name,
            KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
            Tags=[{'Key': 'sim2real', 'Value': 'd1-table-fanout'}],
        )
        ctx.on_cleanup(lambda n=name: _drop_table(ddb, n))

    # A table that exists before the fan-out and must be untouched by it.
    sentinel = f'{stem}-sentinel'
    _make(sentinel)
    _await_active(ctx, ddb, sentinel)
    ddb.put_item(TableName=sentinel, Item={**_KEY, 'blob': {'B': b'SENTINEL'}})

    tables = [f'{stem}-{i:02d}' for i in range(_N)]
    blobs = {t: os.urandom(256) for t in tables}

    def _create(name: str) -> tuple[str, str | None, str | None]:
        try:
            resp = ddb.create_table(
                TableName=name,
                KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                BillingMode='PAY_PER_REQUEST',
                Tags=[{'Key': 'sim2real', 'Value': 'd1-table-fanout'}],
            )
            ctx.on_cleanup(lambda n=name: _drop_table(ddb, n))
            return name, resp['TableDescription']['TableArn'], None
        except ClientError as exc:
            return name, None, f'{name}: {exc.response.get("Error", {}).get("Code")}'

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        creates = list(pool.map(_create, tables))
    failed = [e for _, _, e in creates if e is not None]
    assert failed == [], f'CreateTable failed for {len(failed)} of {_N}: {failed!r}'
    arns = [a for _, a, _ in creates]
    assert len(set(arns)) == _N, (
        f'{_N!r} CreateTable calls returned only {len(set(arns))!r} distinct TableArns: '
        f'{sorted(a for a in set(arns))[:3]!r}'
    )
    for name, arn, _ in creates:
        assert arn.endswith('/' + name), f'{name!r} was given the arn {arn!r}'

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        list(pool.map(lambda t: _await_active(ctx, ddb, t), tables))
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        states = dict(zip(tables, pool.map(
            lambda t: ddb.describe_table(TableName=t)['Table']['TableStatus'], tables)))
    assert states == {t: 'ACTIVE' for t in tables}, (
        'a table did not reach ACTIVE: ' + repr({t: s for t, s in states.items() if s != 'ACTIVE'})
    )

    def _put(name: str) -> None:
        ddb.put_item(TableName=name,
                     Item={**_KEY, 'blob': {'B': blobs[name]},
                           'idx': {'N': str(tables.index(name))}})

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        list(pool.map(_put, tables))

    def _read(name: str) -> tuple[str, bytes, str, int, int]:
        item = ddb.get_item(TableName=name, Key=_KEY, ConsistentRead=True)['Item']
        scan = ddb.scan(TableName=name, ConsistentRead=True)
        return (name, item['blob']['B'], item['idx']['N'], scan['Count'], scan['ScannedCount'])

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        reads = list(pool.map(_read, tables))

    read_map = {n: b for n, b, _, _, _ in reads}
    assert read_map == blobs, (
        'the item read back from a table is not the item written to it: '
        + repr({t: (blobs[t][:8], read_map[t][:8]) for t in tables if read_map[t] != blobs[t]})
    )
    for name, blob, idx, count, scanned in reads:
        assert isinstance(blob, bytes) and len(blob) == 256, (
            f'{name}: the Binary attribute round-tripped as {type(blob).__name__} of '
            f'{len(blob)!r} bytes, expected 256 bytes'
        )
        assert idx == str(tables.index(name)), (
            f'{name}: idx reads {idx!r}, expected {str(tables.index(name))!r}'
        )
        assert count == 1, (
            f'{name}: Scan reports Count {count!r}, expected 1 -- {_N!r} tables were each written '
            f'exactly one item, so any other number means the item store is shared'
        )
        assert scanned == 1, (
            f'{name}: Scan reports ScannedCount {scanned!r} against Count {count!r}, expected 1'
        )

    sent = ddb.scan(TableName=sentinel, ConsistentRead=True)
    assert sent['Count'] == 1 and sent['ScannedCount'] == 1, (
        f'the sentinel table reports Count {sent["Count"]!r} / ScannedCount '
        f'{sent["ScannedCount"]!r} after the fan-out, expected 1 / 1'
    )
    assert sent['Items'][0]['blob']['B'] == b'SENTINEL', (
        f'the sentinel item now holds {sent["Items"][0]["blob"]["B"][:16]!r}'
    )

    def _walk() -> tuple[list[str], int]:
        names, start, pages = [], None, 0
        while True:
            kw = {'Limit': _PAGE}
            if start:
                kw['ExclusiveStartTableName'] = start
            resp = ddb.list_tables(**kw)
            page = resp['TableNames']
            assert len(page) <= _PAGE, (
                f'ListTables returned {len(page)!r} names for Limit={_PAGE!r}'
            )
            names += page
            pages += 1
            start = resp.get('LastEvaluatedTableName')
            if not start:
                return names, pages

    walk, pages = _walk()
    assert len(walk) == len(set(walk)), (
        f'the paginated ListTables walk repeated a name -- ExclusiveStartTableName is not a cursor: '
        f'{sorted({n for n in walk if walk.count(n) > 1})!r}'
    )
    missing = sorted(({sentinel} | set(tables)) - set(walk))
    assert missing == [], (
        f'the ListTables walk of {len(walk)!r} names over {pages!r} pages omits {missing!r}'
    )
    assert pages >= 5, (
        f'Limit={_PAGE!r} over {len(walk)!r} tables produced only {pages!r} page(s); Limit was '
        f'ignored, so the walk was never a paginated walk'
    )

    dupes = tables[:_DUPES]
    with ThreadPoolExecutor(max_workers=_DUPES) as pool:
        codes = list(pool.map(lambda t: _error(lambda: ddb.create_table(
            TableName=t,
            KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'), f'CreateTable on the existing name {t!r}'), dupes))
    expected_dupes = [('ResourceInUseException', f'Table already exists: {t}') for t in dupes]
    assert codes == expected_dupes, (
        f'concurrent CreateTable on names that already exist returned {codes!r}, expected '
        f'{expected_dupes!r}'
    )
    with ThreadPoolExecutor(max_workers=_DUPES) as pool:
        after = dict(zip(dupes, pool.map(
            lambda t: ddb.scan(TableName=t, ConsistentRead=True), dupes)))
    for name, scan in after.items():
        assert scan['Count'] == 1, (
            f'{name}: the rejected CreateTable emptied or duplicated the table -- Count is now '
            f'{scan["Count"]!r}'
        )
        assert scan['Items'][0]['blob']['B'] == blobs[name], (
            f'{name}: the rejected CreateTable replaced the item blob'
        )

    def _rm(name: str) -> str | None:
        try:
            ddb.delete_table(TableName=name)
            return None
        except ClientError as exc:
            return f'{name}: {exc.response.get("Error", {}).get("Code")}'

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        undeleted = [e for e in pool.map(_rm, tables) if e is not None]
    assert undeleted == [], f'DeleteTable failed for: {undeleted!r}'

    def _still(name: str) -> bool:
        try:
            ddb.describe_table(TableName=name)
            return True
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            message = exc.response.get('Error', {}).get('Message')
            assert code == 'ResourceNotFoundException', (
                f'{name}: DescribeTable after DeleteTable returned {code!r}, expected '
                f'ResourceNotFoundException'
            )
            expected_msg = f'Requested resource not found: Table: {name} not found'
            assert message == expected_msg, (
                f'{name}: DescribeTable after DeleteTable said {message!r}, expected {expected_msg!r}'
            )
            return False

    # DeleteTable is asynchronous; poll DescribeTable to a hard deadline.
    bound = _budget_s(ctx, _RESIDUAL_DEADLINE_S)
    deadline = time.monotonic() + bound
    while True:
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            alive = [t for t, up in zip(tables, pool.map(_still, tables)) if up]
        if not alive:
            break
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError('the deleted tables leaving DescribeTable: the run budget ended first; not graded')
        assert time.monotonic() < deadline, (
            f'{len(alive)!r} of {_N!r} tables still answer DescribeTable '
            f'{bound:.0f}s after DeleteTable: {sorted(alive)!r}'
        )
        time.sleep(1.0)

    final, _ = _walk()
    still = sorted(set(tables) & set(final))
    assert still == [], f'ListTables still lists deleted tables: {still!r}'
    assert sentinel in final, (
        f'the sentinel table vanished from ListTables while the fan-out was deleted -- the delete '
        f'reached beyond the {_N!r} named tables'
    )

    dead_code, dead_msg = _error(lambda: ddb.put_item(
        TableName=tables[0], Item={**_KEY, 'blob': {'B': b'DEAD'}}),
        f'PutItem against deleted table {tables[0]!r}')
    assert dead_code == 'ResourceNotFoundException', (
        f'PutItem against deleted table {tables[0]!r} returned {dead_code!r}, expected '
        f'ResourceNotFoundException'
    )
    assert dead_msg == 'Requested resource not found', (
        f'PutItem against deleted table {tables[0]!r} said {dead_msg!r}, expected '
        f"'Requested resource not found'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
