"""parallel-scan-segments-partition-the-table-exactly-once."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parallel-scan-segments-partition-the-table-exactly-once"
GROUP = 'scan'
SERVICES = ['dynamodb']

_ITEMS = 200
_TOTAL_SEGMENTS = 8
_MIN_POPULATED_SEGMENTS = 2      # not asserted: AWS documents no spread across segments
_FREEZE_READS = 3


def _client_error(fn):
    """Return the botocore Error dict for a call real AWS refuses.

    Raises on unexpected success, so accepting invalid input fails distinctly.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(
        f'real AWS refuses this Scan, but it SUCCEEDED and returned {result!r}'
    )


def _drain_batch(ddb, table, requests, *, timeout_s=180):
    """BatchWriteItem until UnprocessedItems is empty; raises if it never drains."""
    pending = {table: list(requests)}
    deadline = time.monotonic() + timeout_s
    while pending:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f'BatchWriteItem never drained UnprocessedItems within {timeout_s}s; '
                f'still pending {pending!r}'
            )
        pending = ddb.batch_write_item(RequestItems=pending).get('UnprocessedItems') or {}
        if pending:
            time.sleep(1.0)


def _scan_all(ddb, table, **extra):
    """Every pk a (possibly segmented) Scan returns, in arrival order, duplicates KEPT.

    A list, not a set: a target that ignores Segment returns the same item from several segments,
    and a set-union would hide that.
    """
    got: list[str] = []
    start: dict = {}
    while True:
        page = ddb.scan(TableName=table, ConsistentRead=True, **extra, **start)
        got += [item['pk']['S'] for item in page['Items']]
        if 'LastEvaluatedKey' not in page:
            return got
        start = {'ExclusiveStartKey': page['LastEvaluatedKey']}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A parallel Scan partitions the table: every item is returned by exactly one segment, the union
    equals an unsegmented Scan, re-reading a segment returns the same items, and
    Segment == TotalSegments is refused with ValidationException.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.ParallelScan
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-parscan-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real:managed', 'Value': 'true'},
              {'Key': 'sim2real:check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    written = [f'ITEM#{i:04d}' for i in range(_ITEMS)]
    for offset in range(0, _ITEMS, 25):
        _drain_batch(ddb, table, [
            {'PutRequest': {'Item': {'pk': {'S': pk}, 'payload': {'S': 'x' * 32}}}}
            for pk in written[offset:offset + 25]
        ])

    # --- reference: one unsegmented Scan sees everything. This is the positive control for the
    # --- per-segment absences below: if it were short, no segment claim would mean anything.
    baseline = _scan_all(ddb, table)
    assert sorted(baseline) == written, (
        f'an unsegmented strongly-consistent Scan must return the {_ITEMS!r} written items exactly '
        f'once; it returned {len(baseline)!r} items, symmetric difference '
        f'{sorted(set(baseline) ^ set(written))[:20]!r}'
    )

    # --- the partition claim ---
    per_segment = {
        seg: _scan_all(ddb, table, TotalSegments=_TOTAL_SEGMENTS, Segment=seg)
        for seg in range(_TOTAL_SEGMENTS)
    }
    flat = [pk for seg in range(_TOTAL_SEGMENTS) for pk in per_segment[seg]]

    duplicated = sorted({pk for pk in flat if flat.count(pk) > 1})
    assert not duplicated, (
        f'parallel Scan segments must be DISJOINT: {len(duplicated)!r} of {_ITEMS!r} items were '
        f'returned by more than one segment, e.g. {duplicated[:10]!r}. Per-segment counts '
        f'{ {s: len(v) for s, v in per_segment.items()} !r}'
    )
    assert len(flat) == _ITEMS, (
        f'parallel Scan segments must be EXHAUSTIVE: the {_TOTAL_SEGMENTS!r} segments returned '
        f'{len(flat)!r} items in total, expected exactly {_ITEMS!r}. Per-segment counts '
        f'{ {s: len(v) for s, v in per_segment.items()} !r}'
    )
    assert sorted(flat) == sorted(baseline), (
        f'the union of the segments must equal the unsegmented Scan; symmetric difference '
        f'{sorted(set(flat) ^ set(baseline))[:20]!r}'
    )
    populated = sorted(s for s, v in per_segment.items() if v)

    # --- a Scan is a read, so re-reading a segment must not move it ---
    probe_segment = populated[0]
    first = sorted(per_segment[probe_segment])
    for attempt in range(_FREEZE_READS):
        again = sorted(_scan_all(ddb, table, TotalSegments=_TOTAL_SEGMENTS,
                                Segment=probe_segment))
        assert again == first, (
            f'Scan is a read and must not advance any server-side cursor: repeat {attempt + 1!r} '
            f'of segment {probe_segment!r} returned {len(again)!r} items, expected the same '
            f'{len(first)!r}; symmetric difference {sorted(set(again) ^ set(first))[:10]!r}'
        )

    # --- always-invalid input: Segment must be < TotalSegments. No restore leg exists by
    # --- construction, so the positive control is the identical call one index lower.
    highest_valid = _scan_all(ddb, table, TotalSegments=_TOTAL_SEGMENTS,
                              Segment=_TOTAL_SEGMENTS - 1)
    assert sorted(highest_valid) == sorted(per_segment[_TOTAL_SEGMENTS - 1]), (
        f'positive control: Segment={_TOTAL_SEGMENTS - 1!r} with TotalSegments='
        f'{_TOTAL_SEGMENTS!r} must be a valid, repeatable request; got {len(highest_valid)!r} '
        f'items vs {len(per_segment[_TOTAL_SEGMENTS - 1])!r} earlier'
    )
    err = _client_error(lambda: ddb.scan(
        TableName=table, ConsistentRead=True,
        TotalSegments=_TOTAL_SEGMENTS, Segment=_TOTAL_SEGMENTS,
    ))
    assert err.get('Code') == 'ValidationException', (
        f'Segment must be less than TotalSegments, so Segment={_TOTAL_SEGMENTS!r} with '
        f'TotalSegments={_TOTAL_SEGMENTS!r} must be refused with ValidationException; got '
        f'{err.get("Code")!r} / {err.get("Message")!r}'
    )
    expected = 'The Segment parameter is zero-based and must be less than parameter TotalSegments'
    assert err.get('Message') == expected, (
        f'expected message {expected!r}, got {err.get("Message")!r}'
    )
    # Effect-absent: the refusal read nothing, so the table is untouched and the valid call still
    # returns the same partition.
    after = _scan_all(ddb, table)
    assert sorted(after) == written, (
        f'a refused Scan must not change the table; an unsegmented Scan now returns '
        f'{len(after)!r} items, expected {_ITEMS!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
