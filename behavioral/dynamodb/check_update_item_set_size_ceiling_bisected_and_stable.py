"""update-item-set-size-ceiling-bisected-and-stable."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-size-ceiling-bisected-and-stable"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

_SHORT_KEY = 'k'
_LONG_KEY = (
    'a_long_descriptive_partition_key_attribute_name_used_for_the_item_size_ceiling_probe'
)
_UPPER_BOUND = 410 * 1024


def _accepted(ddb, table: str, key_name: str, pk: str, clauses: int, n: int) -> bool:
    """True if an UpdateItem SET of *clauses* attribute(s), each an n-byte string, is accepted."""
    ddb.put_item(TableName=table, Item={key_name: {'S': pk}})
    if clauses == 1:
        expr = 'SET v = :v'
        values = {':v': {'S': 'x' * n}}
    else:
        expr = 'SET v1 = :v1, v2 = :v2'
        values = {':v1': {'S': 'x' * n}, ':v2': {'S': 'y' * n}}
    try:
        ddb.update_item(
            TableName=table, Key={key_name: {'S': pk}},
            UpdateExpression=expr, ExpressionAttributeValues=values,
        )
        return True
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') == ERR_VALIDATION:
            return False
        raise


def _bisect(ddb, table: str, key_name: str, clauses: int, pk_source) -> tuple[int, int]:
    """(largest accepted n, smallest refused n) for a SET of *clauses* n-byte value(s)."""
    lo, hi = 1, _UPPER_BOUND
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if _accepted(ddb, table, key_name, next(pk_source), clauses, mid):
            lo = mid
        else:
            hi = mid
    return lo, hi


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The UpdateItem SET size ceiling is a reproducible byte boundary that shifts with
    the primary key attribute's own name length and with the number of SET clauses, and
    that stays put when the same boundary is measured again.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client('dynamodb')

    short_table = ctx.unique_name('sim2real-behav-ceil-short-')
    long_table = ctx.unique_name('sim2real-behav-ceil-long-')
    for table, key_name in ((short_table, _SHORT_KEY), (long_table, _LONG_KEY)):
        ddb.create_table(
            TableName=table,
            KeySchema=[{'AttributeName': key_name, 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': key_name, 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
            Tags=[{'Key': 'sim2real', 'Value': CHECK}],
        )
        ctx.on_cleanup(lambda t=table: ddb.delete_table(TableName=t))
    waiter_config = {'Delay': 2, 'MaxAttempts': 30}
    ddb.get_waiter('table_exists').wait(TableName=short_table, WaiterConfig=waiter_config)
    ddb.get_waiter('table_exists').wait(TableName=long_table, WaiterConfig=waiter_config)

    combos = [
        ('short-1clause', short_table, _SHORT_KEY, 1),
        ('short-2clause', short_table, _SHORT_KEY, 2),
        ('long-1clause', long_table, _LONG_KEY, 1),
        ('long-2clause', long_table, _LONG_KEY, 2),
    ]

    # Every pk value used anywhere in this check is a fixed-width 8-digit counter, so the
    # key *value*'s own contribution to item size never confounds a boundary comparison.
    counter = iter(f'{i:08d}' for i in range(1, 100000))

    boundaries: dict[str, tuple[int, int]] = {}
    for label, table, key_name, clauses in combos:
        lo, hi = _bisect(ddb, table, key_name, clauses, counter)
        assert hi == lo + 1, f'{label}: bisection did not converge to adjacent bytes, got lo={lo} hi={hi}'
        floor = (300 * 1024) // clauses
        assert lo > floor, (
            f'{label}: accepted boundary is implausibly small ({lo} bytes, floor {floor}); the '
            'account may not be accepting ordinary UpdateItem calls at all'
        )
        boundaries[label] = (lo, hi)

    # Re-measure each boundary twice more: the accept/reject answer at the SAME byte count
    # must repeat, both at the largest accepted size and at the smallest refused one.
    for run_idx in range(2):
        for label, table, key_name, clauses in combos:
            lo, hi = boundaries[label]
            assert _accepted(ddb, table, key_name, next(counter), clauses, lo), (
                f'{label} re-measurement {run_idx}: the previously-accepted size {lo} is now refused'
            )
            assert not _accepted(ddb, table, key_name, next(counter), clauses, hi), (
                f'{label} re-measurement {run_idx}: the previously-refused size {hi} is now accepted'
            )

    # The long key name's own bytes count toward the 400 KB limit, so its ceiling is
    # strictly lower than the short key's, for both clause counts.
    assert boundaries['long-1clause'][0] < boundaries['short-1clause'][0], (
        f"long-key 1-clause boundary {boundaries['long-1clause'][0]} is not below "
        f"short-key 1-clause boundary {boundaries['short-1clause'][0]}"
    )
    assert boundaries['long-2clause'][0] < boundaries['short-2clause'][0], (
        f"long-key 2-clause boundary {boundaries['long-2clause'][0]} is not below "
        f"short-key 2-clause boundary {boundaries['short-2clause'][0]}"
    )

    # Splitting the same per-value growth across two SET clauses buys no extra room: the
    # limit is on the item's aggregate size, so the 2-clause per-value ceiling is roughly
    # half the 1-clause ceiling, not an independent 400 KB budget per clause.
    assert boundaries['short-2clause'][0] < boundaries['short-1clause'][0] / 1.5, (
        f"short-key 2-clause boundary {boundaries['short-2clause'][0]} is not roughly half of "
        f"the 1-clause boundary {boundaries['short-1clause'][0]}; two SET clauses may not be "
        "sharing one aggregate limit"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
