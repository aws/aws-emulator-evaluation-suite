"""batch-write-item-throttle-accounting-loses-no-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-throttle-accounting-loses-no-key"
GROUP = 'batch'
SERVICES = ['dynamodb']

_PER_BATCH = 25                  # a fixed API constant
# Burst/adaptive capacity absorbs a few hundred writes at 1 WCU; 8,000 throttles reliably.
_BATCHES = 320
_TOTAL = _PER_BATCH * _BATCHES
_THROTTLE_MSG = ('The level of configured provisioned throughput for the table was exceeded. '
                 'Consider increasing your provisioning level with the UpdateTable API.')
_PAYLOAD = 'x' * 900             # ≈1 KB item -> 1 write unit
_DRAIN_BUDGET_S = 600
_TABLE_ACTIVE_BUDGET_S = 300


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate holds. RAISES on timeout -- never returns the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _item(pk):
    return {'pk': {'S': pk}, 'payload': {'S': _PAYLOAD}}


def _requests(pks):
    return [{'PutRequest': {'Item': _item(pk)}} for pk in pks]


def _scan_pks(ddb, table):
    """Every pk currently in the table, via a paginated strongly-consistent Scan."""
    got: list[str] = []
    start: dict = {}
    while True:
        page = ddb.scan(TableName=table, ConsistentRead=True,
                        ProjectionExpression='pk', **start)
        got += [i['pk']['S'] for i in page['Items']]
        if 'LastEvaluatedKey' not in page:
            return got
        start = {'ExclusiveStartKey': page['LastEvaluatedKey']}


def _create_table(ctx, purpose, throughput=None):
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name(f'sim2real-behav-bwthrottle-{purpose}-')
    params = {
        'TableName': name,
        'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'}],
        'Tags': [{'Key': 'sim2real:managed', 'Value': 'true'},
                 {'Key': 'sim2real:check', 'Value': CHECK}],
    }
    if throughput is None:
        params['BillingMode'] = 'PAY_PER_REQUEST'
    else:
        params['BillingMode'] = 'PROVISIONED'
        params['ProvisionedThroughput'] = throughput
    ddb.create_table(**params)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """At 1 WCU, BatchWriteItem returns partial 200s whose UnprocessedItems plus the table contents
    partition the request exactly, and raising the write budget lands precisely the withheld keys.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchWriteItem.html
    """
    ddb = ctx.client('dynamodb')

    # --- positive control FIRST: the batch shape itself is well formed and, given capacity, is
    # --- accepted whole in one call. Without this, a residue below proves nothing about capacity.
    control = _create_table(ctx, 'control')
    control_pks = [f'CTRL#{i:04d}' for i in range(_PER_BATCH)]
    control_resp = ddb.batch_write_item(RequestItems={control: _requests(control_pks)})
    control_residue = control_resp.get('UnprocessedItems') or {}
    assert not control_residue, (
        f'positive control: a {_PER_BATCH!r}-item BatchWriteItem against a PAY_PER_REQUEST table '
        f'must be accepted whole in one call, got residue {control_residue!r}'
    )
    assert sorted(_scan_pks(ddb, control)) == control_pks, (
        f'positive control: all {_PER_BATCH!r} control items must be readable, got '
        f'{sorted(_scan_pks(ddb, control))!r}'
    )

    # --- the subject: the same shape, one thing broken -- a 1-unit write budget.
    # ReadCapacityUnits is generous so the strongly-consistent verification Scan over _TOTAL items
    # is not itself throttled.
    subject = _create_table(ctx, 'subject', throughput={
        'ReadCapacityUnits': 2000, 'WriteCapacityUnits': 1,
    })

    requested = [f'ITEM#{i:04d}' for i in range(_TOTAL)]
    reported_back: set[str] = set()
    partial_200s = 0
    all_refused_exceptions = 0
    for batch_index in range(_BATCHES):
        chunk = requested[batch_index * _PER_BATCH:(batch_index + 1) * _PER_BATCH]
        try:
            resp = ddb.batch_write_item(RequestItems={subject: _requests(chunk)})
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            assert code == 'ProvisionedThroughputExceededException', (
                f'batch {batch_index!r}: when NO item in a BatchWriteItem can be processed for want '
                f'of provisioned throughput, the documented failure is '
                f'ProvisionedThroughputExceededException, got {code!r} / '
                f'{exc.response.get("Error", {}).get("Message")!r}'
            )
            message = exc.response.get('Error', {}).get('Message')
            assert message == _THROTTLE_MSG, (
                f'batch {batch_index!r}: ProvisionedThroughputExceededException carried the message '
                f'{message!r}, expected {_THROTTLE_MSG!r}'
            )
            all_refused_exceptions += 1
            reported_back.update(chunk)
            continue
        residue = [r['PutRequest']['Item']['pk']['S']
                   for r in (resp.get('UnprocessedItems') or {}).get(subject, [])]
        assert len(residue) < _PER_BATCH, (
            f'batch {batch_index!r}: a 200 response must be a PARTIAL success -- the all-refused '
            f'case is documented to raise ProvisionedThroughputExceededException instead -- so '
            f'UnprocessedItems must be a strict subset of the {_PER_BATCH!r} requests, got '
            f'{len(residue)!r}'
        )
        if residue:
            partial_200s += 1
        reported_back.update(residue)

    # --- the accounting must close, and it must close on a strongly consistent read of the table
    # --- rather than on anything the mutating calls said about themselves.
    landed = _scan_pks(ddb, subject)
    assert len(landed) == len(set(landed)), (
        f'the table reported {len(landed)!r} rows with only {len(set(landed))!r} distinct keys, so '
        f'the Scan itself is duplicating and nothing below can be trusted'
    )
    landed_set = set(landed)
    assert len(landed_set) < _TOTAL, (
        f'a 1-unit provisioned write budget must not absorb {_TOTAL!r} ~1 KB writes issued back to '
        f'back: {len(landed_set)!r} of {_TOTAL!r} landed, with {len(reported_back)!r} keys reported '
        f'as unprocessed across {partial_200s!r} partial 200s and {all_refused_exceptions!r} '
        f'all-refused exceptions -- i.e. this target enforced no write capacity at all'
    )
    silently_lost = sorted(set(requested) - landed_set - reported_back)
    assert not silently_lost, (
        f'{len(silently_lost)!r} keys were neither written nor reported back, so a caller draining '
        f'UnprocessedItems would lose them for good; e.g. {silently_lost[:10]!r}'
    )
    written_but_reported = sorted(landed_set & reported_back)
    assert not written_but_reported, (
        f'{len(written_but_reported)!r} keys were reported as UNPROCESSED and are nevertheless in '
        f'the table, so a caller retrying the residue would double-apply them; e.g. '
        f'{written_but_reported[:10]!r}'
    )
    assert landed_set | reported_back == set(requested), (
        f'the two sets must partition the request exactly: landed {len(landed_set)!r} + reported '
        f'{len(reported_back)!r} != requested {_TOTAL!r}; extras '
        f'{sorted((landed_set | reported_back) - set(requested))[:10]!r}'
    )

    # --- repair the ONE broken thing and demand the withheld writes ---
    ddb.update_table(TableName=subject, ProvisionedThroughput={
        'ReadCapacityUnits': 2000, 'WriteCapacityUnits': 500,
    })
    _poll_until(
        lambda: ddb.describe_table(TableName=subject)['Table'],
        lambda t: (t['TableStatus'] == 'ACTIVE'
                   and t['ProvisionedThroughput']['WriteCapacityUnits'] == 500),
        timeout_s=_TABLE_ACTIVE_BUDGET_S,
        interval_s=5.0,
        description='the raised write budget to be ACTIVE, so the withheld writes can be demanded',
    )
    outstanding = sorted(reported_back)
    deadline = time.monotonic() + _DRAIN_BUDGET_S
    backoff = 1.0
    while outstanding:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f'after raising the write budget to 500 units, {len(outstanding)!r} of the '
                f'{len(reported_back)!r} withheld keys still would not write within '
                f'{_DRAIN_BUDGET_S!r}s; e.g. {outstanding[:10]!r}'
            )
        chunk, outstanding = outstanding[:_PER_BATCH], outstanding[_PER_BATCH:]
        residue = (ddb.batch_write_item(RequestItems={subject: _requests(chunk)})
                   .get('UnprocessedItems') or {}).get(subject, [])
        if residue:
            outstanding = [r['PutRequest']['Item']['pk']['S'] for r in residue] + outstanding
            time.sleep(backoff)
            backoff = min(backoff * 2, 8.0)

    final = _scan_pks(ddb, subject)
    assert sorted(final) == requested, (
        f'once the write budget is raised, the identical BatchWriteItem calls must land exactly the '
        f'{_TOTAL!r} requested keys and nothing else: the table holds {len(final)!r}, symmetric '
        f'difference {sorted(set(final) ^ set(requested))[:10]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
