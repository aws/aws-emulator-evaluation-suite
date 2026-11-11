"""ttl-expired-item-auto-deletion."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ttl-expired-item-auto-deletion"
GROUP = 'ttl'
SERVICES = ['dynamodb']

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


#: The fixed best-effort window in which the TTL background sweep is watched.
_SWEEP_WINDOW_S = 20.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description='condition', ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f'{description}: the run budget ended first; not graded')
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _retry_on_code(fn, *, retry_codes, timeout_s, interval_s, description):
    """Call fn() until it succeeds, retrying ClientErrors whose code is in retry_codes."""
    def _attempt():
        try:
            return ('ok', fn())
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code not in retry_codes:
                raise
            return ('retry', None)

    outcome = _poll_until(
        _attempt,
        lambda r: r[0] == 'ok',
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )
    return outcome[1]


def _describe_ttl(ddb, table_name):
    """DescribeTimeToLive, retrying ThrottlingException (the API has a low account-level rate)."""
    return _retry_on_code(
        lambda: ddb.describe_time_to_live(TableName=table_name)['TimeToLiveDescription'],
        retry_codes=('ThrottlingException',),
        timeout_s=30,
        interval_s=3.0,
        description=f'describe_time_to_live({table_name}) past transient throttling',
    )


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With TTL enabled, an already-expired item stays readable via GetItem and Scan until the
    background sweep runs; a time FilterExpression hides it, and a sweep never deletes a live item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/howitworks-ttl.html
    """
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=name, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=_TAGS_KV)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.update_time_to_live(TableName=name, TimeToLiveSpecification={'Enabled': True, 'AttributeName': 'expiresAt'})
    _poll_until(
        lambda: _describe_ttl(ddb, name),
        lambda d: d.get('TimeToLiveStatus') in ('ENABLED', 'ENABLING'),
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=2.0,
        description='TTL enabled on table',
        ctx=ctx,
    )

    now = int(time.time())
    expired_key = {'pk': {'S': 'ttl-expired-item'}}
    live_key = {'pk': {'S': 'ttl-live-item'}}
    ddb.put_item(TableName=name, Item={**expired_key, 'expiresAt': {'N': str(now - 3600)}, 'payload': {'S': 'x'}})
    ddb.put_item(TableName=name, Item={**live_key, 'expiresAt': {'N': str(now + 3600 * 24 * 30)}, 'payload': {'S': 'x'}})

    # TTL deletion is an asynchronous sweep, not a read-time filter.
    still_there = ddb.get_item(TableName=name, Key=expired_key, ConsistentRead=True)
    assert 'Item' in still_there, 'an expired item must remain readable until the TTL sweep runs'
    assert still_there['Item']['payload'] == {'S': 'x'}, still_there['Item']

    plain_scan = ddb.scan(TableName=name, ConsistentRead=True)
    scanned_pks = {it['pk']['S'] for it in plain_scan['Items']}
    assert {'ttl-expired-item', 'ttl-live-item'} <= scanned_pks, (
        'a plain Scan must still surface an expired-but-undeleted item'
    )

    # AWS's own guidance for hiding not-yet-deleted expired items from reads is
    # a caller-side FilterExpression against the current time.
    filtered_scan = ddb.scan(
        TableName=name,
        FilterExpression='expiresAt > :now',
        ExpressionAttributeValues={':now': {'N': str(now)}},
        ConsistentRead=True,
    )
    filtered_pks = {it['pk']['S'] for it in filtered_scan['Items']}
    assert 'ttl-expired-item' not in filtered_pks, filtered_pks
    assert 'ttl-live-item' in filtered_pks, filtered_pks

    # Best-effort: AWS deletes expired items "within a few days", so the sweep is not asserted.
    # The predicate folds in the deadline so _poll_until returns instead of raising.
    deadline = time.monotonic() + _SWEEP_WINDOW_S

    def _sweep_probe():
        expired_now = ddb.get_item(TableName=name, Key=expired_key, ConsistentRead=True)
        return ('Item' not in expired_now, time.monotonic() >= deadline)

    swept, _ = _poll_until(
        _sweep_probe,
        lambda r: r[0] or r[1],
        timeout_s=150,
        interval_s=2.0,
        description='best-effort observation window for the TTL background sweep',
    )
    if swept:
        live_now = ddb.get_item(TableName=name, Key=live_key, ConsistentRead=True)
        assert 'Item' in live_now, 'TTL sweep must not delete an item whose TTL has not yet passed'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
