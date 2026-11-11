"""concurrent-scheduled-action-puts-on-one-target-are-all-stored."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-scheduled-action-puts-on-one-target-are-all-stored"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_READ = 'dynamodb:table:ReadCapacityUnits'
_COUNT = 12


def _actions(aas, rid):
    out = []
    for page in aas.get_paginator('describe_scheduled_actions').paginate(
            ServiceNamespace=_NS, ResourceId=rid, ScalableDimension=_READ):
        out.extend(page['ScheduledActions'])
    return out


@tags('axis:happy-path', 'cap:c1', 'cap:c6', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """Twelve concurrent PutScheduledAction calls with distinct names on one target, retried on
    ConcurrentUpdateException, all succeed and all twelve are stored with their own schedule and
    bounds; none is lost to a concurrent write.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    name = ctx.unique_name('sim2real-behav-aas-cc-sa-')
    _table(ctx, ddb, name)
    rid = f'table/{name}'
    # Deregistering the target deletes its scheduled actions, so the target's cleanup covers it.
    _register(ctx, aas, rid, _READ, 1, 20)
    base = ctx.unique_name('sim2real-behav-aas-cc-sa-')
    wanted = {f'{base}-{i:02d}': (f'cron(0 {i} 1 1 ? *)', i + 1) for i in range(_COUNT)}

    retry_s = _budget_s(ctx, 30.0)

    # AWS serializes updates per target and answers an overlapping one with
    # ConcurrentUpdateException, so a collision is retried; only a lost write is a mismatch.
    def put(item):
        action, (schedule, low) = item
        deadline = time.monotonic() + retry_s
        attempt = 0
        while True:
            try:
                aas.put_scheduled_action(
                    ServiceNamespace=_NS, ResourceId=rid, ScalableDimension=_READ,
                    ScheduledActionName=action, Schedule=schedule,
                    ScalableTargetAction={'MinCapacity': low, 'MaxCapacity': 20})
                return action
            except ClientError as exc:
                if exc.response['Error']['Code'] != 'ConcurrentUpdateException':
                    raise
                if time.monotonic() >= deadline:
                    if _budget_spent(ctx):
                        raise TimeoutError(
                            'a concurrent put landing past ConcurrentUpdateException: the run '
                            'budget ended first; not graded') from exc
                    raise AssertionError(
                        f'a concurrent put exhausted its {retry_s:.0f}s ConcurrentUpdateException '
                        'retry budget without landing') from exc
                attempt += 1
                time.sleep(min(2.0, 0.2 * (2 ** attempt)) + 0.05 * low)

    with concurrent.futures.ThreadPoolExecutor(max_workers=_COUNT) as pool:
        done = sorted(pool.map(put, wanted.items()))
    assert done == sorted(wanted), f'{len(done)} of {_COUNT} concurrent puts returned'

    stored = {a['ScheduledActionName']: (a['Schedule'], a['ScalableTargetAction']['MinCapacity'])
              for a in _actions(aas, rid)}
    assert sorted(stored) == sorted(wanted), (
        f'{len(stored)} of {_COUNT} concurrently put actions are stored; missing '
        f'{sorted(set(wanted) - set(stored))!r}'.replace(base, '<base>'))
    wrong = {k.replace(base, '<base>'): v for k, v in stored.items() if v != wanted[k]}
    assert not wrong, f'actions stored with another call\'s schedule or bounds: {wrong!r}'


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    """Poll until predicate holds; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _table(ctx, ddb, name, *, read=1, write=1):
    """A PROVISIONED table ``name`` made through ``ddb``, ACTIVE, with its delete registered."""
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': read, 'WriteCapacityUnits': write},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, name))
    _poll_until(lambda: ddb.describe_table(TableName=name)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {name!r} becoming ACTIVE')


def _delete_table(ddb, name):
    deadline = time.monotonic() + 40
    while True:
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _deregister(aas, resource_id, dimension):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=dimension)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _register(ctx, aas, resource_id, dimension, low, high):
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=dimension, MinCapacity=low, MaxCapacity=high)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id, dimension))


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
