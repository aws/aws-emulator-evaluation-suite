"""describe-scheduled-actions-names-resource-and-dimension-intersect."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-scheduled-actions-names-resource-and-dimension-intersect"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_READ = 'dynamodb:table:ReadCapacityUnits'
_WRITE = 'dynamodb:table:WriteCapacityUnits'
_SCHEDULE = 'cron(0 3 1 1 ? *)'


def _actions(aas, **filters):
    out = []
    for page in aas.get_paginator('describe_scheduled_actions').paginate(ServiceNamespace=_NS,
                                                                         **filters):
        out.extend((a['ScheduledActionName'], a['ResourceId'], a['ScalableDimension'])
                   for a in page['ScheduledActions'])
    return sorted(out)


@tags('axis:happy-path', 'cap:c1', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """DescribeScheduledActions intersects ScheduledActionNames, ResourceId and ScalableDimension: each
    of five filter combinations over four actions on two tables returns exactly the actions that
    match all given filters.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    a = ctx.unique_name('sim2real-behav-aas-sa-flt-')
    b = ctx.unique_name('sim2real-behav-aas-sa-flt-')
    shared = ctx.unique_name('sim2real-behav-aas-shared-')
    only_write = ctx.unique_name('sim2real-behav-aas-write-')
    only_b = ctx.unique_name('sim2real-behav-aas-b-')
    for name in (a, b):
        _table(ctx, ddb, name)
    ra, rb = f'table/{a}', f'table/{b}'
    _register(ctx, aas, ra, _READ, 1, 4)
    _register(ctx, aas, ra, _WRITE, 1, 4)
    _register(ctx, aas, rb, _READ, 1, 4)
    # Deregistering each target deletes its scheduled actions, so the targets' cleanups cover them.
    for name, rid, dim in ((shared, ra, _READ), (shared, rb, _READ), (only_write, ra, _WRITE),
                           (only_b, rb, _READ)):
        aas.put_scheduled_action(ServiceNamespace=_NS, ResourceId=rid, ScalableDimension=dim,
                                 ScheduledActionName=name, Schedule=_SCHEDULE,
                                 ScalableTargetAction={'MinCapacity': 1, 'MaxCapacity': 4})

    by_name = _actions(aas, ScheduledActionNames=[shared])
    assert by_name == sorted([(shared, ra, _READ), (shared, rb, _READ)]), (
        f'the shared name alone returned {len(by_name)} actions, expected one per table')
    by_name_and_rid = _actions(aas, ScheduledActionNames=[shared, only_b], ResourceId=ra)
    assert by_name_and_rid == [(shared, ra, _READ)], (
        f'two names on the first table returned {[(x[0] == shared, x[2]) for x in by_name_and_rid]!r}; '
        f'only the shared action lives there')
    by_rid = _actions(aas, ResourceId=ra)
    assert by_rid == sorted([(shared, ra, _READ), (only_write, ra, _WRITE)]), (
        f'the first table alone returned {len(by_rid)} actions, expected its two')
    by_rid_dim = _actions(aas, ResourceId=ra, ScalableDimension=_WRITE)
    assert by_rid_dim == [(only_write, ra, _WRITE)], (
        f'the first table on the write dimension returned {len(by_rid_dim)} actions, expected 1')
    unmatched = _actions(aas, ScheduledActionNames=[shared], ResourceId=ra,
                         ScalableDimension=_WRITE)
    assert unmatched == [], (
        f'the shared name on a dimension it was never put on returned {len(unmatched)} actions')


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    """Bounded retry with a deadline that RAISES on timeout, never returns its last value."""
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
