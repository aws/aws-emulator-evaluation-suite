"""describe-scalable-targets-resource-ids-and-dimension-intersect."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-scalable-targets-resource-ids-and-dimension-intersect"
GROUP = 'state'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_READ = 'dynamodb:table:ReadCapacityUnits'
_WRITE = 'dynamodb:table:WriteCapacityUnits'


def _targets(aas, **filters):
    out = []
    for page in aas.get_paginator('describe_scalable_targets').paginate(ServiceNamespace=_NS,
                                                                        **filters):
        out.extend((t['ResourceId'], t['ScalableDimension'], t['MinCapacity'], t['MaxCapacity'])
                   for t in page['ScalableTargets'])
    return sorted(out)


@tags('axis:happy-path', 'cap:c1', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """DescribeScalableTargets intersects ResourceIds with ScalableDimension: two ids plus a dimension
    return the two matching targets, the ids alone return all three, an unregistered id adds
    nothing, and an unregistered dimension returns none.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    a = ctx.unique_name('sim2real-behav-aas-flt-')
    b = ctx.unique_name('sim2real-behav-aas-flt-')
    never = ctx.unique_name('sim2real-behav-aas-flt-')
    for name in (a, b):
        _table(ctx, ddb, name)
    ra, rb, rn = f'table/{a}', f'table/{b}', f'table/{never}'
    _register(ctx, aas, ra, _READ, 1, 4)
    _register(ctx, aas, ra, _WRITE, 1, 5)
    _register(ctx, aas, rb, _READ, 1, 6)

    both_read = _targets(aas, ResourceIds=[ra, rb], ScalableDimension=_READ)
    assert both_read == sorted([(ra, _READ, 1, 4), (rb, _READ, 1, 6)]), (
        f'two ids with the read dimension returned {len(both_read)} targets: '
        f'{[(t[1], t[3]) for t in both_read]!r}; expected the read target of each table')
    every = _targets(aas, ResourceIds=[ra, rb])
    assert every == sorted([(ra, _READ, 1, 4), (ra, _WRITE, 1, 5), (rb, _READ, 1, 6)]), (
        f'two ids with no dimension returned {[(t[1], t[3]) for t in every]!r}; expected all '
        f'three targets')
    with_unknown = _targets(aas, ResourceIds=[ra, rn], ScalableDimension=_WRITE)
    assert with_unknown == [(ra, _WRITE, 1, 5)], (
        f'a registered id beside a never-registered one returned '
        f'{[(t[1], t[3]) for t in with_unknown]!r}; expected only the write target of the first')
    unmatched = _targets(aas, ResourceIds=[rb], ScalableDimension=_WRITE)
    assert unmatched == [], (
        f'a dimension the table never registered returned {len(unmatched)} targets')


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
