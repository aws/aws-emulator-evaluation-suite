"""table-that-exists-only-in-another-region-register-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-that-exists-only-in-another-region-register-rejected"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_WRITE = 'dynamodb:table:WriteCapacityUnits'


def _other_region(region):
    return 'us-east-1' if region != 'us-east-1' else 'us-west-2'


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def _bounds(aas, resource_id):
    found = []
    for page in aas.get_paginator('describe_scalable_targets').paginate(
            ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_WRITE):
        found.extend((t['MinCapacity'], t['MaxCapacity']) for t in page['ScalableTargets'])
    assert len(found) <= 1, f'{len(found)} targets share one resource id'
    return found[0] if found else None


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """RegisterScalableTarget for a table that exists only in another region is refused with a
    ValidationException naming it and registers nothing; the call in the table's region succeeds.
    """
    other = _other_region(ctx.region)
    ddb_far = ctx.client('dynamodb', region=other)
    aas_home = ctx.client('application-autoscaling')
    aas_far = ctx.client('application-autoscaling', region=other)
    name = ctx.unique_name('sim2real-behav-aas-rgn-')
    resource_id = f'table/{name}'
    _table(ctx, ddb_far, name)
    for aas in (aas_home, aas_far):
        ctx.on_cleanup(lambda aas=aas: _deregister(aas, resource_id, _WRITE))

    code, message = _error(lambda: aas_home.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_WRITE,
        MinCapacity=1, MaxCapacity=5))
    assert code == 'ValidationException', (
        f'a table that lives only in {other} was refused in {ctx.region} with {code!r}')
    expected = f'DynamoDB table does not exist: {resource_id}'
    assert message == expected, f'refusal message {message!r}, expected {expected!r}'
    assert _bounds(aas_home, resource_id) is None, (
        f'the {other} table is registered in {ctx.region} anyway')

    # Positive control: the same call in the table's own region registers.
    aas_far.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                     ScalableDimension=_WRITE, MinCapacity=1, MaxCapacity=5)
    assert _bounds(aas_far, resource_id) == (1, 5), (
        f'the table registered in {other} with bounds {_bounds(aas_far, resource_id)!r}, '
        f'expected (1, 5)')
    assert _bounds(aas_home, resource_id) is None, (
        f'registering in {other} made the target appear in {ctx.region}')


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _table(ctx, ddb, name, *, read=1, write=1):
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
