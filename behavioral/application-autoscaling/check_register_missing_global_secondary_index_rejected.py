"""register-missing-global-secondary-index-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-missing-global-secondary-index-rejected"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_PROV = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}



def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description='condition'):
    """Bounded poll that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _client_error(fn):
    """The Error dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


def _create_table(ctx, ddb, name, **extra):
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=extra.pop('AttributeDefinitions',
                                       [{'AttributeName': 'pk', 'AttributeType': 'S'}]),
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
        **extra,
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, name))
    _poll_until(lambda: ddb.describe_table(TableName=name)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=180, description=f'table {name!r} ACTIVE')


def _delete_table(ddb, name):
    """DeleteTable refuses while the table is UPDATING; retry that, bounded, and raise otherwise."""
    deadline = time.monotonic() + 45
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
            time.sleep(5)


def _deregister(aas, ns, resource_id, dim):
    try:
        aas.deregister_scalable_target(ServiceNamespace=ns, ResourceId=resource_id,
                                       ScalableDimension=dim)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _targets(aas, ns, resource_id):
    out = []
    for page in aas.get_paginator('describe_scalable_targets').paginate(
            ServiceNamespace=ns, ResourceIds=[resource_id]):
        out.extend(page['ScalableTargets'])
    return out


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """RegisterScalableTarget for an index the existing table does not have is refused with a
    ValidationException naming the index resource id and registers nothing; the real GSI
    registers."""
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-gsi-')
    _create_table(
        ctx, ddb, table, BillingMode='PROVISIONED', ProvisionedThroughput=_PROV,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'email', 'AttributeType': 'S'}],
        GlobalSecondaryIndexes=[{
            'IndexName': 'by-email', 'KeySchema': [{'AttributeName': 'email', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'}, 'ProvisionedThroughput': _PROV}])
    index_dim = 'dynamodb:index:ReadCapacityUnits'
    missing = f'table/{table}/index/by-mail'
    real = f'table/{table}/index/by-email'

    ctx.on_cleanup(lambda: _deregister(aas, _NS, missing, index_dim))
    error = _client_error(lambda: aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=missing, ScalableDimension=index_dim,
        MinCapacity=1, MaxCapacity=5))
    assert error.get('Code') == 'ValidationException', (
        f'registering a missing index was refused with {error.get("Code")!r}, '
        f'expected "ValidationException"')
    assert error.get('Message') == f'DynamoDB index does not exist: {missing}', (
        f'the refusal message was {error.get("Message")!r}')
    assert _targets(aas, _NS, missing) == [], 'the refused index registration stored a target'

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=real,
                                 ScalableDimension=index_dim, MinCapacity=1, MaxCapacity=5)
    ctx.on_cleanup(lambda: _deregister(aas, _NS, real, index_dim))
    stored = [(t['ScalableDimension'], t['MinCapacity'], t['MaxCapacity'])
              for t in _targets(aas, _NS, real)]
    assert stored == [(index_dim, 1, 5)], f'the real index reads back {stored!r}'


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
