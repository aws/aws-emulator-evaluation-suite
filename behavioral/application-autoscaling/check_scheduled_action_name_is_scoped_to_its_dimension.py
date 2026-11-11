"""scheduled-action-name-is-scoped-to-its-dimension."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-action-name-is-scoped-to-its-dimension"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_WRITE_DIM = 'dynamodb:table:WriteCapacityUnits'


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


def _create_table(ddb, name, read_capacity):
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': read_capacity, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )


def _wait_active(ddb, name):
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


def _deregister(aas, resource_id, dimension=_DIM):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=dimension)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _client_error(fn):
    """The Error dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def _actions(aas, **filters):
    out, token = [], None
    while True:
        kwargs = {'ServiceNamespace': _NS, **filters}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scheduled_actions(**kwargs)
        out.extend(page['ScheduledActions'])
        token = page.get('NextToken')
        if not token:
            return out


@tags('axis:happy-path', 'cap:c1', 'concern:negative-classes', 'concern:representation',
      'plane:control')
def run(ctx) -> None:
    """One ScheduledActionName on a table's read and write dimensions is two independent actions: a
    name filter returns both, a dimension filter separates them, and deleting one keeps the
    other."""
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-scope-')
    action = ctx.unique_name('sim2real-behav-aas-scope-sa-')
    resource_id = f'table/{table}'

    _create_table(ddb, table, 1)
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _wait_active(ddb, table)
    for dimension in (_DIM, _WRITE_DIM):
        aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                     ScalableDimension=dimension, MinCapacity=1, MaxCapacity=10)
        ctx.on_cleanup(lambda d=dimension: _deregister(aas, resource_id, d))

    # Deregistering a target deletes its scheduled actions, so the target cleanups cover these.
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule='cron(0 7 * * ? *)',
        ScalableTargetAction={'MinCapacity': 2})
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_WRITE_DIM,
        ScheduledActionName=action, Schedule='cron(0 19 * * ? *)',
        ScalableTargetAction={'MaxCapacity': 4})

    by_name = _actions(aas, ResourceId=resource_id, ScheduledActionNames=[action])
    pairs = sorted((a['ScalableDimension'], a['Schedule']) for a in by_name)
    assert pairs == [(_DIM, 'cron(0 7 * * ? *)'), (_WRITE_DIM, 'cron(0 19 * * ? *)')], (
        f'the name filter returned {pairs!r}; the same name on two dimensions must be two actions, '
        f'neither overwriting the other')
    assert len({a['ScheduledActionARN'] for a in by_name}) == 2, (
        'the two same-name actions share a ScheduledActionARN')

    write_only = _actions(aas, ResourceId=resource_id, ScalableDimension=_WRITE_DIM)
    assert [(a['ScheduledActionName'], a['ScalableTargetAction']) for a in write_only] == [
        (action, {'MaxCapacity': 4})], (
        f'the write-dimension filter returned '
        f'{[(a["ScheduledActionName"], a["ScalableTargetAction"]) for a in write_only]!r}')

    error = _client_error(lambda: aas.describe_scheduled_actions(
        ServiceNamespace=_NS, ScalableDimension=_WRITE_DIM, ScheduledActionNames=[action]))
    assert (error['Code'], error['Message']) == (
        'ValidationException', 'Scalable dimension cannot be provided without a resource ID.'), (
        f'a dimension filter without ResourceId gave ({error["Code"]!r}, {error["Message"]!r})')

    aas.delete_scheduled_action(ServiceNamespace=_NS, ResourceId=resource_id,
                                ScalableDimension=_DIM, ScheduledActionName=action)
    left = _actions(aas, ResourceId=resource_id, ScheduledActionNames=[action])
    assert [(a['ScalableDimension'], a['Schedule']) for a in left] == [
        (_WRITE_DIM, 'cron(0 19 * * ? *)')], (
        f'after deleting the read-dimension action the name filter returned '
        f'{[(a["ScalableDimension"], a["Schedule"]) for a in left]!r}; the write one must survive')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
