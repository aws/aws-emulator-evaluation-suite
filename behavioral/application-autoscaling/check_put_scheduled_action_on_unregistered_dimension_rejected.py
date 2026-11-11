"""put-scheduled-action-on-unregistered-dimension-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scheduled-action-on-unregistered-dimension-rejected"
GROUP = 'scheduled-action-rejected'
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


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """A scheduled action is keyed to a registered (resource, dimension) pair, not to the table:
    with only read capacity registered, an action on the table's write dimension is refused and
    nothing is stored there, while the same action on the registered read dimension is accepted.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-unreg-')
    action = ctx.unique_name('sim2real-behav-aas-unreg-sa-')
    resource_id = f'table/{table}'

    _create_table(ddb, table, 1)
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _wait_active(ddb, table)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    # Deregistering the target deletes its scheduled actions, so the target's cleanup covers it.
    error = _client_error(lambda: aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_WRITE_DIM,
        ScheduledActionName=action, Schedule='cron(0 8 * * ? *)',
        ScalableTargetAction={'MinCapacity': 2}))
    assert error['Code'] == 'ObjectNotFoundException', (
        f'an action on the unregistered write dimension was refused with {error["Code"]!r}, '
        f'expected "ObjectNotFoundException"')
    expected = (f'No scalable target registered for service namespace: dynamodb, resource ID: '
                f'{resource_id}, scalable dimension: {_WRITE_DIM}')
    assert error['Message'] == expected, (
        f'the refusal message was {error["Message"]!r}, expected {expected!r}')
    on_write = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id,
                                              ScalableDimension=_WRITE_DIM)
    assert on_write['ScheduledActions'] == [], (
        f'the refused action was stored on the write dimension: {on_write["ScheduledActions"]!r}')
    write_targets = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[resource_id],
                                                  ScalableDimension=_WRITE_DIM)
    assert write_targets['ScalableTargets'] == [], (
        f'the refused action registered the write dimension implicitly: '
        f'{write_targets["ScalableTargets"]!r}')

    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule='cron(0 8 * * ? *)',
        ScalableTargetAction={'MinCapacity': 2})
    stored = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id)
    stored = stored['ScheduledActions']
    assert [(a['ScheduledActionName'], a['ScalableDimension']) for a in stored] == [(action, _DIM)], (
        f'expected only the read-dimension action, got '
        f'{[(a["ScheduledActionName"], a["ScalableDimension"]) for a in stored]!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
