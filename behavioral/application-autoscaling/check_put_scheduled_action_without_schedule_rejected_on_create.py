"""put-scheduled-action-without-schedule-rejected-on-create."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scheduled-action-without-schedule-rejected-on-create"
GROUP = 'scheduled-action-rejected'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'


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
    """Schedule is optional in the model but required to CREATE: a PutScheduledAction for a new
    name with no Schedule is refused and stores nothing, while the identical call is accepted once
    the action exists, as an update that keeps the stored schedule.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-nosch-')
    action = ctx.unique_name('sim2real-behav-aas-nosch-sa-')
    resource_id = f'table/{table}'

    _create_table(ddb, table, 1)
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _wait_active(ddb, table)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    def _schedule_less_put():
        return aas.put_scheduled_action(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            ScheduledActionName=action, ScalableTargetAction={'MinCapacity': 3})

    # Deregistering the target deletes its scheduled actions, so the target's cleanup covers it.
    error = _client_error(_schedule_less_put)
    assert error['Code'] == 'ValidationException', (
        f'a create with no Schedule was refused with {error["Code"]!r}, expected '
        f'"ValidationException"')
    assert error['Message'] == 'Schedule must be set', (
        f'the refusal message was {error["Message"]!r}, expected "Schedule must be set"')
    listed = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id)
    assert listed['ScheduledActions'] == [], (
        f'the refused create stored an action anyway: {listed["ScheduledActions"]!r}')

    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule='cron(15 3 * * ? *)',
        ScalableTargetAction={'MinCapacity': 2})
    _schedule_less_put()
    stored = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id,
                                            ScheduledActionNames=[action])['ScheduledActions']
    assert len(stored) == 1, f'expected one stored action, got {stored!r}'
    assert stored[0]['Schedule'] == 'cron(15 3 * * ? *)', (
        f'the schedule-less update changed the schedule to {stored[0]["Schedule"]!r}')
    assert stored[0]['ScalableTargetAction'] == {'MinCapacity': 3}, (
        f'the schedule-less update left the target action at '
        f'{stored[0]["ScalableTargetAction"]!r}, expected {{"MinCapacity": 3}}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
