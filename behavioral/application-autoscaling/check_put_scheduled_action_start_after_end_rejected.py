"""put-scheduled-action-start-after-end-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scheduled-action-start-after-end-rejected"
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


@tags('axis:rejection', 'cap:c1', 'cap:c4', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """A recurring scheduled action whose StartTime falls after its EndTime is refused and nothing
    is stored; the same action with the window the right way round is stored with both bounds.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-win-')
    action = ctx.unique_name('sim2real-behav-aas-win-sa-')
    resource_id = f'table/{table}'

    _create_table(ddb, table, 1)
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _wait_active(ddb, table)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    early, late = now + datetime.timedelta(days=10), now + datetime.timedelta(days=20)
    # Deregistering the target deletes its scheduled actions, so the target's cleanup covers it.
    error = _client_error(lambda: aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule='rate(1 day)', StartTime=late, EndTime=early,
        ScalableTargetAction={'MinCapacity': 2}))
    assert error['Code'] == 'ValidationException', (
        f'an inverted window was refused with {error["Code"]!r}, expected "ValidationException"')
    assert error['Message'] == 'StartTime must be before EndTime', (
        f'the refusal message was {error["Message"]!r}, expected "StartTime must be before EndTime"')
    listed = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id)
    assert listed['ScheduledActions'] == [], (
        f'the refused action was stored anyway: {listed["ScheduledActions"]!r}')

    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule='rate(1 day)', StartTime=early, EndTime=late,
        ScalableTargetAction={'MinCapacity': 2})
    stored = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id,
                                            ScheduledActionNames=[action])['ScheduledActions']
    assert len(stored) == 1, f'the positive control stored {len(stored)} actions: {stored!r}'
    assert (stored[0].get('StartTime'), stored[0].get('EndTime')) == (early, late), (
        f'the stored window is ({stored[0].get("StartTime")!r}, {stored[0].get("EndTime")!r}), '
        f'expected ({early.isoformat()}, {late.isoformat()})')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
