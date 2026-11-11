"""put-scheduled-action-unknown-rate-unit-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scheduled-action-unknown-rate-unit-rejected"
GROUP = 'scheduled-action-rejected'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_SYNTAX_MESSAGE = (
    'Invalid schedule expression. Details: Schedule expressions must have the following syntax: '
    r'rate(<number>\s?(minutes?|hours?|days?)), cron(<cron_expression>) or '
    "at(yyyy-MM-dd'T'HH:mm:ss)."
)


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
    """Re-putting a live rate() action with a unit the grammar lacks ("fortnights") is refused with
    the schedule-syntax message, and the existing action keeps its old rate and target action.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-rate-')
    action = ctx.unique_name('sim2real-behav-aas-rate-sa-')
    resource_id = f'table/{table}'

    _create_table(ddb, table, 1)
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _wait_active(ddb, table)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    # Deregistering the target deletes its scheduled actions, so the target's cleanup covers it.
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule='rate(5 days)',
        ScalableTargetAction={'MaxCapacity': 9})
    error = _client_error(lambda: aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule='rate(5 fortnights)',
        ScalableTargetAction={'MaxCapacity': 7}))
    assert error['Code'] == 'ValidationException', (
        f'an unknown rate unit was refused with {error["Code"]!r}, expected "ValidationException"')
    assert error['Message'] == _SYNTAX_MESSAGE, (
        f'the refusal message was {error["Message"]!r}, expected {_SYNTAX_MESSAGE!r}')

    stored = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id)
    stored = stored['ScheduledActions']
    assert [a['ScheduledActionName'] for a in stored] == [action], (
        f'expected exactly the original action to be listed, got '
        f'{[a["ScheduledActionName"] for a in stored]!r}')
    assert stored[0]['Schedule'] == 'rate(5 days)', (
        f'the refused update changed the schedule to {stored[0]["Schedule"]!r}; it must still read '
        f'"rate(5 days)"')
    assert stored[0]['ScalableTargetAction'] == {'MaxCapacity': 9}, (
        f'the refused update changed the target action to {stored[0]["ScalableTargetAction"]!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
