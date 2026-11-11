"""delete-scheduled-action-that-does-not-exist-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-scheduled-action-that-does-not-exist-rejected"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(
        f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


def _delete_table(ddb, name):
    for _ in range(8):
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException':
                raise RuntimeError(f'table {name!r} not deleted: {code}') from exc
            time.sleep(6)
    raise RuntimeError(f'table {name!r} still ResourceInUseException after retries')


def _deregister(aas, resource_id):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=_DIM)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _table(ctx, ddb):
    table = ctx.unique_name('sim2real-behav-aas-')
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120,
                description=f'table {table!r} becoming ACTIVE')
    return f'table/{table}'


@tags('axis:rejection', 'cap:c4', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """DeleteScheduledAction for a missing action is refused with AWS's exact message and leaves
    the real action in place; deleting the real one succeeds and it is no longer listed.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    resource_id = _table(ctx, ddb)
    target_arn = aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=10)['ScalableTargetARN']
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    # The message names the target by the UUID whose 32 hex digits end the target's ARN.
    hexid = target_arn.rsplit('scalable-target/', 1)[-1][-32:]
    target_id = '-'.join((hexid[:8], hexid[8:12], hexid[12:16], hexid[16:20], hexid[20:]))
    real = ctx.unique_name('sim2real-behav-aas-act-')
    missing = ctx.unique_name('sim2real-behav-aas-missing-')
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=real, Schedule='cron(0 3 * * ? *)',
        ScalableTargetAction={'MinCapacity': 2, 'MaxCapacity': 5})

    def listed():
        return [a['ScheduledActionName'] for a in aas.describe_scheduled_actions(
            ServiceNamespace=_NS, ResourceId=resource_id)['ScheduledActions']]

    error = _client_error(lambda: aas.delete_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=missing))
    assert error.get('Code') == 'ObjectNotFoundException', (
        f'deleting a missing scheduled action: expected ObjectNotFoundException, got {error!r}'
    )
    assert error.get('Message') == (
        f'No scheduled action found for service namespace: {_NS}, scalable target ID: '
        f'{target_id}, scheduled action name: {missing}'
    ), f'the rejection message was {error.get("Message")!r} (target {target_arn!r})'
    assert listed() == [real], f'the refused delete changed the actions: {listed()!r}'

    aas.delete_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=real)
    assert listed() == [], f'the deleted action is still listed: {listed()!r}'


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
