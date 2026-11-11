"""deleted-scheduled-action-never-fires."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-scheduled-action-never-fires"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_FIRING_TIMEOUT_S = 240


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


def _activities(aas, resource_id):
    out, token = [], None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id, 'ScalableDimension': _DIM}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _next_minute_at(min_lead_s=40):
    """A one-time at() expression for the next whole UTC minute at least ``min_lead_s`` away."""
    now = datetime.datetime.now(datetime.timezone.utc)
    fire = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    if (fire - now).total_seconds() < min_lead_s:
        fire += datetime.timedelta(minutes=1)
    return f'at({fire:%Y-%m-%dT%H:%M:%S})', fire


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:data-plane', 'concern:negative-classes',
      'dp:api', 'plane:data', "timing:real-time")
def run(ctx) -> None:
    """DeleteScheduledAction before the action's instant cancels it: when that instant arrives an
    identical action on a twin target fires and moves its table, and the deleted one does nothing.
    Only the instant passing tells a cancelled timer from one still armed."""
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    subject_table = ctx.unique_name('sim2real-behav-aas-del-')
    control_table = ctx.unique_name('sim2real-behav-aas-dctl-')
    subject_id = f'table/{subject_table}'
    control_id = f'table/{control_table}'
    subject_action = ctx.unique_name('sim2real-behav-aas-del-sa-')
    control_action = ctx.unique_name('sim2real-behav-aas-dctl-sa-')

    for name in (subject_table, control_table):
        _create_table(ddb, name, 1)
        ctx.on_cleanup(lambda n=name: _delete_table(ddb, n))
    for name in (subject_table, control_table):
        _wait_active(ddb, name)
    for resource_id in (subject_id, control_id):
        aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                     ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20)
        ctx.on_cleanup(lambda r=resource_id: _deregister(aas, r))

    schedule, fire_at = _next_minute_at()
    # Deregistering a target deletes its scheduled actions, so the target cleanups cover these.
    for resource_id, name in ((subject_id, subject_action), (control_id, control_action)):
        aas.put_scheduled_action(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            ScheduledActionName=name, Schedule=schedule,
            ScalableTargetAction={'MinCapacity': 4},
        )
    aas.delete_scheduled_action(ServiceNamespace=_NS, ResourceId=subject_id,
                                ScalableDimension=_DIM, ScheduledActionName=subject_action)
    listed = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=subject_id)
    assert listed['ScheduledActions'] == [], (
        f'the deleted action is still listed: {listed["ScheduledActions"]!r}')

    _poll_until(
        lambda: _activities(aas, control_id),
        lambda acts: len(acts) >= 2 and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=_FIRING_TIMEOUT_S, interval_s=5.0,
        description=f'the control action firing at {fire_at.isoformat()} and its floor '
                    f'correction, both Successful')

    fired = _activities(aas, subject_id)
    assert fired == [], (
        f'the deleted action still fired at its instant {fire_at.isoformat()}: '
        f'{[(a["Cause"], a["Description"]) for a in fired]!r}')
    target = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[subject_id],
                                           ScalableDimension=_DIM)['ScalableTargets'][0]
    assert (target['MinCapacity'], target['MaxCapacity']) == (1, 20), (
        f'subject bounds are ({target["MinCapacity"]}, {target["MaxCapacity"]}); the cancelled '
        f'action must not have rewritten them')
    capacity = ddb.describe_table(TableName=subject_table)['Table']['ProvisionedThroughput']
    assert capacity['ReadCapacityUnits'] == 1, (
        f'subject read capacity is {capacity["ReadCapacityUnits"]}; the cancelled action would '
        f'have raised it to 4')
    control_capacity = _poll_until(
        lambda: ddb.describe_table(TableName=control_table)['Table'],
        lambda t: t['TableStatus'] == 'ACTIVE', timeout_s=120, interval_s=5.0,
        description='the control table settling ACTIVE')['ProvisionedThroughput']
    assert control_capacity['ReadCapacityUnits'] == 4, (
        f'control read capacity is {control_capacity["ReadCapacityUnits"]}; the live twin action '
        f'raised it to 4')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
