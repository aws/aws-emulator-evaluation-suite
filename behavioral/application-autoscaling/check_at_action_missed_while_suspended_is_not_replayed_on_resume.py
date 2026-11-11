"""at-action-missed-while-suspended-is-not-replayed-on-resume."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "at-action-missed-while-suspended-is-not-replayed-on-resume"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_FIRING_TIMEOUT_S = 240
_RESUME_TIMEOUT_S = 200
_SUSPENDED = {'DynamicScalingInSuspended': False, 'DynamicScalingOutSuspended': False,
              'ScheduledScalingSuspended': True}
_RESUMED = {'DynamicScalingInSuspended': False, 'DynamicScalingOutSuspended': False,
            'ScheduledScalingSuspended': False}


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


def _triggers(activities, action):
    cause = f'scheduled action name {action} was triggered'
    return [a for a in activities if a['Cause'] == cause]


def _next_minute_at(min_lead_s=40):
    """A one-time at() expression for the next whole UTC minute at least ``min_lead_s`` away."""
    now = datetime.datetime.now(datetime.timezone.utc)
    fire = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    if (fire - now).total_seconds() < min_lead_s:
        fire += datetime.timedelta(minutes=1)
    return f'at({fire:%Y-%m-%dT%H:%M:%S})', fire


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:data-plane', 'concern:negative-classes',
      'dp:api', 'plane:data', 'timing:real-time')
def run(ctx) -> None:
    """An at() action whose instant passes while ScheduledScalingSuspended is set is dropped: after
    resume only the recurring action fires and capacity stays at 1, while the same action on an
    unsuspended control target fired and raised capacity to 4.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    subject_table = ctx.unique_name('sim2real-behav-aas-miss-')
    control_table = ctx.unique_name('sim2real-behav-aas-mctl-')
    subject_id = f'table/{subject_table}'
    control_id = f'table/{control_table}'
    missed = ctx.unique_name('sim2real-behav-aas-miss-at-')
    recurring = ctx.unique_name('sim2real-behav-aas-miss-rate-')
    control_action = ctx.unique_name('sim2real-behav-aas-mctl-at-')

    for name in (subject_table, control_table):
        _create_table(ddb, name, 1)
        ctx.on_cleanup(lambda n=name: _delete_table(ddb, n))
    for name in (subject_table, control_table):
        _wait_active(ddb, name)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=subject_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20,
                                 SuspendedState=_SUSPENDED)
    ctx.on_cleanup(lambda: _deregister(aas, subject_id))
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=control_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20)
    ctx.on_cleanup(lambda: _deregister(aas, control_id))

    schedule, fire_at = _next_minute_at()
    # Deregistering a target deletes its scheduled actions, so the target cleanups cover these.
    for resource_id, name in ((subject_id, missed), (control_id, control_action)):
        aas.put_scheduled_action(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            ScheduledActionName=name, Schedule=schedule,
            ScalableTargetAction={'MinCapacity': 4},
        )
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=subject_id, ScalableDimension=_DIM,
        ScheduledActionName=recurring, Schedule='rate(1 minute)',
        ScalableTargetAction={'MaxCapacity': 19},
    )

    _poll_until(
        lambda: _activities(aas, control_id),
        lambda acts: len(acts) >= 2 and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=_FIRING_TIMEOUT_S, interval_s=5.0,
        description=f'the control at() action firing at {fire_at.isoformat()} and its floor '
                    f'correction, both Successful')
    before = _activities(aas, subject_id)
    assert before == [], (
        f'the suspended subject recorded activities while ScheduledScalingSuspended was set: '
        f'{[(a["Cause"], a["Description"]) for a in before]!r}')

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=subject_id,
                                 ScalableDimension=_DIM, SuspendedState=_RESUMED)
    after = _poll_until(
        lambda: _activities(aas, subject_id),
        lambda acts: len(_triggers(acts, recurring)) >= 2
        and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=_RESUME_TIMEOUT_S, interval_s=5.0,
        description=f'the recurring action {recurring!r} firing twice after scheduled scaling '
                    f'was resumed')
    replayed = _triggers(after, missed)
    assert replayed == [], (
        f'the at() action whose instant {fire_at.isoformat()} passed during the suspension was '
        f'replayed after resume: {[(a["StartTime"], a["Description"]) for a in replayed]!r}')
    assert {a['Cause'] for a in after} == {f'scheduled action name {recurring} was triggered'}, (
        f'after resume the subject recorded {[(a["Cause"], a["Description"]) for a in after]!r}; '
        f'only the recurring action may have fired')

    target = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[subject_id],
                                           ScalableDimension=_DIM)['ScalableTargets'][0]
    assert (target['MinCapacity'], target['MaxCapacity']) == (1, 19), (
        f'subject bounds are ({target["MinCapacity"]}, {target["MaxCapacity"]}); the recurring '
        f'action sets the ceiling to 19 and the missed floor of 4 must never be applied')
    capacity = ddb.describe_table(TableName=subject_table)['Table']['ProvisionedThroughput']
    assert capacity['ReadCapacityUnits'] == 1, (
        f'subject read capacity is {capacity["ReadCapacityUnits"]}; the missed action would have '
        f'raised it to 4')
    control_capacity = _poll_until(
        lambda: ddb.describe_table(TableName=control_table)['Table'],
        lambda t: t['TableStatus'] == 'ACTIVE', timeout_s=120, interval_s=5.0,
        description='the control table settling ACTIVE')['ProvisionedThroughput']
    assert control_capacity['ReadCapacityUnits'] == 4, (
        f'control read capacity is {control_capacity["ReadCapacityUnits"]}; the same action, not '
        f'suspended, raised it to 4')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
