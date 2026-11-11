"""suspended-state-upsert-changes-only-the-flags-it-names."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "suspended-state-upsert-changes-only-the-flags-it-names"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_BARRIER_TIMEOUT_S = 200
_RESUME_TIMEOUT_S = 200
_ALL_SUSPENDED = {'DynamicScalingInSuspended': True, 'DynamicScalingOutSuspended': True,
                  'ScheduledScalingSuspended': True}


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


def _target(aas, resource_id):
    targets = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[resource_id],
                                            ScalableDimension=_DIM)['ScalableTargets']
    assert len(targets) == 1, f'expected one scalable target for {resource_id!r}, got {targets!r}'
    return targets[0]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:data-plane', 'concern:representation',
      'dp:api', 'plane:data', "timing:real-time")
def run(ctx) -> None:
    """RegisterScalableTarget merges SuspendedState per flag: an upsert omitting it keeps all three
    and keeps scheduled scaling held; naming only ScheduledScalingSuspended=False releases it, as
    the table's capacity shows, while both dynamic flags stay set."""
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    subject_table = ctx.unique_name('sim2real-behav-aas-flag-')
    control_table = ctx.unique_name('sim2real-behav-aas-fctl-')
    subject_id = f'table/{subject_table}'
    control_id = f'table/{control_table}'
    subject_action = ctx.unique_name('sim2real-behav-aas-flag-sa-')
    control_action = ctx.unique_name('sim2real-behav-aas-fctl-sa-')

    for name in (subject_table, control_table):
        _create_table(ddb, name, 1)
        ctx.on_cleanup(lambda n=name: _delete_table(ddb, n))
    for name in (subject_table, control_table):
        _wait_active(ddb, name)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=subject_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20,
                                 SuspendedState=_ALL_SUSPENDED)
    ctx.on_cleanup(lambda: _deregister(aas, subject_id))
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=control_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20)
    ctx.on_cleanup(lambda: _deregister(aas, control_id))

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=subject_id,
                                 ScalableDimension=_DIM, MaxCapacity=18)
    kept = _target(aas, subject_id)
    assert kept['SuspendedState'] == _ALL_SUSPENDED, (
        f'an upsert that omitted SuspendedState changed it to {kept["SuspendedState"]!r}; all '
        f'three flags must be kept')
    assert (kept['MinCapacity'], kept['MaxCapacity']) == (1, 18), (
        f'bounds after the max-only upsert are ({kept["MinCapacity"]}, {kept["MaxCapacity"]})')

    # Deregistering a target deletes its scheduled actions, so the target cleanups cover these.
    for resource_id, name in ((subject_id, subject_action), (control_id, control_action)):
        aas.put_scheduled_action(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            ScheduledActionName=name, Schedule='rate(1 minute)',
            ScalableTargetAction={'MinCapacity': 3},
        )
    _poll_until(
        lambda: _triggers(_activities(aas, control_id), control_action),
        lambda acts: len(acts) >= 2, timeout_s=_BARRIER_TIMEOUT_S, interval_s=5.0,
        description=f'the control rate action {control_action!r} firing twice')
    held = _activities(aas, subject_id)
    assert held == [], (
        f'the subject fired while every flag was still suspended: '
        f'{[(a["Cause"], a["Description"]) for a in held]!r}')
    assert ddb.describe_table(TableName=subject_table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits'] == 1, (
        'the held subject table moved off read capacity 1')

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=subject_id,
                                 ScalableDimension=_DIM,
                                 SuspendedState={'ScheduledScalingSuspended': False})
    merged = _target(aas, subject_id)
    assert merged['SuspendedState'] == {'DynamicScalingInSuspended': True,
                                        'DynamicScalingOutSuspended': True,
                                        'ScheduledScalingSuspended': False}, (
        f'a one-flag SuspendedState upsert produced {merged["SuspendedState"]!r}; only '
        f'ScheduledScalingSuspended may change, the two dynamic flags must stay True')

    _poll_until(
        lambda: _triggers(_activities(aas, subject_id), subject_action),
        lambda acts: len(acts) >= 1 and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=_RESUME_TIMEOUT_S, interval_s=5.0,
        description=f'the subject rate action {subject_action!r} firing once scheduled scaling '
                    f'was released')
    final = _target(aas, subject_id)
    assert (final['MinCapacity'], final['MaxCapacity']) == (3, 18), (
        f'subject bounds are ({final["MinCapacity"]}, {final["MaxCapacity"]}); the released '
        f'action sets the floor to 3 under the upserted ceiling of 18')
    for name in (subject_table, control_table):
        _poll_until(
            lambda n=name: ddb.describe_table(TableName=n)['Table'],
            lambda t: t['TableStatus'] == 'ACTIVE'
            and t['ProvisionedThroughput']['ReadCapacityUnits'] == 3,
            timeout_s=120, interval_s=5.0,
            description=f'table {name!r} ACTIVE at the scheduled read capacity 3')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
