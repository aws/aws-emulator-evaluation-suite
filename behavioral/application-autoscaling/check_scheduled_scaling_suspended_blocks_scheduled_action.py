"""scheduled-scaling-suspended-blocks-scheduled-action."""
from __future__ import annotations

import datetime
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-scaling-suspended-blocks-scheduled-action"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'


def _poll_until(probe, predicate, *, timeout_s, interval_s=4.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


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


def _activities(aas, resource_id):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id, 'ScalableDimension': _DIM}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _terminal(activity):
    return activity['StatusCode'] in ('Successful', 'Failed', 'Overridden', 'Unfulfilled')


def _create_provisioned_table(ddb, name):
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    _poll_until(lambda: ddb.describe_table(TableName=name)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {name!r} becoming ACTIVE')


def _next_cron_minute(min_lead_s=25):
    now = datetime.datetime.now(datetime.timezone.utc)
    fire = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    if (fire - now).total_seconds() < min_lead_s:
        fire += datetime.timedelta(minutes=1)
    return f'cron({fire.minute} {fire.hour} {fire.day} {fire.month} ? {fire.year})', fire


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:negative-classes',
      'concern:representation', 'plane:control', 'timing:real-time')
def run(ctx) -> None:
    """ScheduledScalingSuspended stops a scheduled action from firing on that target while an
    identical action fires on a control target, and the target still scales on a bound change.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    suspended_table = ctx.unique_name('sim2real-behav-aas-susp-')
    control_table = ctx.unique_name('sim2real-behav-aas-ctrl-')
    action = ctx.unique_name('sim2real-behav-aas-sa-')
    suspended_id = f'table/{suspended_table}'
    control_id = f'table/{control_table}'

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {}
        for name in (suspended_table, control_table):
            futures[pool.submit(_create_provisioned_table, ddb, name)] = name
            ctx.on_cleanup(lambda n=name: _delete_table(ddb, n))
        for future in futures:
            future.result()

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=suspended_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=20,
        SuspendedState={'DynamicScalingInSuspended': False, 'DynamicScalingOutSuspended': False,
                        'ScheduledScalingSuspended': True},
        Tags={'sim2real': CHECK},
    )
    ctx.on_cleanup(lambda: _deregister(aas, suspended_id))
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=control_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20,
                                 Tags={'sim2real': CHECK})
    ctx.on_cleanup(lambda: _deregister(aas, control_id))

    echoed = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[suspended_id])['ScalableTargets'][0]['SuspendedState']
    assert echoed == {'DynamicScalingInSuspended': False, 'DynamicScalingOutSuspended': False,
                      'ScheduledScalingSuspended': True}, (
        f'the suspended target reported SuspendedState {echoed!r}; only the scheduled flag was set'
    )

    schedule, fire_at = _next_cron_minute()
    for resource_id in (suspended_id, control_id):
        aas.put_scheduled_action(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            ScheduledActionName=action, Schedule=schedule, Timezone='UTC',
            ScalableTargetAction={'MinCapacity': 4, 'MaxCapacity': 18},
        )

    # Both targets share the same cron minute, so the control target's completed chain is the
    # barrier after which the suspended target's empty history is meaningful (not a sleep).
    control_acts = _poll_until(
        lambda: _activities(aas, control_id),
        lambda acts: len(acts) >= 2 and all(_terminal(a) for a in acts),
        timeout_s=210, interval_s=5.0,
        description=f'the control target completing its scheduled chain for '
                    f'{fire_at.isoformat()} -- this arrival is the barrier for the suspended '
                    f'target, which was handed the identical cron minute')
    control_causes = [a['Cause'] for a in control_acts]
    assert f'scheduled action name {action} was triggered' in control_causes, (
        f'the control target scaled for some other reason: {control_causes!r} -- without a '
        f'scheduled dispatch on the control side there is no barrier and no verdict'
    )
    assert 'minimum capacity was set to 4' in control_causes, (
        f'the control target never applied the scheduled floor: {control_causes!r}'
    )

    blocked = _activities(aas, suspended_id)
    assert blocked == [], (
        f'the suspended target recorded {len(blocked)} scaling activities while '
        f'ScheduledScalingSuspended was set: '
        f'{[(a["Cause"], a["Description"], a["StatusCode"]) for a in blocked]!r}'
    )
    suspended_target = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[suspended_id])['ScalableTargets'][0]
    assert (suspended_target['MinCapacity'], suspended_target['MaxCapacity']) == (1, 20), (
        f'the suspended target bounds moved to '
        f'({suspended_target["MinCapacity"]}, {suspended_target["MaxCapacity"]}); a suppressed '
        f'scheduled action must not rewrite them to (4, 18)'
    )
    assert ddb.describe_table(TableName=suspended_table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits'] == 1, (
        'the suspended table\'s read capacity moved; the suppressed scheduled action must leave '
        'DynamoDB untouched'
    )

    # Close the loop: the suspended target is live and scalable RIGHT NOW, so the absence above
    # is the flag and not an unreachable resource. ScheduledScalingSuspended suspends scheduled
    # scaling only -- bound enforcement is a different mechanism and is not suspended.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=suspended_id,
                                 ScalableDimension=_DIM, MinCapacity=3, MaxCapacity=20)
    live = _poll_until(
        lambda: _activities(aas, suspended_id),
        lambda acts: len(acts) >= 1 and _terminal(acts[0]), timeout_s=140, interval_s=4.0,
        description='the suspended target proving it can still scale on a bound change')[0]
    assert live['Cause'] == 'minimum capacity was set to 3', (
        f'the control activity on the suspended target reported cause {live["Cause"]!r}, expected '
        f'"minimum capacity was set to 3"'
    )
    assert ddb.describe_table(TableName=suspended_table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits'] == 3, (
        'the suspended target did not apply its own new floor, so this check could not attribute '
        'the earlier absence to ScheduledScalingSuspended'
    )
    still_blocked = [a for a in _activities(aas, suspended_id)
                     if 'scheduled action' in a['Cause']]
    assert still_blocked == [], (
        f'a scheduled-action activity appeared on the suspended target after all: '
        f'{[(a["Cause"], a["StartTime"]) for a in still_blocked]!r}'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
