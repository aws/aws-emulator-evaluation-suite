"""scheduled-action-in-a-second-region-scales-only-that-regions-table."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-action-in-a-second-region-scales-only-that-regions-table"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_READ = 'dynamodb:table:ReadCapacityUnits'
_FIRING_TIMEOUT_S = 300


def _other_region(region):
    return 'us-east-1' if region != 'us-east-1' else 'us-west-2'


def _activities(aas, resource_id):
    out = []
    for page in aas.get_paginator('describe_scaling_activities').paginate(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_READ):
        out.extend(page['ScalingActivities'])
    return out


def _next_minute_at(min_lead_s=30):
    """A one-time at() expression for the next whole UTC minute at least ``min_lead_s`` away."""
    now = datetime.datetime.now(datetime.timezone.utc)
    fire = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    if (fire - now).total_seconds() < min_lead_s:
        fire += datetime.timedelta(minutes=1)
    return f'at({fire:%Y-%m-%dT%H:%M:%S})', fire


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:data-plane', 'concern:representation',
      'dp:api', 'plane:data', 'timing:real-time')
def run(ctx) -> None:
    """Same-named tables in two regions: a scheduled action put in the second region fires and
    raises only that table; the first region lists no action, no activity, and keeps its capacity.
    """
    other = _other_region(ctx.region)
    ddb_home, aas_home = ctx.client('dynamodb'), ctx.client('application-autoscaling')
    ddb_far = ctx.client('dynamodb', region=other)
    aas_far = ctx.client('application-autoscaling', region=other)
    name = ctx.unique_name('sim2real-behav-aas-rgn-')
    resource_id = f'table/{name}'
    action = ctx.unique_name('sim2real-behav-aas-rgn-sa-')
    for ddb in (ddb_home, ddb_far):
        _table(ctx, ddb, name, read=2)
    for aas in (aas_home, aas_far):
        _register(ctx, aas, resource_id, _READ, 1, 10)

    schedule, fire_at = _next_minute_at()
    # Deregistering the target deletes its scheduled actions, so the target's cleanup covers it.
    aas_far.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_READ,
        ScheduledActionName=action, Schedule=schedule,
        ScalableTargetAction={'MinCapacity': 5, 'MaxCapacity': 10})

    far = _poll_until(
        lambda: _activities(aas_far, resource_id),
        lambda acts: len(acts) >= 2 and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=_FIRING_TIMEOUT_S, interval_s=5.0,
        description=f'the second-region action firing at {fire_at.isoformat()} and its '
                    f'scale-out, both Successful')
    # DescribeScalingActivities documents no result order, so the activities compare as a multiset.
    assert sorted((a['Cause'], a['Description']) for a in far) == sorted([
        ('minimum capacity was set to 5', 'Setting read capacity units to 5.'),
        (f'scheduled action name {action} was triggered',
         'Setting min capacity to 5 and max capacity to 10'),
    ]), f'second-region activities were {[(a["Cause"], a["Description"]) for a in far]!r}'
    far_table = _poll_until(lambda: ddb_far.describe_table(TableName=name)['Table'],
                            lambda t: t['TableStatus'] == 'ACTIVE', timeout_s=120,
                            description=f'the {other} table settling ACTIVE')
    assert far_table['ProvisionedThroughput']['ReadCapacityUnits'] == 5, (
        f'the {other} table reads {far_table["ProvisionedThroughput"]["ReadCapacityUnits"]} '
        f'read capacity units; its scheduled floor of 5 must reach it')

    home_actions = aas_home.describe_scheduled_actions(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_READ)['ScheduledActions']
    assert home_actions == [], (
        f'{ctx.region} lists {len(home_actions)} scheduled actions for the same resource id; '
        f'the action was put in {other} only')
    home_acts = _activities(aas_home, resource_id)
    assert home_acts == [], (
        f'{ctx.region} recorded {len(home_acts)} activities: '
        f'{[a["Description"] for a in home_acts]!r}; nothing was scheduled there')
    home_table = ddb_home.describe_table(TableName=name)['Table']['ProvisionedThroughput']
    assert home_table['ReadCapacityUnits'] == 2, (
        f'the {ctx.region} table moved to {home_table["ReadCapacityUnits"]} read capacity units; '
        f'only the {other} table was scheduled')
    home_target = aas_home.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_READ)['ScalableTargets']
    assert [(t['MinCapacity'], t['MaxCapacity']) for t in home_target] == [(1, 10)], (
        f'the {ctx.region} target reads back as '
        f'{[(t["MinCapacity"], t["MaxCapacity"]) for t in home_target]!r}, expected [(1, 10)]')


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _table(ctx, ddb, name, *, read=1, write=1):
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': read, 'WriteCapacityUnits': write},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, name))
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


def _deregister(aas, resource_id, dimension):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=dimension)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _register(ctx, aas, resource_id, dimension, low, high):
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=dimension, MinCapacity=low, MaxCapacity=high)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id, dimension))


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
