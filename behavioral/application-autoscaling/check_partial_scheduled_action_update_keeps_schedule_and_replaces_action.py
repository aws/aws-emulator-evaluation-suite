"""partial-scheduled-action-update-keeps-schedule-and-replaces-action."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partial-scheduled-action-update-keeps-schedule-and-replaces-action"
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
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:data-plane', 'concern:representation',
      'dp:api', 'plane:data', 'timing:real-time')
def run(ctx) -> None:
    """Re-putting an armed scheduled action with only a new ScalableTargetAction keeps its Schedule
    and Timezone but REPLACES the action whole: it fires on the old instant with the new floor and
    no ceiling, so the registered maximum is left as it was rather than merged from the old action.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-pupd-')
    action = ctx.unique_name('sim2real-behav-aas-pupd-sa-')
    resource_id = f'table/{table}'

    _create_table(ddb, table, 1)
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _wait_active(ddb, table)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    schedule, fire_at = _next_minute_at()
    # Deregistering the target deletes its scheduled actions, so the target's cleanup covers it.
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule=schedule, Timezone='Etc/UTC',
        ScalableTargetAction={'MinCapacity': 2, 'MaxCapacity': 6},
    )
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, ScalableTargetAction={'MinCapacity': 5},
    )
    stored = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id,
                                            ScheduledActionNames=[action])['ScheduledActions']
    assert len(stored) == 1, f'the update produced {len(stored)} actions, expected one: {stored!r}'
    assert stored[0]['Schedule'] == schedule, (
        f'an update that omitted Schedule changed it to {stored[0]["Schedule"]!r}; expected the '
        f'original {schedule!r} to be kept')
    assert stored[0].get('Timezone') == 'Etc/UTC', (
        f'an update that omitted Timezone left {stored[0].get("Timezone")!r}, expected "Etc/UTC"')
    assert stored[0]['ScalableTargetAction'] == {'MinCapacity': 5}, (
        f'the stored action is {stored[0]["ScalableTargetAction"]!r}; the update REPLACES it with '
        f'{{"MinCapacity": 5}} rather than merging the old MaxCapacity 6 back in')

    activities = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: len(acts) >= 2 and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=_FIRING_TIMEOUT_S, interval_s=5.0,
        description=f'the updated action firing at {fire_at.isoformat()} and the floor '
                    f'correction it causes, both Successful')
    assert len(activities) == 2, (
        f'expected one dispatch and one floor correction, saw '
        f'{[(a["Cause"], a["Description"]) for a in activities]!r}')
    correction, dispatch = activities[0], activities[1]
    assert dispatch['Cause'] == f'scheduled action name {action} was triggered', (
        f'the older activity has cause {dispatch["Cause"]!r}, expected the dispatch of {action!r}')
    assert dispatch['Description'] == 'Setting min capacity to 5', (
        f'the dispatch described itself as {dispatch["Description"]!r}; the updated action '
        f'carries only a floor, so it must read "Setting min capacity to 5"')
    assert correction['Description'] == 'Setting read capacity units to 5.', (
        f'the follow-on activity described itself as {correction["Description"]!r}')

    target = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[resource_id],
                                           ScalableDimension=_DIM)['ScalableTargets'][0]
    assert (target['MinCapacity'], target['MaxCapacity']) == (5, 20), (
        f'bounds are ({target["MinCapacity"]}, {target["MaxCapacity"]}); the replaced action sets '
        f'the floor to 5 and leaves the registered ceiling of 20 (a merge would have written 6)')
    capacity = _poll_until(
        lambda: ddb.describe_table(TableName=table)['Table'],
        lambda t: t['TableStatus'] == 'ACTIVE', timeout_s=120, interval_s=5.0,
        description=f'table {table!r} settling ACTIVE')['ProvisionedThroughput']
    assert capacity['ReadCapacityUnits'] == 5, (
        f'table read capacity is {capacity["ReadCapacityUnits"]}; the updated floor of 5 must reach '
        f'DynamoDB, not the original floor of 2')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
