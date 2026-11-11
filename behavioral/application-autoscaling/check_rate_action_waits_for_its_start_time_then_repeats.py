"""rate-action-waits-for-its-start-time-then-repeats."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rate-action-waits-for-its-start-time-then-repeats"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_START_LEAD_S = 75
_FIRING_TIMEOUT_S = 300
_CLOCK_SLACK = datetime.timedelta(seconds=2)


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


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:data-plane', 'concern:representation',
      'dp:api', 'plane:data', 'timing:real-time')
def run(ctx) -> None:
    """A rate() scheduled action with a future StartTime does not fire before that instant, then
    fires on its interval -- each firing is its own activity -- and drags real table capacity up.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-rstart-')
    action = ctx.unique_name('sim2real-behav-aas-rsa-')
    resource_id = f'table/{table}'

    _create_table(ddb, table, 1)
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _wait_active(ddb, table)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    start = (datetime.datetime.now(datetime.timezone.utc)
             + datetime.timedelta(seconds=_START_LEAD_S)).replace(microsecond=0)
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule='rate(1 minute)', StartTime=start,
        ScalableTargetAction={'MinCapacity': 2},
    )
    # Deregistering the target deletes its scheduled actions, so the target's cleanup covers it.
    stored = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id,
                                            ScheduledActionNames=[action])['ScheduledActions']
    assert len(stored) == 1, f'expected one stored scheduled action, got {stored!r}'
    assert stored[0]['Schedule'] == 'rate(1 minute)', (
        f'the stored schedule is {stored[0]["Schedule"]!r}, expected "rate(1 minute)"')
    assert stored[0].get('StartTime') == start, (
        f'StartTime came back as {stored[0].get("StartTime")!r}, expected {start.isoformat()}')

    first_seen = {}

    def _probe():
        found = _triggers(_activities(aas, resource_id), action)
        now = datetime.datetime.now(datetime.timezone.utc)
        for a in found:
            first_seen.setdefault(a['ActivityId'], now)
        return found

    fired = _poll_until(
        _probe, lambda acts: len(acts) >= 2 and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=_FIRING_TIMEOUT_S, interval_s=5.0,
        description=f'two successful firings of {action!r} after its StartTime {start.isoformat()}')

    early = sorted(t.isoformat() for t in first_seen.values() if t < start - _CLOCK_SLACK)
    assert not early, (
        f'a firing of the rate action was already listed at {early!r}, before its StartTime '
        f'{start.isoformat()}')
    stamped_early = sorted(a['StartTime'].isoformat() for a in fired
                           if a['StartTime'] < start - _CLOCK_SLACK)
    assert not stamped_early, (
        f'firing activities are stamped {stamped_early!r}, before StartTime {start.isoformat()}')
    assert len({a['ActivityId'] for a in fired}) == len(fired), (
        f'the firings share an ActivityId; each recurrence must be its own activity: '
        f'{[a["ActivityId"] for a in fired]!r}')
    assert all(a['Description'] == 'Setting min capacity to 2' for a in fired), (
        f'firing descriptions were {[a["Description"] for a in fired]!r}, expected each to be '
        f'"Setting min capacity to 2"')

    target = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[resource_id],
                                           ScalableDimension=_DIM)['ScalableTargets'][0]
    assert (target['MinCapacity'], target['MaxCapacity']) == (2, 20), (
        f'bounds are ({target["MinCapacity"]}, {target["MaxCapacity"]}); the action sets only the '
        f'floor to 2 and must leave the registered ceiling of 20')
    capacity = _poll_until(
        lambda: ddb.describe_table(TableName=table)['Table'],
        lambda t: t['TableStatus'] == 'ACTIVE' and t['ProvisionedThroughput']['ReadCapacityUnits'] == 2,
        timeout_s=120, interval_s=5.0,
        description=f'table {table!r} ACTIVE at read capacity 2')['ProvisionedThroughput']
    assert capacity['ReadCapacityUnits'] == 2, f'read capacity is {capacity["ReadCapacityUnits"]}'


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
