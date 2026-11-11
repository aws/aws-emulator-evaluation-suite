"""scheduled-action-cron-fires-and-moves-capacity."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-action-cron-fires-and-moves-capacity"
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


def _delete_action(aas, resource_id, action):
    try:
        aas.delete_scheduled_action(ServiceNamespace=_NS, ResourceId=resource_id,
                                    ScalableDimension=_DIM, ScheduledActionName=action)
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


def _next_cron_minute(min_lead_s=25):
    """The next whole UTC minute at least ``min_lead_s`` away, as a one-shot cron expression.

    The explicit year and day-of-month make it name a single instant, never a recurrence.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    fire = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    if (fire - now).total_seconds() < min_lead_s:
        fire += datetime.timedelta(minutes=1)
    return f'cron({fire.minute} {fire.hour} {fire.day} {fire.month} ? {fire.year})', fire


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:representation', 'plane:control',
      'timing:real-time')
def run(ctx) -> None:
    """A cron scheduled action fires at its instant: it rewrites the target's bounds to (4, 18), and
    the new floor triggers a second activity that raises DynamoDB's read capacity to 4.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-cron-')
    action = ctx.unique_name('sim2real-behav-aas-sa-')
    resource_id = f'table/{table}'

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {table!r} becoming ACTIVE')

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    schedule, fire_at = _next_cron_minute()
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule=schedule, Timezone='UTC',
        ScalableTargetAction={'MinCapacity': 4, 'MaxCapacity': 18},
    )
    ctx.on_cleanup(lambda: _delete_action(aas, resource_id, action))
    stored = aas.describe_scheduled_actions(
        ServiceNamespace=_NS, ResourceId=resource_id,
        ScheduledActionNames=[action])['ScheduledActions']
    assert len(stored) == 1 and stored[0]['Schedule'] == schedule, (
        f'the scheduled action did not come back as one entry carrying {schedule!r}: {stored!r}'
    )

    activities = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: len(acts) >= 2 and all(_terminal(a) for a in acts),
        timeout_s=210, interval_s=5.0,
        description=f'the cron scheduled action {action!r} firing at {fire_at.isoformat()} and '
                    f'the floor correction it causes, both terminal')
    assert len(activities) == 2, (
        f'expected exactly two activities -- the scheduled dispatch and the floor correction it '
        f'triggers -- but saw {len(activities)}: '
        f'{[(a["Cause"], a["Description"]) for a in activities]!r}'
    )
    dispatch, correction = activities[1], activities[0]
    assert dispatch['Cause'] == f'scheduled action name {action} was triggered', (
        f'the dispatch activity cause was {dispatch["Cause"]!r}; real AWS writes '
        f'"scheduled action name {action} was triggered"'
    )
    assert dispatch['Description'] == 'Setting min capacity to 4 and max capacity to 18', (
        f'the dispatch activity described itself as {dispatch["Description"]!r}, expected '
        f'"Setting min capacity to 4 and max capacity to 18"'
    )
    assert dispatch['StatusMessage'] == (
        'Successfully set min capacity to 4 and max capacity to 18'
    ), f'the dispatch status message was {dispatch["StatusMessage"]!r}'
    assert correction['Cause'] == 'minimum capacity was set to 4', (
        f'the follow-on activity cause was {correction["Cause"]!r}; the new floor of 4 above a '
        f'live capacity of 1 is recorded as "minimum capacity was set to 4"'
    )
    assert correction['Description'] == 'Setting read capacity units to 4.', (
        f'the follow-on activity described itself as {correction["Description"]!r}, expected '
        f'"Setting read capacity units to 4."'
    )

    target = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id])['ScalableTargets'][0]
    assert (target['MinCapacity'], target['MaxCapacity']) == (4, 18), (
        f'the scalable target bounds are '
        f'({target["MinCapacity"]}, {target["MaxCapacity"]}) after the action fired; a scheduled '
        f'action REWRITES the registered bounds to its ScalableTargetAction (4, 18)'
    )
    throughput = ddb.describe_table(TableName=table)['Table']['ProvisionedThroughput']
    assert throughput['ReadCapacityUnits'] == 4, (
        f'table read capacity is {throughput["ReadCapacityUnits"]}; the scheduled floor of 4 must '
        f'reach DynamoDB, not just the Application Auto Scaling record'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
