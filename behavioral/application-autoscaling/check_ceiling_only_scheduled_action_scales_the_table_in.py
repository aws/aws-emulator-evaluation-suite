"""ceiling-only-scheduled-action-scales-the-table-in."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ceiling-only-scheduled-action-scales-the-table-in"
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
    """A scheduled action setting only MaxCapacity below the table's live capacity scales the table
    IN when it fires: the ceiling is rewritten, the floor kept, and DynamoDB records the cut.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-ceil-')
    action = ctx.unique_name('sim2real-behav-aas-ceil-sa-')
    resource_id = f'table/{table}'

    _create_table(ddb, table, 8)
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _wait_active(ddb, table)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    schedule, fire_at = _next_minute_at()
    # Deregistering the target deletes its scheduled actions, so the target's cleanup covers it.
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule=schedule,
        ScalableTargetAction={'MaxCapacity': 3},
    )
    stored = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id,
                                            ScheduledActionNames=[action])['ScheduledActions']
    assert len(stored) == 1 and stored[0]['ScalableTargetAction'] == {'MaxCapacity': 3}, (
        f'the ceiling-only action was not stored as {{"MaxCapacity": 3}}: {stored!r}')

    activities = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: len(acts) >= 2 and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=_FIRING_TIMEOUT_S, interval_s=5.0,
        description=f'the action firing at {fire_at.isoformat()} and the scale-in it causes, '
                    f'both Successful')
    assert len(activities) == 2, (
        f'expected the dispatch and one scale-in, saw {len(activities)}: '
        f'{[(a["Cause"], a["Description"]) for a in activities]!r}')
    scale_in, dispatch = activities[0], activities[1]
    assert dispatch['Cause'] == f'scheduled action name {action} was triggered', (
        f'the older activity has cause {dispatch["Cause"]!r}, expected the dispatch of {action!r}')
    assert dispatch['Description'] == 'Setting max capacity to 3', (
        f'the dispatch described itself as {dispatch["Description"]!r}, expected '
        f'"Setting max capacity to 3"')
    assert dispatch['StatusMessage'] == 'Successfully set max capacity to 3', (
        f'the dispatch status message was {dispatch["StatusMessage"]!r}')
    assert scale_in['Cause'] == 'maximum capacity was set to 3', (
        f'the follow-on activity cause was {scale_in["Cause"]!r}; a ceiling of 3 under a live '
        f'capacity of 8 is recorded as "maximum capacity was set to 3"')
    assert scale_in['Description'] == 'Setting read capacity units to 3.', (
        f'the follow-on activity described itself as {scale_in["Description"]!r}')
    assert scale_in['StatusMessage'] == (
        'Successfully set read capacity units to 3. Change successfully fulfilled by dynamodb.'
    ), f'the scale-in status message was {scale_in["StatusMessage"]!r}'

    target = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[resource_id],
                                           ScalableDimension=_DIM)['ScalableTargets'][0]
    assert (target['MinCapacity'], target['MaxCapacity']) == (1, 3), (
        f'bounds are ({target["MinCapacity"]}, {target["MaxCapacity"]}); a ceiling-only action '
        f'rewrites the maximum to 3 and keeps the registered minimum of 1')
    table_desc = _poll_until(
        lambda: ddb.describe_table(TableName=table)['Table'],
        lambda t: t['TableStatus'] == 'ACTIVE', timeout_s=120, interval_s=5.0,
        description=f'table {table!r} settling ACTIVE')
    throughput = table_desc['ProvisionedThroughput']
    assert throughput['ReadCapacityUnits'] == 3, (
        f'table read capacity is {throughput["ReadCapacityUnits"]}; the scheduled ceiling of 3 '
        f'must reach DynamoDB')
    assert throughput['NumberOfDecreasesToday'] == 1, (
        f'DynamoDB counts {throughput["NumberOfDecreasesToday"]} decreases today on a fresh table; '
        f'the scale-in from 8 to 3 is exactly one')
    assert throughput['WriteCapacityUnits'] == 1, (
        f'write capacity moved to {throughput["WriteCapacityUnits"]}; only reads were scheduled')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
