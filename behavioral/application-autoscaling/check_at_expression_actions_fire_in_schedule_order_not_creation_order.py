"""at-expression-actions-fire-in-schedule-order-not-creation-order."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "at-expression-actions-fire-in-schedule-order-not-creation-order"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'

_MIN_CAPACITY = 1
_MAX_CAPACITY = 20
#: The FIRST action to fire rewrites both bounds.
_FIRST_MIN = 3
_FIRST_MAX = 12
#: The SECOND action to fire rewrites ONLY the floor, so _FIRST_MAX must survive it.
_SECOND_MIN = 5

_LEAD_S = 70
#: Dispatch latency after the at() instant is undocumented; this caps only the wait, never a verdict.
_DISPATCH_S = 300.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=4.0, description='condition',
                budget_s=None):
    """Bounded retry that raises on timeout, never returns its last value; a stop forced by the
    runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    deadline = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if budget_s is not None and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s wait for {description} ended; last saw {last!r}; not graded"
        )
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


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
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id, 'ScalableDimension': _DIM,
                  'IncludeNotScaledActivities': True}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _terminal(activity):
    return activity['StatusCode'] in ('Successful', 'Failed', 'Overridden', 'Unfulfilled')


def _two_at_instants(min_lead_s):
    """Two consecutive whole UTC minutes, the first at least ``min_lead_s`` away.

    Returned as `at(yyyy-mm-ddThh:mm:ss)` expressions together with the instants they name.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    first = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    while (first - now).total_seconds() < min_lead_s:
        first += datetime.timedelta(minutes=1)
    second = first + datetime.timedelta(minutes=1)
    fmt = '%Y-%m-%dT%H:%M:%S'
    return (f'at({first.strftime(fmt)})', first), (f'at({second.strftime(fmt)})', second)


# timing:real-time — schedule: 120 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:representation', 'plane:control',
      'timing:real-time')
def run(ctx) -> None:
    """Two `at()` scheduled actions on one target, created in reverse, fire in schedule order, and
    the later one's MinCapacity-only action leaves the MaxCapacity the earlier one wrote.

    Reference: https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScheduledAction.html
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    account = ctx.client('sts').get_caller_identity()['Account']
    table = ctx.unique_name('sim2real-behav-aas-atorder-')
    resource_id = f'table/{table}'

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK},
              {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {table!r} becoming ACTIVE')
    assert ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits'] == 1, (
        f'table {table!r} in region {ctx.region} of account {account} did not start at 1 read '
        f'capacity unit; both floor corrections below are relative to that'
    )

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    assert _activities(aas, resource_id) == [], (
        'a freshly registered target must start with an empty activity history, or the ordering '
        'arithmetic below counts activities this check did not cause'
    )

    (first_schedule, first_at), (second_schedule, second_at) = _two_at_instants(_LEAD_S)
    assert first_schedule != second_schedule, (
        f'both actions were given the same schedule {first_schedule!r}; the ordering claim would be '
        f'vacuous'
    )
    assert (second_at - first_at).total_seconds() == 60, (
        f'the two instants {first_at.isoformat()} and {second_at.isoformat()} are not exactly one '
        f'minute apart, so "fired in schedule order" could be explained by clock granularity'
    )

    # CREATED IN REVERSE. `later` is put first and fires second; `earlier` is put second and fires
    # first. This is the whole discriminator against an insertion-ordered scheduler.
    later = ctx.unique_name('sim2real-behav-aas-atlater-')
    earlier = ctx.unique_name('sim2real-behav-aas-atearlier-')
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=later, Schedule=second_schedule, Timezone='UTC',
        # Floor only: _FIRST_MAX must survive this action.
        ScalableTargetAction={'MinCapacity': _SECOND_MIN},
    )
    ctx.on_cleanup(lambda: _delete_action(aas, resource_id, later))
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=earlier, Schedule=first_schedule, Timezone='UTC',
        ScalableTargetAction={'MinCapacity': _FIRST_MIN, 'MaxCapacity': _FIRST_MAX},
    )
    ctx.on_cleanup(lambda: _delete_action(aas, resource_id, earlier))

    stored = {a['ScheduledActionName']: a for a in aas.describe_scheduled_actions(
        ServiceNamespace=_NS, ResourceId=resource_id)['ScheduledActions']}
    assert set(stored) == {later, earlier}, (
        f'DescribeScheduledActions reports {sorted(stored)!r}, expected both '
        f'{sorted((later, earlier))!r}; a scheduler with one slot per target keeps only one'
    )
    assert stored[earlier]['Schedule'] == first_schedule, (
        f'the earlier action came back carrying {stored[earlier]["Schedule"]!r}, expected '
        f'{first_schedule!r}'
    )
    assert stored[later]['Schedule'] == second_schedule, (
        f'the later action came back carrying {stored[later]["Schedule"]!r}, expected '
        f'{second_schedule!r}'
    )
    assert 'MaxCapacity' not in stored[later]['ScalableTargetAction'], (
        f'the later action came back with ScalableTargetAction '
        f'{stored[later]["ScalableTargetAction"]!r}; it was sent with MinCapacity only, and a '
        f'MaxCapacity invented here would make the partial-update claim untestable'
    )

    # Both dispatches plus the floor correction each one causes: 1 -> _FIRST_MIN, then
    # _FIRST_MIN -> _SECOND_MIN.
    dispatch_wait_s = _DISPATCH_S + 60.0 + max(
        0.0, (second_at - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
    activities = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: len(acts) >= 4 and all(_terminal(a) for a in acts),
        timeout_s=dispatch_wait_s,
        budget_s=_budget_s(ctx, dispatch_wait_s),
        interval_s=5.0,
        description=f'both at() actions firing -- {earlier!r} at {first_at.isoformat()} and '
                    f'{later!r} at {second_at.isoformat()} -- and the two floor corrections they '
                    f'cause, all terminal')
    assert len(activities) == 4, (
        f'expected exactly four activities (two scheduled dispatches and the two floor corrections '
        f'they trigger) but saw {len(activities)}: '
        f'{[(a.get("Cause"), a.get("Description")) for a in activities]!r}'
    )

    by_cause = {a['Cause']: a for a in activities}
    earlier_cause = f'scheduled action name {earlier} was triggered'
    later_cause = f'scheduled action name {later} was triggered'
    assert earlier_cause in by_cause, (
        f'no activity attributes itself to {earlier_cause!r}; the causes present are '
        f'{sorted(by_cause)!r}'
    )
    assert later_cause in by_cause, (
        f'no activity attributes itself to {later_cause!r}; the causes present are '
        f'{sorted(by_cause)!r}'
    )
    earlier_dispatch, later_dispatch = by_cause[earlier_cause], by_cause[later_cause]

    # Creation order was (later, earlier); firing order must be the reverse.
    assert earlier_dispatch['StartTime'] < later_dispatch['StartTime'], (
        f'the action scheduled for {first_at.isoformat()} started at '
        f'{earlier_dispatch["StartTime"].isoformat()} and the one scheduled for '
        f'{second_at.isoformat()} started at {later_dispatch["StartTime"].isoformat()}. They were '
        f'CREATED in the opposite order -- {later!r} first, {earlier!r} second -- so an '
        f'insertion-ordered scheduler dispatches them the other way round. Schedule order must win'
    )
    assert earlier_dispatch['EndTime'] <= later_dispatch['StartTime'], (
        f'the earlier dispatch ended at {earlier_dispatch["EndTime"].isoformat()}, after the later '
        f'one started at {later_dispatch["StartTime"].isoformat()}; changes on one target serialise'
    )
    for name, activity, instant in ((earlier, earlier_dispatch, first_at),
                                    (later, later_dispatch, second_at)):
        assert activity['StartTime'] >= instant, (
            f'the dispatch for {name!r} reports StartTime '
            f'{activity["StartTime"].isoformat()}, BEFORE the instant {instant.isoformat()} its '
            f'at() expression names; a scheduled action must not run early'
        )
        assert activity['StatusCode'] == 'Successful', (
            f'the dispatch for {name!r} finished {activity["StatusCode"]!r}, expected "Successful"'
        )

    # The earlier action set both bounds, so the both-bounds phrasing applies; the later action set
    # only a floor, so only the floor may be named.
    assert earlier_dispatch['Description'] == (
        f'Setting min capacity to {_FIRST_MIN} and max capacity to {_FIRST_MAX}'
    ), f'the earlier dispatch described itself as {earlier_dispatch["Description"]!r}'
    assert f'{_SECOND_MIN}' in later_dispatch['Description'], (
        f'the later dispatch described itself as {later_dispatch["Description"]!r}, which does not '
        f'name the minimum capacity {_SECOND_MIN} it set'
    )
    assert 'max capacity' not in later_dispatch['Description'], (
        f'the later dispatch described itself as {later_dispatch["Description"]!r}; it carried no '
        f'MaxCapacity, so naming a maximum means one was invented'
    )

    # The partial-update claim, read at the target rather than off either response.
    final = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id],
        ScalableDimension=_DIM)['ScalableTargets']
    assert len(final) == 1, (
        f'DescribeScalableTargets returned {len(final)} targets for {resource_id!r}: {final!r}'
    )
    assert final[0]['MinCapacity'] == _SECOND_MIN, (
        f'the target reports MinCapacity {final[0]["MinCapacity"]}; the later action set the floor '
        f'to {_SECOND_MIN} and it fired last'
    )
    assert final[0]['MaxCapacity'] == _FIRST_MAX, (
        f'the target reports MaxCapacity {final[0]["MaxCapacity"]}, expected {_FIRST_MAX}. The '
        f'later action carried MinCapacity only, so it must leave the ceiling the earlier action '
        f'wrote. An implementation that treats ScalableTargetAction as a whole-record replacement '
        f'answers {_MAX_CAPACITY} (the registered ceiling) or drops the field entirely'
    )

    # The scheduled floor must reach DynamoDB, not just the record.
    throughput = _poll_until(
        lambda: ddb.describe_table(TableName=table)['Table']['ProvisionedThroughput'],
        lambda t: t['ReadCapacityUnits'] == _SECOND_MIN, timeout_s=90, interval_s=4.0,
        description=f'DynamoDB reporting {_SECOND_MIN} read capacity units for {table!r} after the '
                    f'second scheduled floor raise')
    assert throughput['ReadCapacityUnits'] == _SECOND_MIN, (
        f'table read capacity is {throughput["ReadCapacityUnits"]}, expected {_SECOND_MIN}; the '
        f'scheduled floor must reach DynamoDB and not only the Application Auto Scaling record'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
