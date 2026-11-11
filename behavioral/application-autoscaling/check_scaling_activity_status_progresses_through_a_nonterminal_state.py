"""scaling-activity-status-progresses-through-a-nonterminal-state."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scaling-activity-status-progresses-through-a-nonterminal-state"
GROUP = 'scaling-activities'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'

_MIN_CAPACITY = 1
_MAX_CAPACITY = 100
#: Large enough that DynamoDB takes visible time to apply it, small enough to stay cheap.
_BUMP_TO = 60
_SECOND_BUMP_TO = 70

_TERMINAL = ('Successful', 'Overridden', 'Unfulfilled', 'Failed')
#: The documented progression. Index order is what "must not regress" means.
_ORDER = ('Pending', 'InProgress') + _TERMINAL
_NON_TERMINAL = ('Pending', 'InProgress')

_FAST_INTERVAL_S = 0.5
_OBSERVE_S = 150.0
_SECOND_S = 90.0
_FREEZE_READS = 3


def _poll_until(probe, predicate, *, timeout_s, interval_s=4.0, description='condition'):
    """Bounded retry that raises on timeout, never returns its last value."""
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
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id, 'ScalableDimension': _DIM,
                  'IncludeNotScaledActivities': True}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """One scaling activity progresses through a non-terminal status to Successful without regressing,
    has EndTime exactly when terminal, and the history lists the newest activity first.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scaling-activities.html
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    account = ctx.client('sts').get_caller_identity()['Account']
    table = ctx.unique_name('sim2real-behav-aas-status-')
    resource_id = f'table/{table}'

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': _MIN_CAPACITY, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK},
              {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {table!r} becoming ACTIVE')
    started_at = ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits']
    assert started_at == _MIN_CAPACITY, (
        f'table {table!r} in region {ctx.region} of account {account} reports {started_at} read '
        f'capacity units, expected {_MIN_CAPACITY}; the size of the change is what makes the '
        f'non-terminal states observable'
    )

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    assert _activities(aas, resource_id) == [], (
        'a freshly registered target must start with an empty activity history, or the single-id '
        'arithmetic below counts activities this check did not cause'
    )

    # Cause exactly one activity, with no policy, alarm or metric as a second source.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=_BUMP_TO,
                                 MaxCapacity=_MAX_CAPACITY)

    observations = []
    deadline = time.monotonic() + _OBSERVE_S
    while time.monotonic() < deadline:
        current = _activities(aas, resource_id)
        if current:
            observations.append(current)
            if current[0]['StatusCode'] in _TERMINAL:
                break
        time.sleep(_FAST_INTERVAL_S)
    assert observations, (
        f'DescribeScalingActivities stayed empty for {_OBSERVE_S}s after MinCapacity was raised to '
        f'{_BUMP_TO} on {resource_id!r}; raising the floor above the live capacity of '
        f'{_MIN_CAPACITY} must record an activity'
    )
    assert observations[-1][0]['StatusCode'] in _TERMINAL, (
        f'the activity never reached a terminal status within {_OBSERVE_S}s; the last seen was '
        f'{observations[-1][0]["StatusCode"]!r}'
    )

    ids = {a['ActivityId'] for snapshot in observations for a in snapshot}
    assert len(ids) == 1, (
        f'raising MinCapacity once produced {len(ids)} distinct activity ids {sorted(ids)!r}; the '
        f'progression claim is about ONE activity changing state, not several rows appearing'
    )
    activity_id = ids.pop()

    seen = [snapshot[0] for snapshot in observations]
    codes = [a['StatusCode'] for a in seen]
    for code in codes:
        assert code in _ORDER, (
            f'the activity reported StatusCode {code!r}, which is not in the modelled '
            f'ScalingActivityStatusCode enum {_ORDER!r}. Observed sequence: {codes!r}'
        )
    ranks = [_ORDER.index(code) for code in codes]
    assert ranks == sorted(ranks), (
        f'the activity {activity_id!r} regressed through the documented status order: observed '
        f'{codes!r}, which is not non-decreasing under {_ORDER!r}. A scaling activity is a state '
        f'machine and must not go backwards'
    )

    # AWS documents a Pending status before the target responds; the large capacity change keeps
    # the non-terminal window wide enough to catch at the fast poll interval.
    non_terminal = [a for a in seen if a['StatusCode'] in _NON_TERMINAL]
    assert non_terminal, (
        f'the activity {activity_id!r} was never observed in a non-terminal state across '
        f'{len(seen)} reads at {_FAST_INTERVAL_S}s intervals while DynamoDB applied a change from '
        f'{_MIN_CAPACITY} to {_BUMP_TO} read capacity units; the codes seen were {sorted(set(codes))!r}. '
        f'AWS documents that "all scaling activities have a Pending status before the target service '
        f'responds", so a target that only ever shows a terminal status is writing one row rather '
        f'than deriving a state'
    )

    # EndTime is present exactly when the status is terminal.
    for activity in seen:
        if activity['StatusCode'] in _TERMINAL:
            assert 'EndTime' in activity, (
                f'the activity {activity_id!r} reported terminal status '
                f'{activity["StatusCode"]!r} with no EndTime'
            )
            assert activity['EndTime'] >= activity['StartTime'], (
                f'the activity {activity_id!r} reported EndTime '
                f'{activity["EndTime"].isoformat()} before its StartTime '
                f'{activity["StartTime"].isoformat()}'
            )
        else:
            assert 'EndTime' not in activity, (
                f'the activity {activity_id!r} reported non-terminal status '
                f'{activity["StatusCode"]!r} but already carries EndTime '
                f'{activity.get("EndTime")!r}; an activity that has not finished has no end'
            )

    final = seen[-1]
    assert final['StatusCode'] == 'Successful', (
        f'the activity {activity_id!r} finished {final["StatusCode"]!r}, expected "Successful"; '
        f'raising the floor to {_BUMP_TO} within a MaxCapacity of {_MAX_CAPACITY} must succeed'
    )
    assert final['Cause'] == f'minimum capacity was set to {_BUMP_TO}', (
        f'the activity attributes itself to {final["Cause"]!r}; a floor raise is recorded as '
        f'"minimum capacity was set to {_BUMP_TO}"'
    )
    assert final['Description'] == f'Setting read capacity units to {_BUMP_TO}.', (
        f'the activity described itself as {final["Description"]!r}, expected "Setting read '
        f'capacity units to {_BUMP_TO}."'
    )

    # Repeated reads of a finished activity must not advance anything.
    frozen = []
    for _ in range(_FREEZE_READS):
        time.sleep(2.0)
        latest = _activities(aas, resource_id)
        assert len(latest) == 1, (
            f'DescribeScalingActivities reports {len(latest)} activities after the single floor '
            f'raise settled: {[a.get("Description") for a in latest]!r}'
        )
        frozen.append((latest[0]['StatusCode'], latest[0]['EndTime']))
    assert len(set(frozen)) == 1, (
        f'{_FREEZE_READS} consecutive reads of the finished activity {activity_id!r} returned '
        f'{frozen!r}; a terminal activity must not change on a read'
    )

    # A second activity is listed first, ahead of the older terminal one.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=_SECOND_BUMP_TO,
                                 MaxCapacity=_MAX_CAPACITY)
    two = _poll_until(
        lambda: _activities(aas, resource_id), lambda acts: len(acts) == 2,
        timeout_s=_SECOND_S, interval_s=_FAST_INTERVAL_S,
        description=f'a second activity appearing after MinCapacity was raised to '
                    f'{_SECOND_BUMP_TO} on {resource_id!r}')
    assert two[0]['ActivityId'] != activity_id, (
        f'the newest of the two activities is still {activity_id!r}; the second floor raise must be '
        f'its own activity and must be listed first'
    )
    assert two[1]['ActivityId'] == activity_id, (
        f'the older of the two activities is {two[1]["ActivityId"]!r}, not the first one '
        f'{activity_id!r}; the history is ordered newest first'
    )
    assert two[0]['StartTime'] > two[1]['StartTime'], (
        f'the newest activity reports StartTime {two[0]["StartTime"].isoformat()}, not after the '
        f'older one at {two[1]["StartTime"].isoformat()}'
    )
    # A non-terminal activity leading the list is only observable when the second change is caught
    # in flight, so both arms assert the EndTime polarity.
    if two[0]['StatusCode'] in _TERMINAL:
        assert 'EndTime' in two[0], (
            f'the newest activity reports terminal status {two[0]["StatusCode"]!r} with no EndTime'
        )
        print(f'[MEASURE] the second activity was already {two[0]["StatusCode"]!r} on first sight; '
              f'raise the gap between _BUMP_TO ({_BUMP_TO}) and _SECOND_BUMP_TO '
              f'({_SECOND_BUMP_TO}) so a non-terminal activity can be observed LEADING the list')
    else:
        assert 'EndTime' not in two[0], (
            f'the newest activity is non-terminal ({two[0]["StatusCode"]!r}) and yet already '
            f'carries EndTime {two[0].get("EndTime")!r} while being listed AHEAD of a terminal '
            f'activity; ordering by EndTime cannot produce this list, which is the point'
        )

    throughput = _poll_until(
        lambda: ddb.describe_table(TableName=table)['Table']['ProvisionedThroughput'],
        lambda t: t['ReadCapacityUnits'] == _SECOND_BUMP_TO, timeout_s=_SECOND_S, interval_s=4.0,
        description=f'DynamoDB reporting {_SECOND_BUMP_TO} read capacity units for {table!r}')
    assert throughput['ReadCapacityUnits'] == _SECOND_BUMP_TO, (
        f'table read capacity is {throughput["ReadCapacityUnits"]}, expected {_SECOND_BUMP_TO}; the '
        f'activity history claims fulfilled changes that DynamoDB does not show'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
