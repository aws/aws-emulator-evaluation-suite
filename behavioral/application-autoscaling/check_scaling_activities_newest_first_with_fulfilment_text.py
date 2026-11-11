"""scaling-activities-newest-first-with-fulfilment-text."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scaling-activities-newest-first-with-fulfilment-text"
GROUP = 'scaling-activities'
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
    """Every activity for this resource, following NextToken."""
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


@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """DescribeScalingActivities lists a target's history newest first, and each entry carries the
    terminal "Change successfully fulfilled by dynamodb." text once DynamoDB applied the capacity.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-acts-')
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
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    assert _activities(aas, resource_id) == [], (
        'a freshly registered target must start with an empty activity history'
    )

    # Wait for a terminal status so the two activities start at distinct, ordered times.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=3, MaxCapacity=10)
    _poll_until(lambda: _activities(aas, resource_id),
                lambda acts: len(acts) == 1 and _terminal(acts[0]),
                timeout_s=140, interval_s=4.0,
                description='the first (floor 3) activity reaching a terminal status')

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=6, MaxCapacity=10)
    activities = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: len(acts) == 2 and all(_terminal(a) for a in acts),
        timeout_s=140, interval_s=4.0,
        description='the second (floor 6) activity reaching a terminal status')

    assert len(activities) == 2, (
        f'expected exactly the two activities this check caused, saw {len(activities)}: '
        f'{[a["Cause"] for a in activities]!r}'
    )
    newer, older = activities
    assert newer['StartTime'] > older['StartTime'], (
        f'DescribeScalingActivities returned {older["StartTime"]!r} before '
        f'{newer["StartTime"]!r}; real AWS orders the history newest first'
    )
    assert newer['Cause'] == 'minimum capacity was set to 6', (
        f'the first entry is {newer["Cause"]!r}; the newest activity is the floor-6 one'
    )
    assert older['Cause'] == 'minimum capacity was set to 3', (
        f'the second entry is {older["Cause"]!r}; the older activity is the floor-3 one'
    )
    for activity, units in ((newer, 6), (older, 3)):
        assert activity['StatusCode'] == 'Successful', (
            f'the floor-{units} activity finished {activity["StatusCode"]!r}, expected "Successful"'
        )
        assert activity['Description'] == f'Setting read capacity units to {units}.', (
            f'the floor-{units} activity described itself as {activity["Description"]!r}'
        )
        assert activity['StatusMessage'] == (
            f'Successfully set read capacity units to {units}. '
            f'Change successfully fulfilled by dynamodb.'
        ), (
            f'the floor-{units} activity status message was {activity["StatusMessage"]!r}; the '
            f'terminal wording names the service that fulfilled the change'
        )
        assert activity['EndTime'] > activity['StartTime'], (
            f'the floor-{units} activity ended at {activity["EndTime"]!r}, not after its start '
            f'{activity["StartTime"]!r}'
        )
        assert activity['ResourceId'] == resource_id, (
            f'the floor-{units} activity named resource {activity["ResourceId"]!r}'
        )
    assert older['EndTime'] <= newer['StartTime'], (
        f'the floor-3 activity ended at {older["EndTime"]!r}, after the floor-6 activity started '
        f'at {newer["StartTime"]!r}; capacity changes on one target serialise'
    )
    assert ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits'] == 6, (
        'the history claims a fulfilled change to 6 read capacity units that DynamoDB does not show'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
