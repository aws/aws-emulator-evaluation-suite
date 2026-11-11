"""register-scalable-target-clamps-capacity-into-bounds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-scalable-target-clamps-capacity-into-bounds"
GROUP = 'scalable-targets'
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


@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """Bounds that exclude the table's current capacity make Application Auto Scaling move it, up
    to MinCapacity and down to MaxCapacity with no policy, each recorded as its own activity.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-clamp-')
    resource_id = f'table/{table}'

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}, {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {table!r} becoming ACTIVE')

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    assert ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits'] == 1, (
        'registering bounds that already contain the current capacity must not move it'
    )

    # Raise the floor above the live capacity: 1 is now out of [5, 10].
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=5, MaxCapacity=10)
    up = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: len(acts) >= 1 and _terminal(acts[0]), timeout_s=140, interval_s=4.0,
        description='a terminal scaling activity correcting capacity up to the new minimum')[0]
    assert up['Cause'] == 'minimum capacity was set to 5', (
        f'the scale-up cause was {up["Cause"]!r}; real AWS attributes a floor correction to '
        f'"minimum capacity was set to 5"'
    )
    assert up['Description'] == 'Setting read capacity units to 5.', (
        f'the scale-up description was {up["Description"]!r}, expected '
        f'"Setting read capacity units to 5."'
    )
    assert up['StatusCode'] == 'Successful', (
        f'the scale-up finished {up["StatusCode"]!r}, expected "Successful"'
    )
    assert up['StatusMessage'] == (
        'Successfully set read capacity units to 5. Change successfully fulfilled by dynamodb.'
    ), f'the scale-up status message was {up["StatusMessage"]!r}'
    raised = ddb.describe_table(TableName=table)['Table']['ProvisionedThroughput']
    assert raised['ReadCapacityUnits'] == 5, (
        f'table read capacity is {raised["ReadCapacityUnits"]} after the floor moved to 5; a '
        f'capacity below MinCapacity must be corrected up to it'
    )

    # Drop the ceiling below the live capacity: 5 is now out of [1, 3].
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=3)
    down = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: len(acts) >= 2 and _terminal(acts[0]), timeout_s=140, interval_s=4.0,
        description='a terminal scaling activity correcting capacity down to the new maximum')[0]
    assert down['Cause'] == 'maximum capacity was set to 3', (
        f'the scale-down cause was {down["Cause"]!r}; real AWS attributes a ceiling correction '
        f'to "maximum capacity was set to 3"'
    )
    assert down['Description'] == 'Setting read capacity units to 3.', (
        f'the scale-down description was {down["Description"]!r}, expected '
        f'"Setting read capacity units to 3."'
    )
    lowered = ddb.describe_table(TableName=table)['Table']['ProvisionedThroughput']
    assert lowered['ReadCapacityUnits'] == 3, (
        f'table read capacity is {lowered["ReadCapacityUnits"]} after the ceiling moved to 3; a '
        f'capacity above MaxCapacity must be corrected down to it'
    )
    assert lowered['WriteCapacityUnits'] == 1, (
        f'write capacity moved to {lowered["WriteCapacityUnits"]}; bounds on {_DIM!r} must not '
        f'touch the write dimension'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
