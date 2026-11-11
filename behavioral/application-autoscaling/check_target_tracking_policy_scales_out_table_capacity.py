"""target-tracking-policy-scales-out-table-capacity."""
from __future__ import annotations

import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-tracking-policy-scales-out-table-capacity"
GROUP = 'scaling-policies'
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
    """Delete the table, tolerating the UPDATING window a scaling activity leaves behind."""
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


def _delete_policy(aas, resource_id, policy):
    try:
        aas.delete_scaling_policy(ServiceNamespace=_NS, ResourceId=resource_id,
                                  ScalableDimension=_DIM, PolicyName=policy)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _activities(aas, resource_id):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id,
                  'ScalableDimension': _DIM}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


# timing:real-time — metric: 120 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-target-tracking.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:representation', 'plane:control',
      'timing:real-time')
def run(ctx) -> None:
    """A target-tracking policy under real read load raises the table's provisioned read capacity
    to MaxCapacity, and the scaling activity names the AlarmHigh and policy that drove it.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-target-tracking.html
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-tt-')
    policy = ctx.unique_name('sim2real-behav-aas-ttpol-')
    resource_id = f'table/{table}'

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {table!r} becoming ACTIVE')
    ddb.put_item(TableName=table, Item={'pk': {'S': 'hot'}, 'payload': {'S': 'x' * 512}})

    # 1 provisioned RCU against a TargetValue of 40% puts the AlarmHigh threshold at
    # 0.40 * 60 * 1 == 24 consumed units per minute. Four strongly-consistent readers deliver
    # several hundred, so only CloudWatch's two 60 s evaluation periods bound the poll below.
    # SetAlarmState is no shortcut: target tracking re-reads the metric itself, so load is required.
    stop = threading.Event()

    def _drive_read_load():
        while not stop.is_set():
            try:
                ddb.get_item(TableName=table, Key={'pk': {'S': 'hot'}}, ConsistentRead=True)
            except ClientError:
                time.sleep(0.2)

    readers = [threading.Thread(target=_drive_read_load, daemon=True) for _ in range(4)]
    for reader in readers:
        reader.start()
    ctx.on_cleanup(stop.set)

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    put = aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy, PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration={
            'TargetValue': 40.0,
            'PredefinedMetricSpecification': {
                'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'},
            'ScaleOutCooldown': 0, 'ScaleInCooldown': 0},
    )
    ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, policy))
    alarm_high = [a['AlarmName'] for a in put['Alarms'] if '-AlarmHigh-' in a['AlarmName']]
    assert len(alarm_high) == 1, (
        f'PutScalingPolicy minted {len(alarm_high)} AlarmHigh alarms, expected exactly 1; '
        f'alarms were {[a["AlarmName"] for a in put["Alarms"]]!r}'
    )

    activities = _poll_until(
        lambda: _activities(aas, resource_id), bool, timeout_s=240, interval_s=5.0,
        description=f'a scaling activity for {resource_id!r} driven by the target-tracking '
                    f'AlarmHigh breaching on real read load')
    newest = activities[0]
    assert newest['Description'] == 'Setting read capacity units to 10.', (
        f'scale-out activity described itself as {newest["Description"]!r}; real AWS resolves '
        f'a 40% target under saturating load to the MaxCapacity of 10 and says '
        f'"Setting read capacity units to 10."'
    )
    assert newest['Cause'] == (
        f'monitor alarm {alarm_high[0]} in state ALARM triggered policy {policy}'
    ), (
        f'scale-out cause was {newest["Cause"]!r}; real AWS attributes it to the AlarmHigh '
        f'{alarm_high[0]!r} and the policy {policy!r}'
    )
    assert newest['ScalableDimension'] == _DIM, (
        f'activity carried scalable dimension {newest["ScalableDimension"]!r}, expected {_DIM!r}'
    )
    assert newest['ServiceNamespace'] == _NS, (
        f'activity carried service namespace {newest["ServiceNamespace"]!r}, expected {_NS!r}'
    )

    throughput = _poll_until(
        lambda: ddb.describe_table(TableName=table)['Table']['ProvisionedThroughput'],
        lambda t: t['ReadCapacityUnits'] != 1, timeout_s=90, interval_s=3.0,
        description=f'DynamoDB provisioned read capacity for {table!r} moving off 1')
    assert throughput['ReadCapacityUnits'] == 10, (
        f'table ended at {throughput["ReadCapacityUnits"]} read capacity units; the policy '
        f'resolves to the MaxCapacity of 10, so storing the policy without applying it is the '
        f'failure this asserts against'
    )
    assert throughput['WriteCapacityUnits'] == 1, (
        f'write capacity moved to {throughput["WriteCapacityUnits"]}; a policy on '
        f'{_DIM!r} must leave the write dimension alone'
    )

    target = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id])['ScalableTargets'][0]
    assert (target['MinCapacity'], target['MaxCapacity']) == (1, 10), (
        f'the scalable target bounds moved to '
        f'({target["MinCapacity"]}, {target["MaxCapacity"]}); dynamic scaling changes the '
        f'resource capacity, never the registered bounds'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
