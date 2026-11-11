"""deregister-in-one-region-keeps-the-same-named-target-in-another."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-in-one-region-keeps-the-same-named-target-in-another"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_WRITE = 'dynamodb:table:WriteCapacityUnits'


def _other_region(region):
    return 'us-east-1' if region != 'us-east-1' else 'us-west-2'


def _policies(aas, resource_id):
    out = []
    for page in aas.get_paginator('describe_scaling_policies').paginate(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_WRITE):
        out.extend(page['ScalingPolicies'])
    return out


def _alarm_names(cw, names):
    out = []
    for page in cw.get_paginator('describe_alarms').paginate(AlarmNames=names):
        out.extend(a['AlarmName'] for a in page['MetricAlarms'])
    return sorted(out)


def _delete_alarms(cw, prefix):
    left = []
    for page in cw.get_paginator('describe_alarms').paginate(AlarmNamePrefix=prefix):
        left.extend(a['AlarmName'] for a in page['MetricAlarms'])
    if left:
        cw.delete_alarms(AlarmNames=left)


@tags('axis:happy-path', 'cap:c1', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """With the same resource id and policy name in two regions, deregistering in one region removes
    only that region's target, policy and alarms; the other region's stay intact.
    """
    other = _other_region(ctx.region)
    name = ctx.unique_name('sim2real-behav-aas-rgn-')
    resource_id = f'table/{name}'
    policy = ctx.unique_name('sim2real-behav-aas-rgn-tt-')
    sides = {}
    for region in (ctx.region, other):
        ddb = ctx.client('dynamodb', region=region)
        aas = ctx.client('application-autoscaling', region=region)
        cw = ctx.client('cloudwatch', region=region)
        _table(ctx, ddb, name)
        # Runs after the deregistration below (LIFO), removing any alarm the cascade left.
        ctx.on_cleanup(lambda cw=cw: _delete_alarms(cw, f'TargetTracking-{resource_id}-'))
        _register(ctx, aas, resource_id, _WRITE, 1, 5)
        alarms = aas.put_scaling_policy(
            PolicyName=policy, ServiceNamespace=_NS, ResourceId=resource_id,
            ScalableDimension=_WRITE, PolicyType='TargetTrackingScaling',
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': 70.0,
                'PredefinedMetricSpecification': {
                    'PredefinedMetricType': 'DynamoDBWriteCapacityUtilization'}})['Alarms']
        sides[region] = (aas, cw, sorted(a['AlarmName'] for a in alarms))

    aas_home, cw_home, home_alarms = sides[ctx.region]
    aas_far, cw_far, far_alarms = sides[other]
    assert len(home_alarms) == 4 and len(far_alarms) == 4, (
        f'each region minted {len(home_alarms)} / {len(far_alarms)} alarms, expected 4 each')
    _poll_until(lambda: _alarm_names(cw_far, far_alarms), lambda found: found == far_alarms,
                timeout_s=60, interval_s=3.0,
                description=f'the {other} policy alarms being visible')

    aas_home.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                        ScalableDimension=_WRITE)
    home_targets = aas_home.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_WRITE)['ScalableTargets']
    assert home_targets == [], f'{ctx.region} still lists {len(home_targets)} targets'
    assert _policies(aas_home, resource_id) == [], (
        f'{ctx.region} still lists a policy after its target was deregistered')
    _poll_until(lambda: _alarm_names(cw_home, home_alarms), lambda found: found == [],
                timeout_s=90, interval_s=3.0,
                description=f'the {ctx.region} alarms being removed with the target')

    far_targets = aas_far.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_WRITE)['ScalableTargets']
    assert [(t['MinCapacity'], t['MaxCapacity']) for t in far_targets] == [(1, 5)], (
        f'the {other} target reads back as '
        f'{[(t["MinCapacity"], t["MaxCapacity"]) for t in far_targets]!r}, expected [(1, 5)]')
    far_policies = _policies(aas_far, resource_id)
    assert [p['PolicyName'] for p in far_policies] == [policy], (
        f'{other} lists {len(far_policies)} policies, expected the one named policy')
    assert sorted(a['AlarmName'] for a in far_policies[0]['Alarms']) == far_alarms, (
        f'the {other} policy no longer lists the alarms it minted')
    assert _alarm_names(cw_far, far_alarms) == far_alarms, (
        f'the {other} alarms were removed by a deregistration in {ctx.region}')


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


def _table(ctx, ddb, name, *, read=1, write=1):
    """A PROVISIONED table ``name`` made through ``ddb``, ACTIVE, with its delete registered."""
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
