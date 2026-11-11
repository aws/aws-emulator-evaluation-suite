"""reregistering-after-deregister-mints-a-new-target-without-the-old-tags-or-policy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reregistering-after-deregister-mints-a-new-target-without-the-old-tags-or-policy"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_PROV = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}



def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description='condition'):
    """Bounded poll that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _create_table(ctx, ddb, name, **extra):
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=extra.pop('AttributeDefinitions',
                                       [{'AttributeName': 'pk', 'AttributeType': 'S'}]),
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
        **extra,
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, name))
    _poll_until(lambda: ddb.describe_table(TableName=name)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=180, description=f'table {name!r} ACTIVE')


def _delete_table(ddb, name):
    """DeleteTable refuses while the table is UPDATING; retry that, bounded, and raise otherwise."""
    deadline = time.monotonic() + 45
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
            time.sleep(5)


def _deregister(aas, ns, resource_id, dim):
    try:
        aas.deregister_scalable_target(ServiceNamespace=ns, ResourceId=resource_id,
                                       ScalableDimension=dim)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _targets(aas, ns, resource_id):
    out = []
    for page in aas.get_paginator('describe_scalable_targets').paginate(
            ServiceNamespace=ns, ResourceIds=[resource_id]):
        out.extend(page['ScalableTargets'])
    return out


def _policies(aas, ns, resource_id):
    out = []
    for page in aas.get_paginator('describe_scaling_policies').paginate(
            ServiceNamespace=ns, ResourceId=resource_id):
        out.extend(page['ScalingPolicies'])
    return out


@tags('axis:happy-path', 'cap:c1', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """Re-registering a deregistered (table, dimension) mints a new target ARN with the new bounds
    and none of the old target's tags or scaling policies, as an IaC replace relies on.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-rereg-')
    _create_table(ctx, ddb, table, BillingMode='PROVISIONED', ProvisionedThroughput=_PROV)
    resource_id = f'table/{table}'
    policy = ctx.unique_name('sim2real-behav-aas-rereg-pol-')

    old_arn = aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=5, Tags={'generation': 'one'})['ScalableTargetARN']
    ctx.on_cleanup(lambda: _deregister(aas, _NS, resource_id, _DIM))
    aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM, PolicyName=policy,
        PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration={
            'TargetValue': 70.0,
            'PredefinedMetricSpecification': {
                'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'}})
    assert [p['PolicyName'] for p in _policies(aas, _NS, resource_id)] == [policy], (
        'the first generation did not store its policy')

    aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                   ScalableDimension=_DIM)
    new_arn = aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=8)['ScalableTargetARN']

    assert new_arn != old_arn, 're-registering after deregister returned the old target ARN'
    targets = _targets(aas, _NS, resource_id)
    assert [(t['ScalableTargetARN'] == new_arn, t['MinCapacity'], t['MaxCapacity'])
            for t in targets] == [(True, 1, 8)], (
        f'the table reads back {[(t["MinCapacity"], t["MaxCapacity"]) for t in targets]!r} over '
        f'{len(targets)} target(s); expected the one new target with bounds (1, 8)')
    new_tags = aas.list_tags_for_resource(ResourceARN=new_arn)['Tags']
    assert new_tags == {}, f'the new target inherited tags {new_tags!r} from the deregistered one'
    left = [p['PolicyName'] for p in _policies(aas, _NS, resource_id)]
    assert left == [], f'the new target carries policies {left!r} from the deregistered one'


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
