"""describe-dimension-filter-without-a-resource-id-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-dimension-filter-without-a-resource-id-rejected"
GROUP = 'state'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_READ = 'dynamodb:table:ReadCapacityUnits'


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    listed = {k: len(v) for k, v in result.items() if isinstance(v, list)}
    raise AssertionError(f'expected the call to be refused, but it succeeded: {listed!r}')


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """Every Describe* read refuses a ScalableDimension filter without a resource id (Targets says
    "resource IDs", the rest "a resource ID"); with the id added, the same filter finds the
    registered target, policy and scheduled action.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    name = ctx.unique_name('sim2real-behav-aas-flt-')
    policy = ctx.unique_name('sim2real-behav-aas-flt-tt-')
    action = ctx.unique_name('sim2real-behav-aas-flt-sa-')
    _table(ctx, ddb, name)
    rid = f'table/{name}'
    _register(ctx, aas, rid, _READ, 1, 4)
    # Deregistering the target deletes its policy, alarms and scheduled action.
    aas.put_scaling_policy(
        PolicyName=policy, ServiceNamespace=_NS, ResourceId=rid, ScalableDimension=_READ,
        PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration={
            'TargetValue': 70.0,
            'PredefinedMetricSpecification': {
                'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'}})
    aas.put_scheduled_action(ServiceNamespace=_NS, ResourceId=rid, ScalableDimension=_READ,
                             ScheduledActionName=action, Schedule='cron(0 3 1 1 ? *)',
                             ScalableTargetAction={'MinCapacity': 1, 'MaxCapacity': 4})

    refusals = {
        'DescribeScalableTargets': _error(lambda: aas.describe_scalable_targets(
            ServiceNamespace=_NS, ScalableDimension=_READ)),
        'DescribeScalingPolicies': _error(lambda: aas.describe_scaling_policies(
            ServiceNamespace=_NS, ScalableDimension=_READ)),
        'DescribeScheduledActions': _error(lambda: aas.describe_scheduled_actions(
            ServiceNamespace=_NS, ScalableDimension=_READ)),
        'DescribeScalingActivities': _error(lambda: aas.describe_scaling_activities(
            ServiceNamespace=_NS, ScalableDimension=_READ)),
    }
    plural = ('ValidationException', 'Scalable dimension cannot be provided without resource IDs.')
    singular = ('ValidationException',
                'Scalable dimension cannot be provided without a resource ID.')
    assert refusals == {'DescribeScalableTargets': plural, 'DescribeScalingPolicies': singular,
                        'DescribeScheduledActions': singular,
                        'DescribeScalingActivities': singular}, (
        f'a bare dimension filter was answered with {refusals!r}')
    named = _error(lambda: aas.describe_scaling_policies(
        ServiceNamespace=_NS, PolicyNames=[policy], ScalableDimension=_READ))
    assert named == singular, (
        f'naming the policy does not stand in for the resource id; got {named!r}')

    # Positive control: the same dimension filter with the resource id finds what was created.
    targets = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[rid],
                                            ScalableDimension=_READ)['ScalableTargets']
    policies = aas.describe_scaling_policies(ServiceNamespace=_NS, ResourceId=rid,
                                             ScalableDimension=_READ)['ScalingPolicies']
    actions = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=rid,
                                             ScalableDimension=_READ)['ScheduledActions']
    assert [(t['MinCapacity'], t['MaxCapacity']) for t in targets] == [(1, 4)], (
        f'the scoped target read is {[(t["MinCapacity"], t["MaxCapacity"]) for t in targets]!r}')
    assert [p['PolicyName'] for p in policies] == [policy], (
        f'the scoped policy read lists {len(policies)} policies, expected the one created')
    assert [a['ScheduledActionName'] for a in actions] == [action], (
        f'the scoped action read lists {len(actions)} actions, expected the one created')


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
