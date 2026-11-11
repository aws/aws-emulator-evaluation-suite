"""put-scaling-policy-again-updates-in-place-keeping-the-policy-arn."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scaling-policy-again-updates-in-place-keeping-the-policy-arn"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description='condition'):
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


def _policies(aas, resource_id):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_policies(**kwargs)
        out.extend(page['ScalingPolicies'])
        token = page.get('NextToken')
        if not token:
            return out



def _table(ctx, ddb):
    table = ctx.unique_name('sim2real-behav-aas-')
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120,
                description=f'table {table!r} becoming ACTIVE')
    return f'table/{table}'


@tags('axis:happy-path', 'cap:c2', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """A second PutScalingPolicy with the same name updates in place: same PolicyARN, one policy
    on the target, carrying the second call's TargetValue.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    resource_id = _table(ctx, ddb)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    policy = ctx.unique_name('sim2real-behav-aas-pol-')

    def put(target):
        return aas.put_scaling_policy(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyName=policy, PolicyType='TargetTrackingScaling',
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': target,
                'PredefinedMetricSpecification': {
                    'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'},
            })['PolicyARN']

    first, second = put(50.0), put(70.0)
    assert second == first, f'the second put minted a new policy ARN: {first!r} -> {second!r}'
    stored = _policies(aas, resource_id)
    assert [p['PolicyName'] for p in stored] == [policy], (
        f'the target must hold exactly the one policy, got {[p["PolicyName"] for p in stored]!r}'
    )
    assert stored[0]['PolicyARN'] == first, f'stored ARN {stored[0]["PolicyARN"]!r}'
    value = stored[0]['TargetTrackingScalingPolicyConfiguration']['TargetValue']
    assert value == 70.0, f'the stored TargetValue must be the second put\'s 70.0, got {value!r}'


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
