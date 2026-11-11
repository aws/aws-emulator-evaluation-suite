"""put-scaling-policy-rejects-unregistered-target."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scaling-policy-rejects-unregistered-target"
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


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(
        f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


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


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """PutScalingPolicy on an existing table that was never registered as a scalable target is
    refused and stores nothing; the same policy succeeds once the target is registered.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-unreg-')
    policy = ctx.unique_name('sim2real-behav-aas-unregpol-')
    resource_id = f'table/{table}'
    policy_config = {
        'TargetValue': 50.0,
        'PredefinedMetricSpecification': {
            'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'},
    }

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
    assert aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id])['ScalableTargets'] == [], (
        'this check requires the table to be UNregistered before the policy attempt'
    )

    error = _client_error(lambda: aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy, PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration=policy_config))
    assert error.get('Code') == 'ObjectNotFoundException', (
        f'attaching a policy to an unregistered target was rejected with '
        f'{error.get("Code")!r}, expected "ObjectNotFoundException"'
    )
    assert error.get('Message') == (
        f'No scalable target registered for service namespace: {_NS}, '
        f'resource ID: {resource_id}, scalable dimension: {_DIM}'
    ), f'the rejection message was {error.get("Message")!r}'
    assert _policies(aas, resource_id) == [], (
        'the refused policy was stored anyway; a rejection must leave no policy behind'
    )
    assert aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id])['ScalableTargets'] == [], (
        'the refused PutScalingPolicy implicitly registered a scalable target'
    )

    # Positive control: the SAME policy document, once the target is registered.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy, PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration=policy_config)
    stored = _policies(aas, resource_id)
    assert [p['PolicyName'] for p in stored] == [policy], (
        f'the positive control did not store exactly the one policy: '
        f'{[p["PolicyName"] for p in stored]!r}'
    )
    assert stored[0]['TargetTrackingScalingPolicyConfiguration']['TargetValue'] == 50.0, (
        f'the stored policy came back with TargetValue '
        f'{stored[0]["TargetTrackingScalingPolicyConfiguration"]["TargetValue"]!r}, expected 50.0'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
