"""concurrent-upserts-of-one-policy-name-leave-one-policy-and-one-alarm-set."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-upserts-of-one-policy-name-leave-one-policy-and-one-alarm-set"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_WRITE = 'dynamodb:table:WriteCapacityUnits'
_TARGETS = [20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0]


def _alarms_with_prefix(cw, prefix):
    out = []
    for page in cw.get_paginator('describe_alarms').paginate(AlarmNamePrefix=prefix):
        out.extend(page['MetricAlarms'])
    return out


def _delete_alarms(cw, prefix):
    left = [a['AlarmName'] for a in _alarms_with_prefix(cw, prefix)]
    if left:
        cw.delete_alarms(AlarmNames=left)


@tags('axis:happy-path', 'cap:c1', 'cap:c6', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """Concurrent PutScalingPolicy upserts of one name either win or get ConcurrentUpdateException;
    exactly one policy remains with a winner's target value and one set of four alarms whose
    AlarmHigh threshold derives from it. How many calls lose is timing and is not asserted.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    name = ctx.unique_name('sim2real-behav-aas-cc-')
    policy = ctx.unique_name('sim2real-behav-aas-cc-tt-')
    _table(ctx, ddb, name, write=1)
    rid = f'table/{name}'
    prefix = f'TargetTracking-{rid}-'
    # Runs after the deregistration below (LIFO), removing any alarm the cascade left.
    ctx.on_cleanup(lambda: _delete_alarms(cw, prefix))
    _register(ctx, aas, rid, _WRITE, 1, 10)

    def put(target):
        try:
            aas.put_scaling_policy(
                PolicyName=policy, ServiceNamespace=_NS, ResourceId=rid, ScalableDimension=_WRITE,
                PolicyType='TargetTrackingScaling',
                TargetTrackingScalingPolicyConfiguration={
                    'TargetValue': target,
                    'PredefinedMetricSpecification': {
                        'PredefinedMetricType': 'DynamoDBWriteCapacityUtilization'}})
            return target, None
        except ClientError as exc:
            return target, (exc.response['Error']['Code'], exc.response['Error'].get('Message'))

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(_TARGETS)) as pool:
        results = list(pool.map(put, _TARGETS))
    winners = {target for target, error in results if error is None}
    refusals = {error for _target, error in results if error is not None}
    assert winners, f'no concurrent upsert succeeded; refusals were {refusals!r}'
    refused = ('ConcurrentUpdateException',
               'You already have a pending update to an Auto Scaling resource.')
    assert refusals <= {refused}, (
        f'a concurrent upsert was refused with something other than {refused!r}: {refusals!r}')

    policies = aas.describe_scaling_policies(ServiceNamespace=_NS, ResourceId=rid,
                                             ScalableDimension=_WRITE)['ScalingPolicies']
    assert [p['PolicyName'] for p in policies] == [policy], (
        f'{len(policies)} policies exist after concurrent upserts of one name, expected 1')
    stored = policies[0]['TargetTrackingScalingPolicyConfiguration']['TargetValue']
    assert stored in winners, (
        f'the stored target value {stored!r} was not sent by a winning call {sorted(winners)!r}')
    owned = sorted(a['AlarmName'] for a in policies[0]['Alarms'])
    assert len(owned) == 4, f'the policy owns {len(owned)} alarms, expected 4'

    alarms = _poll_until(lambda: _alarms_with_prefix(cw, prefix),
                         lambda found: sorted(a['AlarmName'] for a in found) == owned,
                         timeout_s=90, interval_s=5.0,
                         description="CloudWatch holding exactly the stored policy's alarms")
    high = [a for a in alarms if a['AlarmName'].startswith(f'{prefix}AlarmHigh-')]
    assert len(high) == 1, f'{len(high)} AlarmHigh alarms exist, expected 1'
    # One provisioned WCU over a 60 s period: the high threshold is target% of 60 units.
    assert abs(high[0]['Threshold'] - stored * 0.6) < 1e-9, (
        f'AlarmHigh threshold is {high[0]["Threshold"]!r}; the stored target {stored!r} on 1 WCU '
        f'derives {stored * 0.6!r}')


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    """Poll until predicate holds; raises on timeout."""
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
