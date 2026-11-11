"""describe-filter-lists-above-fifty-entries-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-filter-lists-above-fifty-entries-rejected"
GROUP = 'state'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_READ = 'dynamodb:table:ReadCapacityUnits'
_LIMIT = 50


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    listed = {k: len(v) for k, v in result.items() if isinstance(v, list)}
    raise AssertionError(f'expected the call to be refused, but it succeeded: {listed!r}')


def _too_long(values, member):
    return ('ValidationException',
            f"1 validation error detected: Value '[{', '.join(values)}]' at '{member}' failed to "
            f"satisfy constraint: Member must have length less than or equal to {_LIMIT}")


@tags('axis:rejection', 'cap:c1', 'cap:c5', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """ResourceIds, PolicyNames and ScheduledActionNames hold at most 50 entries: 51 is refused with a
    ValidationException echoing the list and member, while exactly 50 with the real entry last
    finds it.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    name = ctx.unique_name('sim2real-behav-aas-lim-')
    policy = ctx.unique_name('sim2real-behav-aas-lim-tt-')
    action = ctx.unique_name('sim2real-behav-aas-lim-sa-')
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

    fillers = [f'{name}-absent-{i}' for i in range(_LIMIT)]
    ids = [f'table/{f}' for f in fillers[:_LIMIT - 1]] + [rid]
    policies = fillers[:_LIMIT - 1] + [policy]
    actions = fillers[:_LIMIT - 1] + [action]
    over_ids = [f'table/{fillers[-1]}'] + ids
    over_policies = [fillers[-1]] + policies
    over_actions = [fillers[-1]] + actions

    refused = {
        'resourceIds': _error(lambda: aas.describe_scalable_targets(
            ServiceNamespace=_NS, ResourceIds=over_ids)),
        'policyNames': _error(lambda: aas.describe_scaling_policies(
            ServiceNamespace=_NS, ResourceId=rid, PolicyNames=over_policies)),
        'scheduledActionNames': _error(lambda: aas.describe_scheduled_actions(
            ServiceNamespace=_NS, ResourceId=rid, ScheduledActionNames=over_actions)),
    }
    expected = {'resourceIds': _too_long(over_ids, 'resourceIds'),
                'policyNames': _too_long(over_policies, 'policyNames'),
                'scheduledActionNames': _too_long(over_actions, 'scheduledActionNames')}
    for member, (code, message) in refused.items():
        assert code == 'ValidationException', f'51 {member} were refused with {code!r}'
        assert message == expected[member][1], (
            f'the 51-entry {member} refusal message was {message!r}, expected {expected[member][1]!r}')

    # Positive control: exactly 50 entries, the real one last, finds it.
    targets = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=ids)['ScalableTargets']
    assert [(t['ResourceId'] == rid, t['ScalableDimension']) for t in targets] == [(True, _READ)], (
        f'50 resource ids returned {len(targets)} targets, expected the one registered')
    found = aas.describe_scaling_policies(ServiceNamespace=_NS, ResourceId=rid,
                                          PolicyNames=policies)['ScalingPolicies']
    assert [p['PolicyName'] for p in found] == [policy], (
        f'50 policy names returned {len(found)} policies, expected the one created')
    stored = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=rid,
                                            ScheduledActionNames=actions)['ScheduledActions']
    assert [a['ScheduledActionName'] for a in stored] == [action], (
        f'50 action names returned {len(stored)} actions, expected the one created')


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
