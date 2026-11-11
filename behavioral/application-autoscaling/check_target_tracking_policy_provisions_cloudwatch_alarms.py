"""target-tracking-policy-provisions-cloudwatch-alarms."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-tracking-policy-provisions-cloudwatch-alarms"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_TARGET_VALUE = 40.0
_CREATED_BY = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')

# For TargetValue=40 against a table provisioned at 1 read capacity unit:
# the utilisation alarms are computed as a per-minute SUM of consumed units, so their thresholds
# are TargetValue% * 60 * provisioned (24.0) and half of that for scale-in (12.0); the
# provisioned-capacity alarms watch the provisioned figure itself (1.0).
_EXPECTED = {
    'AlarmHigh': {'MetricName': 'ConsumedReadCapacityUnits', 'Statistic': 'Sum', 'Period': 60,
                  'EvaluationPeriods': 2, 'Threshold': 24.0,
                  'ComparisonOperator': 'GreaterThanThreshold'},
    'AlarmLow': {'MetricName': 'ConsumedReadCapacityUnits', 'Statistic': 'Sum', 'Period': 60,
                 'EvaluationPeriods': 15, 'Threshold': 12.0,
                 'ComparisonOperator': 'LessThanThreshold'},
    'ProvisionedCapacityHigh': {'MetricName': 'ProvisionedReadCapacityUnits',
                                'Statistic': 'Average', 'Period': 300, 'EvaluationPeriods': 3,
                                'Threshold': 1.0,
                                'ComparisonOperator': 'GreaterThanThreshold'},
    'ProvisionedCapacityLow': {'MetricName': 'ProvisionedReadCapacityUnits',
                               'Statistic': 'Average', 'Period': 300, 'EvaluationPeriods': 3,
                               'Threshold': 1.0, 'ComparisonOperator': 'LessThanThreshold'},
}


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description='condition'):
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


def _delete_alarms(cw, names):
    if names:
        try:
            cw.delete_alarms(AlarmNames=list(names))
        except ClientError as exc:
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFound",):
                raise RuntimeError(f'alarms {sorted(names)!r} not deleted: '
                                   f'{exc.response.get("Error", {}).get("Code")}') from exc


def _kind_of(alarm_name):
    for kind in ('ProvisionedCapacityHigh', 'ProvisionedCapacityLow', 'AlarmHigh', 'AlarmLow'):
        if f'-{kind}-' in alarm_name:
            return kind
    return None


@tags('axis:happy-path', 'cap:c1', 'concern:metrics', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """A target-tracking policy creates four CloudWatch alarms on this table, with thresholds
    derived from the target value and capacity and each wired to the policy; deleting the policy
    deletes them.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    table = ctx.unique_name('sim2real-behav-aas-alarms-')
    policy = ctx.unique_name('sim2real-behav-aas-alarmpol-')
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
    put = aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy, PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration={
            'TargetValue': _TARGET_VALUE,
            'PredefinedMetricSpecification': {
                'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'}},
    )
    policy_arn = put['PolicyARN']
    names = [a['AlarmName'] for a in put['Alarms']]
    ctx.on_cleanup(lambda: _delete_alarms(cw, names))

    by_kind = {}
    for name in names:
        kind = _kind_of(name)
        assert kind is not None, (
            f'alarm {name!r} is none of the four kinds real AWS mints for a target-tracking '
            f'policy ({sorted(_EXPECTED)})'
        )
        assert name.startswith(f'TargetTracking-{resource_id}-{kind}-'), (
            f'alarm {name!r} is not named TargetTracking-<resourceId>-{kind}-<uuid>'
        )
        by_kind[kind] = name
    assert sorted(by_kind) == sorted(_EXPECTED), (
        f'the policy minted alarms for {sorted(by_kind)!r}, expected {sorted(_EXPECTED)!r}'
    )

    alarms = _poll_until(
        lambda: {a['AlarmName']: a for a in
                 cw.describe_alarms(AlarmNames=names)['MetricAlarms']},
        lambda found: len(found) == 4, timeout_s=60, interval_s=3.0,
        description='all four alarms being readable in CloudWatch')
    for kind, want in _EXPECTED.items():
        alarm = alarms[by_kind[kind]]
        assert alarm['Namespace'] == 'AWS/DynamoDB', (
            f'{kind} watches namespace {alarm["Namespace"]!r}, expected "AWS/DynamoDB"'
        )
        assert alarm['Dimensions'] == [{'Name': 'TableName', 'Value': table}], (
            f'{kind} watches dimensions {alarm["Dimensions"]!r}, expected exactly the TableName '
            f'{table!r}'
        )
        for field, expected in want.items():
            assert alarm[field] == expected, (
                f'{kind} has {field}={alarm[field]!r}, expected {expected!r}'
            )
        # The alarm action is the policy ARN with a ':createdBy/<uuid>' suffix that
        # PutScalingPolicy's own PolicyARN does not carry, so they are compared structurally.
        assert len(alarm['AlarmActions']) == 1, (
            f'{kind} lists {len(alarm["AlarmActions"])} alarm actions '
            f'{alarm["AlarmActions"]!r}; exactly one -- the scaling policy -- must be wired up, '
            f'or a breach reaches nothing or reaches too much'
        )
        action = alarm['AlarmActions'][0]
        assert action.startswith(f'{policy_arn}:createdBy/'), (
            f'{kind} points at {action!r}; the action must be the scaling policy '
            f'{policy_arn!r} with a createdBy suffix, or a breach reaches nothing'
        )
        assert _CREATED_BY.fullmatch(action[len(policy_arn) + len(':createdBy/'):]), (
            f'{kind} action {action!r} does not end in a createdBy uuid'
        )

    aas.delete_scaling_policy(ServiceNamespace=_NS, ResourceId=resource_id,
                              ScalableDimension=_DIM, PolicyName=policy)
    # The alarm deletion behind DeleteScalingPolicy is eventually consistent and can exceed 60s.
    surviving = _poll_until(
        lambda: {a['AlarmName'] for a in
                 cw.describe_alarms(AlarmNames=names)['MetricAlarms']},
        lambda found: found == set(), timeout_s=100, interval_s=3.0,
        description='the four alarms being deleted along with the policy')
    assert surviving == set(), (
        f'DeleteScalingPolicy left the alarms it created behind: {sorted(surviving)!r}'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
