"""deregister-scalable-target-cascades-but-keeps-activities."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-scalable-target-cascades-but-keeps-activities"
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


def _client_error(fn):
    """Return the ClientError response of fn(); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
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


def _delete_alarms(cw, names):
    if names:
        try:
            cw.delete_alarms(AlarmNames=list(names))
        except ClientError as exc:
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFound",):
                raise RuntimeError(f'alarms {sorted(names)!r} not deleted: '
                                   f'{exc.response.get("Error", {}).get("Code")}') from exc


def _paginate(client, op, key, **kwargs):
    out = []
    token = None
    while True:
        page = getattr(client, op)(**kwargs, **({'NextToken': token} if token else {}))
        out.extend(page[key])
        token = page.get('NextToken')
        if not token:
            return out


def _terminal(activity):
    return activity['StatusCode'] in ('Successful', 'Failed', 'Overridden', 'Unfulfilled')


@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:negative-classes',
      'concern:representation', 'plane:control')
def run(ctx) -> None:
    """DeregisterScalableTarget removes the target's policies, scheduled actions, tags and minted
    CloudWatch alarms and makes the target unusable, but keeps its scaling-activity history.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    table = ctx.unique_name('sim2real-behav-aas-casc-')
    policy = ctx.unique_name('sim2real-behav-aas-cascpol-')
    action = ctx.unique_name('sim2real-behav-aas-cascsa-')
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

    registered = aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=3, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    target_arn = registered['ScalableTargetARN']

    aas.tag_resource(ResourceARN=target_arn,
                     Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'})
    assert aas.list_tags_for_resource(ResourceARN=target_arn).get('Tags') == {
        'sim2real': CHECK, 'owner': 'sim2real-behav-aas'}, (
        'the tags did not round-trip onto the scalable target before deregistration'
    )

    put = aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy, PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration={
            'TargetValue': 40.0,
            'PredefinedMetricSpecification': {
                'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'}},
    )
    alarm_names = sorted(a['AlarmName'] for a in put['Alarms'])
    ctx.on_cleanup(lambda: _delete_alarms(cw, alarm_names))
    assert len(alarm_names) == 4, (
        f'the DynamoDB target-tracking policy minted {len(alarm_names)} alarms, expected 4: '
        f'{alarm_names!r}'
    )
    live_alarms = {a['AlarmName'] for a in
                   cw.describe_alarms(AlarmNames=alarm_names)['MetricAlarms']}
    assert live_alarms == set(alarm_names), (
        f'CloudWatch does not hold every alarm the policy claims; missing '
        f'{sorted(set(alarm_names) - live_alarms)!r}'
    )

    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule='cron(30 4 15 6 ? 2035)', Timezone='UTC',
        ScalableTargetAction={'MinCapacity': 2, 'MaxCapacity': 6},
    )
    assert [a['ScheduledActionName'] for a in _paginate(
        aas, 'describe_scheduled_actions', 'ScheduledActions',
        ServiceNamespace=_NS, ResourceId=resource_id)] == [action], (
        'the scheduled action was not readable before deregistration'
    )

    # A real activity, so "the history survives" is a claim about something that exists.
    history = _poll_until(
        lambda: _paginate(aas, 'describe_scaling_activities', 'ScalingActivities',
                          ServiceNamespace=_NS, ResourceId=resource_id,
                          ScalableDimension=_DIM),
        lambda acts: len(acts) >= 1 and _terminal(acts[0]), timeout_s=140, interval_s=4.0,
        description='the floor-3 correction activity reaching a terminal status')
    activity_ids_before = {a['ActivityId'] for a in history}

    aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                   ScalableDimension=_DIM)

    assert _paginate(aas, 'describe_scalable_targets', 'ScalableTargets',
                     ServiceNamespace=_NS, ResourceIds=[resource_id]) == [], (
        'the scalable target is still registered after DeregisterScalableTarget'
    )
    assert _paginate(aas, 'describe_scaling_policies', 'ScalingPolicies',
                     ServiceNamespace=_NS, ResourceId=resource_id) == [], (
        'the scaling policy outlived its scalable target; deregistration must cascade to policies'
    )
    assert _paginate(aas, 'describe_scheduled_actions', 'ScheduledActions',
                     ServiceNamespace=_NS, ResourceId=resource_id) == [], (
        'the scheduled action outlived its scalable target; deregistration must cascade to '
        'scheduled actions'
    )
    surviving = _poll_until(
        lambda: {a['AlarmName'] for a in
                 cw.describe_alarms(AlarmNames=alarm_names)['MetricAlarms']},
        lambda names: names == set(), timeout_s=60, interval_s=4.0,
        description='the CloudWatch alarms the policy minted being deleted with the target')
    assert surviving == set(), f'alarms left behind: {sorted(surviving)!r}'

    tag_resp = _client_error(lambda: aas.list_tags_for_resource(ResourceARN=target_arn))
    tag_error = tag_resp.get('Error', {})
    assert tag_error.get('Code') == 'ResourceNotFoundException', (
        f'reading tags off the deregistered target ARN returned '
        f'{tag_error.get("Code")!r}, expected "ResourceNotFoundException"'
    )
    tag_status = tag_resp.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert isinstance(tag_status, int) and 400 <= tag_status < 500, f'the tag-read rejection carried HTTP {tag_status!r}, expected 4xx'
    expected_message = "Scalable Target not found"
    assert tag_error.get('Message') == expected_message, f"expected the message {expected_message!r}, got {tag_error.get('Message')!r}"

    # The deregistered target is unusable, not just unlisted.
    put_resp = _client_error(lambda: aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy, PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration={
            'TargetValue': 40.0,
            'PredefinedMetricSpecification': {
                'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'}},
    ))
    put_error = put_resp.get('Error', {})
    assert put_error.get('Code') == 'ObjectNotFoundException', (
        f'PutScalingPolicy on the deregistered target returned {put_error.get("Code")!r}, '
        f'expected "ObjectNotFoundException"'
    )
    put_status = put_resp.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert isinstance(put_status, int) and 400 <= put_status < 500, (
        f'PutScalingPolicy on the deregistered target carried HTTP {put_status!r}, expected 4xx'
    )
    expected_message = f"No scalable target registered for service namespace: dynamodb, resource ID: {resource_id}, scalable dimension: dynamodb:table:ReadCapacityUnits"
    assert put_error.get('Message') == expected_message, f"expected the message {expected_message!r}, got {put_error.get('Message')!r}"

    kept = _paginate(aas, 'describe_scaling_activities', 'ScalingActivities',
                     ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM)
    assert {a['ActivityId'] for a in kept} == activity_ids_before, (
        f'the scaling-activity history changed across deregistration: '
        f'{sorted(a["ActivityId"] for a in kept)!r} vs '
        f'{sorted(activity_ids_before)!r} -- real AWS keeps the history of a deleted target'
    )
    assert '3' in kept[0]['Cause'], (
        f'surviving activity cause {kept[0]["Cause"]!r} does not reflect MinCapacity=3')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
