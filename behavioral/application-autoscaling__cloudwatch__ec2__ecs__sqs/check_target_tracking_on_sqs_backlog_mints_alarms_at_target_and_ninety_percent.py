"""target-tracking-on-sqs-backlog-mints-alarms-at-target-and-ninety-percent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-tracking-on-sqs-backlog-mints-alarms-at-target-and-ninety-percent"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'cloudwatch', 'ecs', 'sqs']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_START_COUNT = 1
_MIN_CAPACITY = 1
_MAX_CAPACITY = 3
#: Messages visible per the whole queue that the policy holds the metric at.
_TARGET_VALUE = 10.0
#: The backlog this check creates, 10x the target.
_BACKLOG = 100


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


def _code(exc):
    return exc.response.get('Error', {}).get('Code')


def _deregister(aas, resource_id):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=_DIM)
    except ClientError as exc:
        if _code(exc) != 'ObjectNotFoundException':
            raise


def _delete_policy(aas, resource_id, policy):
    try:
        aas.delete_scaling_policy(ServiceNamespace=_NS, ResourceId=resource_id,
                                  ScalableDimension=_DIM, PolicyName=policy)
    except ClientError as exc:
        if _code(exc) != 'ObjectNotFoundException':
            raise


def _delete_service(ecs, cluster, service):
    try:
        ecs.update_service(cluster=cluster, service=service, desiredCount=0)
    except ClientError as exc:
        if _code(exc) not in ('ServiceNotFoundException', 'ServiceNotActiveException'):
            raise
    try:
        ecs.delete_service(cluster=cluster, service=service, force=True)
    except ClientError as exc:
        if _code(exc) != 'ServiceNotFoundException':
            raise


def _delete_cluster(ecs, cluster):
    """DeleteCluster fails while any service is still draining; retry, then raise."""
    for _ in range(8):
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = _code(exc)
            if code == 'ClusterNotFoundException':
                return
            if code != 'ClusterContainsServicesException':
                raise
            time.sleep(5)
    raise RuntimeError(f'cluster {cluster!r} still contains a draining service after retries')


def _retire_task_definition(ecs, task_definition):
    """Deregister a task definition revision, then delete it; an already-deleted revision is
    fine and any other failure raises."""
    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)['taskDefinition']
    except ClientError as exc:
        if 'Unable to describe task definition' in exc.response['Error'].get('Message', ''):
            return
        raise
    arn = described['taskDefinitionArn']
    if described['status'] == 'DELETE_IN_PROGRESS':
        return
    if described['status'] == 'ACTIVE':
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get('failures', [])
    if failures:
        raise RuntimeError(f'task definition {arn} teardown failed: {failures}')


def _ecs_estate(ctx, ecs, slug, desired):
    """An ECS cluster and an EC2-launch-type service at `desired` to be the scalable target.

    networkMode bridge needs no networkConfiguration, so no VPC is assumed; no task is placed
    because the subject is the desiredCount Application Auto Scaling computes."""
    cluster = ctx.unique_name(f'sim2real-behav-aas-{slug}-cl-')
    service = ctx.unique_name(f'sim2real-behav-aas-{slug}-svc-')
    family = ctx.unique_name(f'sim2real-behav-aas-{slug}-td-')
    pairs = [{'key': 'sim2real', 'value': CHECK}, {'key': 'owner', 'value': 'sim2real-behav-aas'}]
    ecs.create_cluster(clusterName=cluster, tags=pairs)
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    task_def = ecs.register_task_definition(
        family=family, networkMode='bridge', requiresCompatibilities=['EC2'],
        containerDefinitions=[{
            'name': 'sim2real-idle',
            'image': 'public.ecr.aws/docker/library/busybox:1.36',
            'memory': 128, 'essential': True, 'command': ['sh', '-c', 'sleep 3600'],
        }],
        tags=pairs,
    )['taskDefinition']['taskDefinitionArn']
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def))
    ecs.create_service(cluster=cluster, serviceName=service, taskDefinition=task_def,
                       desiredCount=desired, launchType='EC2', tags=pairs)
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, service))
    return cluster, service, f'service/{cluster}/{service}'


def _delete_queue(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if _code(exc) not in ('AWS.SimpleQueueService.NonExistentQueue', 'QueueDoesNotExist'):
            raise


def _delete_alarms(cw, names):
    """Delete whichever of the policy's alarms still exist (deleting the policy removes them)."""
    existing = [a['AlarmName'] for a in cw.describe_alarms(AlarmNames=names)['MetricAlarms']]
    if existing:
        cw.delete_alarms(AlarmNames=existing)


@tags('axis:happy-path', 'cap:c4', 'concern:metrics', 'plane:control')
def run(ctx) -> None:
    """A target tracking policy on SQS's own ApproximateNumberOfMessagesVisible over a filled queue
    mints a scale-out alarm above the target over 3 one-minute periods and a scale-in alarm below
    90% of it over 15, both on that queue's series and acting on the policy.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-target-tracking.html
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    sqs = ctx.client('sqs')

    base = ctx.unique_name('sim2real-behav-mda-tt-')
    queue_url = sqs.create_queue(QueueName=base, tags={'sim2real': CHECK})['QueueUrl']
    ctx.on_cleanup(lambda: _delete_queue(sqs, queue_url))
    for batch in range(_BACKLOG // 10):
        sent = sqs.send_message_batch(QueueUrl=queue_url, Entries=[
            {'Id': str(i), 'MessageBody': f'{CHECK} {batch}-{i}'} for i in range(10)])
        assert not sent.get('Failed'), f'SendMessageBatch reported failures: {sent["Failed"]!r}'
    visible = _poll_until(
        lambda: int(sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=['ApproximateNumberOfMessages'],
        )['Attributes']['ApproximateNumberOfMessages']),
        lambda n: n == _BACKLOG, timeout_s=60, interval_s=3.0,
        description=f'ApproximateNumberOfMessages reaching the {_BACKLOG}-message backlog')
    assert visible == _BACKLOG, f'the queue reports {visible} visible messages'

    cluster, service, resource_id = _ecs_estate(ctx, ecs, 'ttsqs', _START_COUNT)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=_MIN_CAPACITY,
                                 MaxCapacity=_MAX_CAPACITY, Tags={'sim2real': CHECK})
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    policy = f'{base}-pol'
    config = {
        'TargetValue': _TARGET_VALUE,
        'CustomizedMetricSpecification': {
            'MetricName': 'ApproximateNumberOfMessagesVisible', 'Namespace': 'AWS/SQS',
            'Dimensions': [{'Name': 'QueueName', 'Value': base}], 'Statistic': 'Average'},
        'ScaleOutCooldown': 0, 'ScaleInCooldown': 0,
    }
    put = aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM, PolicyName=policy,
        PolicyType='TargetTrackingScaling', TargetTrackingScalingPolicyConfiguration=config)
    names = sorted(a['AlarmName'] for a in put['Alarms'])
    ctx.on_cleanup(lambda: _delete_alarms(cw, names))
    ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, policy))
    assert len(names) == 2, f'PutScalingPolicy created alarms {names!r}, expected 2'

    stored = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyNames=[policy])['ScalingPolicies']
    assert len(stored) == 1, f'DescribeScalingPolicies returned {stored!r} for {policy!r}'
    assert stored[0]['TargetTrackingScalingPolicyConfiguration'] == config, (
        f'the configuration reads back as '
        f'{stored[0]["TargetTrackingScalingPolicyConfiguration"]!r}')
    assert sorted(a['AlarmName'] for a in stored[0]['Alarms']) == names, (
        'DescribeScalingPolicies lists different alarms than PutScalingPolicy returned')

    alarms = cw.describe_alarms(AlarmNames=names)['MetricAlarms']
    by_kind = {('High' if '-AlarmHigh-' in a['AlarmName'] else
                'Low' if '-AlarmLow-' in a['AlarmName'] else 'other'): a for a in alarms}
    assert sorted(by_kind) == ['High', 'Low'], (
        f'the policy minted alarms {sorted(a["AlarmName"] for a in alarms)!r}; expected one '
        f'AlarmHigh and one AlarmLow')
    shape = {k: (a['Namespace'], a['MetricName'], a['Dimensions'], a['Statistic'],
                 a['ComparisonOperator'], a['Threshold'], a['Period'], a['EvaluationPeriods'])
             for k, a in by_kind.items()}
    series = ('AWS/SQS', 'ApproximateNumberOfMessagesVisible',
              [{'Name': 'QueueName', 'Value': base}], 'Average')
    assert shape == {
        'High': series + ('GreaterThanThreshold', _TARGET_VALUE, 60, 3),
        'Low': series + ('LessThanThreshold', _TARGET_VALUE * 0.9, 60, 15),
    }, f'the alarms are {shape!r}'
    arn = put['PolicyARN']
    for kind, alarm in by_kind.items():
        actions = alarm['AlarmActions']
        assert len(actions) == 1 and actions[0].startswith(arn + ':createdBy/'), (
            f'the {kind} alarm acts on {actions!r}, not on the policy {arn!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
