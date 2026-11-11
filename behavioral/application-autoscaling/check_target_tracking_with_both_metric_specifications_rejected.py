"""target-tracking-with-both-metric-specifications-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-tracking-with-both-metric-specifications-rejected"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'



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


def _client_error(fn):
    """The Error dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


def _create_ecs_service(ctx, ecs, desired=0):
    """An EC2-launch-type service on an empty cluster: nothing is ever placed, so nothing bills."""
    cluster = ctx.unique_name('sim2real-behav-aas-ecs-')
    ecs.create_cluster(clusterName=cluster, tags=[{'key': 'sim2real', 'value': CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    task_def = ecs.register_task_definition(
        family=ctx.unique_name('sim2real-behav-aas-ecs-'), requiresCompatibilities=['EC2'],
        networkMode='bridge',
        containerDefinitions=[{'name': 'idle',
                               'image': 'public.ecr.aws/docker/library/busybox:1.36',
                               'memory': 32, 'essential': True, 'command': ['sleep', '3600']}],
        tags=[{'key': 'sim2real', 'value': CHECK}])['taskDefinition']['taskDefinitionArn']
    ctx.on_cleanup(lambda: _delete_task_definition(ecs, task_def))
    service = ctx.unique_name('sim2real-behav-aas-ecs-svc-')
    ecs.create_service(cluster=cluster, serviceName=service, taskDefinition=task_def,
                       desiredCount=desired, launchType='EC2',
                       tags=[{'key': 'sim2real', 'value': CHECK}])
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, service))
    return cluster, service


def _desired(ecs, cluster, service):
    return ecs.describe_services(cluster=cluster, services=[service])['services'][0]['desiredCount']


def _delete_service(ecs, cluster, service):
    try:
        ecs.delete_service(cluster=cluster, service=service, force=True)
    except ClientError as exc:
        if exc.response['Error']['Code'] not in ('ServiceNotFoundException',
                                                 'ServiceNotActiveException'):
            raise


def _delete_task_definition(ecs, arn):
    ecs.deregister_task_definition(taskDefinition=arn)
    ecs.delete_task_definitions(taskDefinitions=[arn])


def _delete_cluster(ecs, cluster):
    """DeleteCluster refuses while the deleted service is still draining; retry that, bounded."""
    deadline = time.monotonic() + 45
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'ClusterNotFoundException':
                return
            if code not in ('ClusterContainsServicesException', 'ClusterContainsTasksException') \
                    or time.monotonic() > deadline:
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


def _alarms(cw, names):
    out = []
    for page in cw.get_paginator('describe_alarms').paginate(AlarmNames=names):
        out.extend(page['MetricAlarms'])
    return out


def _delete_alarms(cw, names):
    """Delete whichever of the policy's alarms still exist (the policy's own delete takes them)."""
    existing = [a['AlarmName'] for a in _alarms(cw, names)] if names else []
    if existing:
        cw.delete_alarms(AlarmNames=existing)


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """A target-tracking configuration with both Predefined and Customized metric specifications is
    refused with a ValidationException and stores nothing; predefined alone is accepted."""
    ecs = ctx.client('ecs')
    aas = ctx.client('application-autoscaling')
    cluster, service = _create_ecs_service(ctx, ecs)
    resource_id = f'service/{cluster}/{service}'
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=0, MaxCapacity=4)
    ctx.on_cleanup(lambda: _deregister(aas, _NS, resource_id, _DIM))

    error = _client_error(lambda: aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=ctx.unique_name('sim2real-behav-aas-both-'), PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration={
            'TargetValue': 60.0,
            'PredefinedMetricSpecification': {'PredefinedMetricType': 'ECSServiceAverageCPUUtilization'},
            'CustomizedMetricSpecification': {'MetricName': 'QueueDepth',
                                              'Namespace': 'sim2real/behav', 'Statistic': 'Average'}}))
    assert error.get('Code') == 'ValidationException', (
        f'the call was refused with {error.get("Code")!r}, expected "ValidationException"')
    assert error.get('Message') == (
        ('Only one of PredefinedMetricSpecification or CustomizedMetricSpecification can be '
        'set for target tracking scaling.')), (
        f'the refusal message was {error.get("Message")!r}')
    assert _policies(aas, _NS, resource_id) == [], 'the refused policy was stored'

    policy = ctx.unique_name('sim2real-behav-aas-ok-')
    cw = ctx.client('cloudwatch')
    put = aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM, PolicyName=policy,
        PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration={
            'TargetValue': 60.0, 'PredefinedMetricSpecification': {'PredefinedMetricType': 'ECSServiceAverageCPUUtilization'}})
    ctx.on_cleanup(lambda: _delete_alarms(cw, [a['AlarmName'] for a in put.get('Alarms', [])]))
    stored = [p['PolicyName'] for p in _policies(aas, _NS, resource_id)]
    assert stored == [policy], f'the valid policy was not the one stored: {len(stored)} policies'


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
