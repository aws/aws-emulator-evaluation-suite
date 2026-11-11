"""ecs-cpu-and-memory-policies-coexist-and-deleting-one-keeps-the-other."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-cpu-and-memory-policies-coexist-and-deleting-one-keeps-the-other"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'



def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


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


@tags('axis:happy-path', 'cap:c1', 'concern:metrics', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """CPU and memory target-tracking policies on one ECS target coexist, each with two alarms;
    deleting the CPU policy removes only it and its alarms, leaving the memory policy intact.
    """
    ecs = ctx.client('ecs')
    aas = ctx.client('application-autoscaling')
    cluster, service = _create_ecs_service(ctx, ecs)
    resource_id = f'service/{cluster}/{service}'
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=0, MaxCapacity=4)
    ctx.on_cleanup(lambda: _deregister(aas, _NS, resource_id, _DIM))
    cw = ctx.client('cloudwatch')
    specs = {
        'cpu': ('ECSServiceAverageCPUUtilization', 'CPUUtilization', 60.0),
        'mem': ('ECSServiceAverageMemoryUtilization', 'MemoryUtilization', 75.0),
    }
    names, alarm_names = {}, {}
    for key, (metric_type, _, target) in specs.items():
        names[key] = ctx.unique_name(f'sim2real-behav-aas-{key}-')
        put = aas.put_scaling_policy(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyName=names[key], PolicyType='TargetTrackingScaling',
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': target,
                'PredefinedMetricSpecification': {'PredefinedMetricType': metric_type}})
        alarm_names[key] = sorted(a['AlarmName'] for a in put['Alarms'])
        ctx.on_cleanup(lambda n=alarm_names[key]: _delete_alarms(cw, n))

    stored = {p['PolicyName']: p for p in _policies(aas, _NS, resource_id)}
    assert sorted(stored) == sorted(names.values()), (
        f'{len(stored)} policies read back; expected the CPU and the memory policy')
    for key, (metric_type, metric, target) in specs.items():
        alarms = _alarms(cw, alarm_names[key])
        watched = sorted({(a['Namespace'], a['MetricName']) for a in alarms})
        assert len(alarms) == 2 and watched == [('AWS/ECS', metric)], (
            f'the {key} policy has {len(alarms)} alarms watching {watched!r}')

    aas.delete_scaling_policy(ServiceNamespace=_NS, ResourceId=resource_id,
                              ScalableDimension=_DIM, PolicyName=names['cpu'])
    left = _policies(aas, _NS, resource_id)
    assert [p['PolicyName'] for p in left] == [names['mem']], (
        f'after deleting the CPU policy {len(left)} policies remain; expected only the memory one')
    mem_cfg = left[0]['TargetTrackingScalingPolicyConfiguration']
    assert (mem_cfg['TargetValue'], mem_cfg['PredefinedMetricSpecification']['PredefinedMetricType']) \
        == (75.0, 'ECSServiceAverageMemoryUtilization'), (
        f'the memory policy changed to {mem_cfg!r}')
    _poll_until(lambda: _alarms(cw, alarm_names['cpu']), lambda a: a == [], timeout_s=120,
                interval_s=5, description='the CPU policy alarms deleted')
    mem_alarms = _alarms(cw, alarm_names['mem'])
    assert len(mem_alarms) == 2, (
        f'deleting the CPU policy left {len(mem_alarms)} of the memory policy\'s two alarms')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
