"""ecs-service-target-lifecycle-leaves-the-desired-count-after-deregister."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-service-target-lifecycle-leaves-the-desired-count-after-deregister"
GROUP = 'scalable-targets'
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


def _activities(aas, ns, resource_id):
    out = []
    for page in aas.get_paginator('describe_scaling_activities').paginate(
            ServiceNamespace=ns, ResourceId=resource_id):
        out.extend(page['ScalingActivities'])
    return out


@tags('axis:happy-path', 'cap:c1', 'concern:data-plane', 'concern:representation', 'dp:api',
      'plane:control', 'plane:data')
def run(ctx) -> None:
    """Registering in-bounds limits on an ECS service records no activity; raising the floor to 2
    sets desiredCount to 2; deregistering removes the target but leaves desiredCount at 2.
    """
    ecs = ctx.client('ecs')
    aas = ctx.client('application-autoscaling')
    cluster, service = _create_ecs_service(ctx, ecs)
    resource_id = f'service/{cluster}/{service}'
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=0, MaxCapacity=4)
    ctx.on_cleanup(lambda: _deregister(aas, _NS, resource_id, _DIM))

    targets = _targets(aas, _NS, resource_id)
    assert len(targets) == 1, f'{len(targets)} targets read back for the service'
    target = targets[0]
    assert (target['MinCapacity'], target['MaxCapacity']) == (0, 4), (
        f'the target reads back ({target["MinCapacity"]}, {target["MaxCapacity"]}), expected (0, 4)')
    role = f'arn:aws:iam::{ctx.account}:role/aws-service-role/' \
           'ecs.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_ECSService'
    assert target['RoleARN'] == role, (
        f'the target role is {"a different role" if target["RoleARN"] else "absent"}; an ECS '
        f'target uses the ECS service-linked role of its own account')
    assert target['SuspendedState'] == {'DynamicScalingInSuspended': False,
                                        'DynamicScalingOutSuspended': False,
                                        'ScheduledScalingSuspended': False}, (
        f'a fresh target reads back SuspendedState {target["SuspendedState"]!r}')
    assert _activities(aas, _NS, resource_id) == [], (
        'registering bounds that contain the desired count recorded a scaling activity')
    assert _desired(ecs, cluster, service) == 0, (
        f'an in-bounds registration moved desiredCount to {_desired(ecs, cluster, service)}')

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=2)
    _poll_until(lambda: _desired(ecs, cluster, service), lambda d: d != 0, timeout_s=180,
                interval_s=5, description='the service desiredCount leaving 0')
    assert _desired(ecs, cluster, service) == 2, (
        f'raising the floor to 2 set desiredCount to {_desired(ecs, cluster, service)}')
    causes = [a['Cause'] for a in _activities(aas, _NS, resource_id)]
    assert causes == ['minimum capacity was set to 2'], (
        f'the floor change recorded activities caused by {causes!r}')

    aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                   ScalableDimension=_DIM)
    assert _targets(aas, _NS, resource_id) == [], 'the deregistered target is still described'
    assert _desired(ecs, cluster, service) == 2, (
        f'deregistering reset desiredCount to {_desired(ecs, cluster, service)}; it keeps the 2 '
        f'scaling set')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
