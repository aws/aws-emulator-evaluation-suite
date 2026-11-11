"""ecs-registration-floor-sets-the-desired-count-with-no-capacity-to-run-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-registration-floor-sets-the-desired-count-with-no-capacity-to-run-it"
GROUP = 'data-plane'
SERVICES = ['application-autoscaling']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'


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


def _activities(aas, resource_id):
    out = []
    for page in aas.get_paginator('describe_scaling_activities').paginate(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM):
        out.extend(page['ScalingActivities'])
    return out


@tags('axis:happy-path', 'cap:c1', 'concern:data-plane', 'concern:representation', 'dp:api',
      'plane:data')
def run(ctx) -> None:
    """Registering an ECS service with MinCapacity 2 raises its desiredCount to 2 even with no
    container instance to run tasks, and the single activity names the floor as its cause.
    """
    ecs = ctx.client('ecs')
    aas = ctx.client('application-autoscaling')
    cluster = ctx.unique_name('sim2real-behav-aas-ecs-')
    ecs.create_cluster(clusterName=cluster, tags=[{'key': 'sim2real', 'value': CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    family = ctx.unique_name('sim2real-behav-aas-ecs-')
    task_def = ecs.register_task_definition(
        family=family, requiresCompatibilities=['EC2'], networkMode='bridge',
        containerDefinitions=[{'name': 'idle',
                               'image': 'public.ecr.aws/docker/library/busybox:1.36',
                               'memory': 32, 'essential': True, 'command': ['sleep', '3600']}],
        tags=[{'key': 'sim2real', 'value': CHECK}])['taskDefinition']['taskDefinitionArn']
    ctx.on_cleanup(lambda: _delete_task_definition(ecs, task_def))
    # The cluster has no container instances, so no task is ever placed and nothing bills.
    service = ctx.unique_name('sim2real-behav-aas-ecs-svc-')
    ecs.create_service(cluster=cluster, serviceName=service, taskDefinition=task_def,
                       desiredCount=0, launchType='EC2',
                       tags=[{'key': 'sim2real', 'value': CHECK}])
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, service))
    resource_id = f'service/{cluster}/{service}'
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=2, MaxCapacity=4)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    svc = _poll_until(lambda: ecs.describe_services(cluster=cluster, services=[service])['services'][0],
                      lambda s: s['desiredCount'] != 0, timeout_s=180, interval_s=5.0,
                      description='the service desiredCount leaving 0')
    assert svc['desiredCount'] == 2, (
        f'the service desiredCount is {svc["desiredCount"]}; the registered floor of 2 sets it to 2')
    assert (svc['runningCount'], svc['pendingCount']) == (0, 0), (
        f'running/pending are {svc["runningCount"]}/{svc["pendingCount"]} on a cluster with no '
        f'container instance')
    activities = _activities(aas, resource_id)
    shapes = [(a['Cause'], a['Description']) for a in activities]
    assert shapes == [('minimum capacity was set to 2', 'Setting desired count to 2.')], (
        f'activities were {shapes!r}')
    target = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[resource_id],
                                           ScalableDimension=_DIM)['ScalableTargets']
    assert [(t['MinCapacity'], t['MaxCapacity']) for t in target] == [(2, 4)], (
        f'the target reads back as {[(t["MinCapacity"], t["MaxCapacity"]) for t in target]!r}')


def _ignore(fn, *codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response['Error']['Code'] not in codes:
            raise


def _deregister(aas, resource_id):
    _ignore(lambda: aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                                   ScalableDimension=_DIM),
            'ObjectNotFoundException')


def _delete_service(ecs, cluster, service):
    _ignore(lambda: ecs.delete_service(cluster=cluster, service=service, force=True),
            'ServiceNotFoundException', 'ServiceNotActiveException')


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


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
