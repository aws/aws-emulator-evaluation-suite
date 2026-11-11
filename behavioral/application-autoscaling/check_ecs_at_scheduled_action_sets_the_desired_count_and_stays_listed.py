"""ecs-at-scheduled-action-sets-the-desired-count-and-stays-listed."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-at-scheduled-action-sets-the-desired-count-and-stays-listed"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description='condition',
                ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f'{description}: the run budget ended first; not graded')
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
            time.sleep(2)


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


def _actions(aas, ns, resource_id):
    out = []
    for page in aas.get_paginator('describe_scheduled_actions').paginate(
            ServiceNamespace=ns, ResourceId=resource_id):
        out.extend(page['ScheduledActions'])
    return out


def _activities(aas, ns, resource_id):
    out = []
    for page in aas.get_paginator('describe_scaling_activities').paginate(
            ServiceNamespace=ns, ResourceId=resource_id):
        out.extend(page['ScalingActivities'])
    return out


# timing:real-time — schedule: 5 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:data-plane', 'dp:api', 'plane:control',
      'plane:data', "timing:real-time")
def run(ctx) -> None:
    """A one-time at() action on an ECS service fires: target bounds become (2, 3), desiredCount
    rises to 2, the activity names the action, and the fired action is still listed.
    """
    ecs = ctx.client('ecs')
    aas = ctx.client('application-autoscaling')
    cluster, service = _create_ecs_service(ctx, ecs)
    resource_id = f'service/{cluster}/{service}'
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=0, MaxCapacity=4)
    ctx.on_cleanup(lambda: _deregister(aas, _NS, resource_id, _DIM))
    action = ctx.unique_name('sim2real-behav-aas-at-')
    when = (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=5)).strftime('%Y-%m-%dT%H:%M:%S')
    aas.put_scheduled_action(ServiceNamespace=_NS, ResourceId=resource_id,
                             ScalableDimension=_DIM, ScheduledActionName=action,
                             Schedule=f'at({when})',
                             ScalableTargetAction={'MinCapacity': 2, 'MaxCapacity': 3})

    # at() fires within about a minute of its instant, and ECS then takes the write.
    _poll_until(lambda: _desired(ecs, cluster, service), lambda d: d != 0,
                timeout_s=_budget_s(ctx, 240), interval_s=1,
                description='the scheduled action raising desiredCount', ctx=ctx)
    assert _desired(ecs, cluster, service) == 2, (
        f'the fired action set desiredCount to {_desired(ecs, cluster, service)}, expected 2')
    bounds = [(t['MinCapacity'], t['MaxCapacity']) for t in _targets(aas, _NS, resource_id)]
    assert bounds == [(2, 3)], f'after firing the target reads back {bounds!r}, expected [(2, 3)]'
    causes = [a['Cause'] for a in _activities(aas, _NS, resource_id)]
    assert f'scheduled action name {action} was triggered' in causes, (
        f'no activity names the scheduled action as its cause; causes were {causes!r}')
    listed = [a['ScheduledActionName'] for a in _actions(aas, _NS, resource_id)]
    assert listed == [action], f'after firing the listed actions are {listed!r}'


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
