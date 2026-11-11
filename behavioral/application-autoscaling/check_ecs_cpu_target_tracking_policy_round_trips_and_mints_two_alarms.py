"""ecs-cpu-target-tracking-policy-round-trips-and-mints-two-alarms."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-cpu-target-tracking-policy-round-trips-and-mints-two-alarms"
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
    """An ECS CPU target-tracking policy at 60 reads back field for field and creates two CloudWatch
    alarms (above 60 over 3 periods, below 54 over 15) acting on it; deleting the policy removes
    the policy and both alarms."""
    ecs = ctx.client('ecs')
    aas = ctx.client('application-autoscaling')
    cluster, service = _create_ecs_service(ctx, ecs)
    resource_id = f'service/{cluster}/{service}'
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=0, MaxCapacity=4)
    ctx.on_cleanup(lambda: _deregister(aas, _NS, resource_id, _DIM))
    cw = ctx.client('cloudwatch')
    policy = ctx.unique_name('sim2real-behav-aas-cpu-')
    config = {'TargetValue': 60.0, 'PredefinedMetricSpecification': {'PredefinedMetricType': 'ECSServiceAverageCPUUtilization'},
              'ScaleOutCooldown': 60, 'ScaleInCooldown': 120}
    put = aas.put_scaling_policy(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, PolicyName=policy,
                                 PolicyType='TargetTrackingScaling',
                                 TargetTrackingScalingPolicyConfiguration=config)
    policy_arn = put['PolicyARN']
    names = sorted(a['AlarmName'] for a in put['Alarms'])
    ctx.on_cleanup(lambda: _delete_alarms(cw, names))

    stored = _policies(aas, _NS, resource_id)
    assert len(stored) == 1, f'{len(stored)} policies read back for the service'
    got = stored[0]
    assert (got['PolicyName'], got['PolicyType'], got['PolicyARN']) == (
        policy, 'TargetTrackingScaling', policy_arn), (
        f'the policy reads back as {got["PolicyName"]!r}/{got["PolicyType"]!r} with '
        f'{"the" if got["PolicyARN"] == policy_arn else "a different"} ARN')
    assert got['TargetTrackingScalingPolicyConfiguration'] == config, (
        f'the configuration reads back as {got["TargetTrackingScalingPolicyConfiguration"]!r}')
    assert sorted(a['AlarmName'] for a in got['Alarms']) == names, (
        'DescribeScalingPolicies lists different alarms than PutScalingPolicy returned')

    alarms = {('High' if '-AlarmHigh-' in a['AlarmName'] else
               'Low' if '-AlarmLow-' in a['AlarmName'] else 'other'): a
              for a in _alarms(cw, names)}
    assert sorted(alarms) == ['High', 'Low'] and len(names) == 2, (
        f'the policy minted alarms of kinds {sorted(alarms)!r} from {len(names)} names; '
        f'expected one AlarmHigh and one AlarmLow')
    shape = {k: (a['Namespace'], a['MetricName'], a['Statistic'], a['ComparisonOperator'],
                 a['Threshold'], a['EvaluationPeriods'], a['Period'])
             for k, a in alarms.items()}
    assert shape == {
        'High': ('AWS/ECS', 'CPUUtilization', 'Average', 'GreaterThanThreshold', 60.0, 3, 60),
        'Low': ('AWS/ECS', 'CPUUtilization', 'Average', 'LessThanThreshold', 54.0, 15, 60),
    }, f'the alarms are {shape!r}'
    for kind, alarm in alarms.items():
        dims = {d['Name']: d['Value'] for d in alarm['Dimensions']}
        assert dims == {'ClusterName': cluster, 'ServiceName': service}, (
            f'the {kind} alarm watches dimensions {sorted(dims)!r} of '
            f'{"this" if dims.get("ServiceName") == service else "another"} service')
        actions = alarm['AlarmActions']
        assert len(actions) == 1 and actions[0].startswith(policy_arn + ':createdBy/'), (
            f'the {kind} alarm has {len(actions)} action(s), '
            f'{"acting" if actions and actions[0].startswith(policy_arn) else "not acting"} on the policy')

    aas.delete_scaling_policy(ServiceNamespace=_NS, ResourceId=resource_id,
                              ScalableDimension=_DIM, PolicyName=policy)
    assert _policies(aas, _NS, resource_id) == [], 'the deleted policy is still described'
    _poll_until(lambda: _alarms(cw, names), lambda left: left == [], timeout_s=120,
                interval_s=5, description='both policy alarms deleted')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
