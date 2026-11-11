"""step-scaling-suspended-scale-in-holds-while-scale-out-still-fires."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "step-scaling-suspended-scale-in-holds-while-scale-out-still-fires"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'cloudwatch', 'ecs', 'iam']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'SuspendedScaleInDriver'
_START_COUNT = 2
_MIN_CAPACITY = 1
_MAX_CAPACITY = 3
#: One series and one threshold: above it the out alarm breaches, below it the in alarm does.
_THRESHOLD = 50.0
_HIGH = _THRESHOLD + 25.0
_LOW = _THRESHOLD - 25.0
_ALARM_PERIOD_S = 10
_TRANSITION_S = 90.0
_APPLY_S = 150.0
#: Fargate tasks pull and start before runningCount reaches desiredCount.
_RUNNING_S = 180.0
#: How long scale-in is watched NOT happening while its alarm is in ALARM: longer than the
#: once-a-minute re-invocation of a policy by an alarm that stays in ALARM.
_HOLD_S = 75.0


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


def _delete_alarm(cw, name):
    try:
        cw.delete_alarms(AlarmNames=[name])
    except ClientError as exc:
        if _code(exc) != 'ResourceNotFound':
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
    """DeleteCluster fails while any service or task is still draining; retry, then raise."""
    for _ in range(16):
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = _code(exc)
            if code == 'ClusterNotFoundException':
                return
            if code not in ('ClusterContainsServicesException', 'ClusterContainsTasksException'):
                raise
            time.sleep(8)
    raise RuntimeError(f'cluster {cluster!r} still contains a draining service or task after retries')


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


def _detach_role_policy(iam, role_name, policy_arn):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if _code(exc) != 'NoSuchEntity':
            raise


def _delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if _code(exc) != 'NoSuchEntity':
            raise


def _execution_role(ctx, iam):
    """A minimal Fargate task-execution role for pulling the task image."""
    role_name = ctx.unique_name('sim2real-behav-aas-fgexec-')[:64]
    trust = {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
         'Action': 'sts:AssumeRole'},
    ]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['Role']['Arn']
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _detach_role_policy(iam, role_name, policy_arn))
    return role_arn


def _ecs_estate(ctx, iam, ecs, slug, desired):
    """A Fargate cluster and service at `desired` running tasks to be the scalable target.

    A scaling activity on an ECS service stays InProgress until ECS runs the new desiredCount, and
    no new activity starts while one is InProgress, so the tasks must actually run: Fargate, in the
    run's shared network, gives them placement capacity."""
    net = ctx.network()
    role_arn = _execution_role(ctx, iam)
    cluster = ctx.unique_name(f'sim2real-behav-aas-{slug}-cl-')
    service = ctx.unique_name(f'sim2real-behav-aas-{slug}-svc-')
    family = ctx.unique_name(f'sim2real-behav-aas-{slug}-td-')
    pairs = [{'key': 'sim2real', 'value': CHECK}, {'key': 'owner', 'value': 'sim2real-behav-aas'}]
    ecs.create_cluster(clusterName=cluster, tags=pairs)
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    task_def = ecs.register_task_definition(
        family=family, networkMode='awsvpc', requiresCompatibilities=['FARGATE'],
        cpu='256', memory='512', executionRoleArn=role_arn,
        containerDefinitions=[{
            'name': 'sim2real-idle',
            'image': 'public.ecr.aws/docker/library/busybox:1.36',
            'essential': True, 'command': ['sh', '-c', 'sleep 3600'],
        }],
        tags=pairs,
    )['taskDefinition']['taskDefinitionArn']
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def))
    ecs.create_service(
        cluster=cluster, serviceName=service, taskDefinition=task_def, desiredCount=desired,
        launchType='FARGATE',
        networkConfiguration={'awsvpcConfiguration': {
            'subnets': list(net.subnet_ids), 'securityGroups': [net.security_group_id],
            'assignPublicIp': 'ENABLED'}},
        tags=pairs)
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, service))
    _poll_until(lambda: _running_count(ecs, cluster, service), lambda c: c == desired,
                timeout_s=_RUNNING_S, interval_s=5.0,
                description=f'ECS reporting runningCount {desired} for {service!r}')
    return cluster, service, f'service/{cluster}/{service}'


def _running_count(ecs, cluster, service):
    described = ecs.describe_services(cluster=cluster, services=[service])['services']
    assert len(described) == 1, (
        f'DescribeServices returned {len(described)} services for {service!r}: {described!r}')
    return described[0]['runningCount']


def _desired_count(ecs, cluster, service):
    """ECS's own view of the service Application Auto Scaling resizes."""
    described = ecs.describe_services(cluster=cluster, services=[service])['services']
    assert len(described) == 1, (
        f'DescribeServices returned {len(described)} services for {service!r}: {described!r}')
    return described[0]['desiredCount']


def _activities(aas, resource_id):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id, 'ScalableDimension': _DIM,
                  'IncludeNotScaledActivities': True}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _alarm_state(cw, name):
    alarms = cw.describe_alarms(AlarmNames=[name])['MetricAlarms']
    assert len(alarms) == 1, f'DescribeAlarms returned {len(alarms)} alarms named {name!r}'
    return alarms[0]['StateValue']


def _publish(cw, value, dimension):
    cw.put_metric_data(
        Namespace=_METRIC_NAMESPACE,
        MetricData=[{
            'MetricName': _METRIC_NAME,
            'Dimensions': [{'Name': 'Driver', 'Value': dimension}],
            'Timestamp': datetime.datetime.now(datetime.timezone.utc),
            'Value': value, 'Unit': 'None', 'StorageResolution': 1,
        }],
    )


def _step_policy(ctx, aas, resource_id, name, steps, cooldown):
    """A ChangeInCapacity step policy; returns its ARN."""
    arn = aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=name, PolicyType='StepScaling',
        StepScalingPolicyConfiguration={
            'AdjustmentType': 'ChangeInCapacity', 'MetricAggregationType': 'Maximum',
            'Cooldown': cooldown, 'StepAdjustments': steps,
        },
    )['PolicyARN']
    ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, name))
    return arn


def _alarm(ctx, cw, name, dimension, policy_arn, operator, missing='notBreaching'):
    """A 10-second alarm on the high-resolution metric this check publishes."""
    cw.put_metric_alarm(
        AlarmName=name, AlarmDescription=f'sim2real {CHECK}',
        Namespace=_METRIC_NAMESPACE, MetricName=_METRIC_NAME,
        Dimensions=[{'Name': 'Driver', 'Value': dimension}],
        Statistic='Maximum', Period=_ALARM_PERIOD_S, EvaluationPeriods=1, DatapointsToAlarm=1,
        Threshold=_THRESHOLD, ComparisonOperator=operator, TreatMissingData=missing,
        AlarmActions=[policy_arn],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}, {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    ctx.on_cleanup(lambda: _delete_alarm(cw, name))
    wired = cw.describe_alarms(AlarmNames=[name])['MetricAlarms']
    assert len(wired) == 1 and wired[0]['AlarmActions'] == [policy_arn], (
        f'the alarm {name!r} lists alarm actions {[a.get("AlarmActions") for a in wired]!r}; '
        f'it must point at exactly {policy_arn!r}')
    assert wired[0]['Period'] == _ALARM_PERIOD_S, (
        f'the alarm {name!r} reports Period {wired[0].get("Period")!r}, expected '
        f'{_ALARM_PERIOD_S}')


def _drive(cw, alarm, dimension, value, *, want, leg, timeout_s):
    """Publish `value` every few seconds until `alarm` reports `want`; bounded, raises."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        _publish(cw, value, dimension)
        last = _alarm_state(cw, alarm)
        if last == want:
            return
        time.sleep(4.0)
    raise AssertionError(f'{leg}: alarm {alarm!r} never reached {want} within {timeout_s}s of '
                         f'publishing {value} against {_THRESHOLD}; last state {last!r}')


# timing:real-time — metric: 10 s
@tags('axis:negative-delivery', 'cap:c4', 'concern:metrics', 'plane:control', 'timing:real-time')
def run(ctx) -> None:
    """With DynamicScalingInSuspended, a scale-in alarm in ALARM removes no capacity while a
    scale-out alarm on the same series still adds capacity; resuming scale-in lets the same alarm
    remove it.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-suspend-resume-scaling.html
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    iam = ctx.client('iam')

    cluster, service, resource_id = _ecs_estate(ctx, iam, ecs, 'susin', _START_COUNT)
    _poll_until(lambda: _desired_count(ecs, cluster, service), lambda c: c == _START_COUNT,
                timeout_s=60, interval_s=3.0,
                description=f'ECS reporting desiredCount {_START_COUNT} for {service!r}')
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=_MIN_CAPACITY,
                                 MaxCapacity=_MAX_CAPACITY,
                                 SuspendedState={'DynamicScalingInSuspended': True},
                                 Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'})
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    described = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_DIM)['ScalableTargets']
    assert described and described[0]['SuspendedState'] == {
        'DynamicScalingInSuspended': True, 'DynamicScalingOutSuspended': False,
        'ScheduledScalingSuspended': False}, (
        f'the registered target reports {[t.get("SuspendedState") for t in described]!r}')

    out_policy = ctx.unique_name('sim2real-behav-aas-susoutpol-')
    in_policy = ctx.unique_name('sim2real-behav-aas-susinpol-')
    out_arn = _step_policy(ctx, aas, resource_id, out_policy,
                           [{'MetricIntervalLowerBound': 0.0, 'ScalingAdjustment': 1}], 0)
    in_arn = _step_policy(ctx, aas, resource_id, in_policy,
                          [{'MetricIntervalUpperBound': 0.0, 'ScalingAdjustment': -1}], 0)
    out_alarm = ctx.unique_name('sim2real-behav-aas-susoutal-')
    in_alarm = ctx.unique_name('sim2real-behav-aas-susinal-')
    _alarm(ctx, cw, out_alarm, service, out_arn, 'GreaterThanThreshold')
    _alarm(ctx, cw, in_alarm, service, in_arn, 'LessThanThreshold')

    # ---- Blocked: the in alarm breaches and capacity does not fall.
    _drive(cw, in_alarm, service, _LOW, want='ALARM', leg='scale-in breach',
           timeout_s=_TRANSITION_S)
    hold_until = time.monotonic() + _HOLD_S
    samples = 0
    while time.monotonic() < hold_until:
        _publish(cw, _LOW, service)
        assert _alarm_state(cw, in_alarm) == 'ALARM', f'{in_alarm!r} left ALARM during the hold'
        desired = _desired_count(ecs, cluster, service)
        assert desired == _START_COUNT, (
            f'desiredCount fell to {desired} while DynamicScalingInSuspended was true; the in '
            f'alarm must not remove capacity')
        samples += 1
        time.sleep(5)
    assert samples >= 5, f'the hold must be sampled at least 5 times, got {samples}'
    set_lower = [a for a in _activities(aas, resource_id)
                 if a.get('Description') == f'Setting desired count to {_START_COUNT - 1}.']
    assert not set_lower, f'a scale-in activity ran while suspended: {set_lower!r}'

    # ---- Independent: scale-out still fires with scale-in suspended.
    _drive(cw, out_alarm, service, _HIGH, want='ALARM', leg='scale-out breach',
           timeout_s=_TRANSITION_S)

    def desired_while(value):
        _publish(cw, value, service)
        return _desired_count(ecs, cluster, service)

    peak = _poll_until(lambda: desired_while(_HIGH), lambda d: d > _START_COUNT,
                       timeout_s=_APPLY_S, interval_s=4.0,
                       description='scale-out firing while scale-in is suspended')
    assert peak == _MAX_CAPACITY, f'desiredCount became {peak}, expected {_MAX_CAPACITY}'
    out_act = _poll_until(
        lambda: [a for a in _activities(aas, resource_id)
                 if a.get('Description') == f'Setting desired count to {peak}.'],
        bool, timeout_s=_APPLY_S, interval_s=4.0,
        description=f'the activity "Setting desired count to {peak}."')[0]
    assert out_alarm in out_act['Cause'] and out_policy in out_act['Cause'], (
        f'the scale-out activity cause {out_act["Cause"]!r} does not name {out_alarm!r} and '
        f'{out_policy!r}')

    # ---- Positive control: resume scale-in, and the same in alarm now removes capacity.
    resumed_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM,
                                 SuspendedState={'DynamicScalingInSuspended': False})
    described = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_DIM)['ScalableTargets']
    assert described and described[0]['SuspendedState']['DynamicScalingInSuspended'] is False, (
        f'the resume did not persist: {described!r}')
    _drive(cw, in_alarm, service, _LOW, want='ALARM', leg='scale-in breach after resume',
           timeout_s=_TRANSITION_S)
    fallen = _poll_until(lambda: desired_while(_LOW), lambda d: d < peak,
                         timeout_s=_APPLY_S, interval_s=4.0,
                         description=f'scale-in from {peak} after resuming it')
    assert fallen == peak - 1, f'desiredCount fell {peak} -> {fallen}; one step of -1 expected'
    in_acts = _poll_until(
        lambda: [a for a in _activities(aas, resource_id)
                 if a.get('Description') == f'Setting desired count to {fallen}.'
                 and a['StartTime'] >= resumed_at],
        bool, timeout_s=_APPLY_S, interval_s=4.0,
        description=f'a scale-in activity after the resume setting desired count to {fallen}')
    assert in_alarm in in_acts[0]['Cause'] and in_policy in in_acts[0]['Cause'], (
        f'the scale-in activity cause {in_acts[0]["Cause"]!r} does not name {in_alarm!r} and '
        f'{in_policy!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
