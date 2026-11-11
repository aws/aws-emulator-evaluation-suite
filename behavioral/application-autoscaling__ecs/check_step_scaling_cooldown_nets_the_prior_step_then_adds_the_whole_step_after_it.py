"""step-scaling-cooldown-nets-the-prior-step-then-adds-the-whole-step-after-it."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "step-scaling-cooldown-nets-the-prior-step-then-adds-the-whole-step-after-it"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'cloudwatch', 'ecs', 'iam']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'CooldownNetDriver'
_START_COUNT = 4
_SMALL_STEP = 2
_BIG_STEP = 3
_STEP_BOUNDARY = 20.0
_THRESHOLD = 50.0
_COOLDOWN_S = 180
_ALARM_PERIOD_S = 10
_TRANSITION_S = 90.0
_APPLY_S = 150.0
#: Fargate tasks pull and start before runningCount reaches desiredCount.
_RUNNING_S = 180.0
#: How far before the window closes the in-window breach must already be in ALARM.
_INSIDE_MARGIN_S = 45.0
#: How far past the window's close the after-window breach is driven.
_AFTER_MARGIN_S = 20.0


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


# timing:real-time — cooldown: 180 s
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics', 'plane:control',
      'timing:real-time')
def run(ctx) -> None:
    """A more aggressive step firing inside a step policy's Cooldown adds only the difference over
    what the first activity added (4 -> 6 -> 7), and the same breach after the window adds the whole
    adjustment (7 -> 10): Cooldown is neither ignored nor a hard block.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    iam = ctx.client('iam')

    cluster, service, resource_id = _ecs_estate(ctx, iam, ecs, 'cdnet', _START_COUNT)
    initial = _poll_until(lambda: _desired_count(ecs, cluster, service),
                          lambda c: c == _START_COUNT, timeout_s=60, interval_s=3.0,
                          description=f'ECS reporting desiredCount {_START_COUNT} for {service!r}')

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20,
                                 Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'})
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    policy = ctx.unique_name('sim2real-behav-aas-cdnetpol-')
    policy_arn = _step_policy(ctx, aas, resource_id, policy, [
        {'MetricIntervalLowerBound': 0.0, 'MetricIntervalUpperBound': _STEP_BOUNDARY,
         'ScalingAdjustment': _SMALL_STEP},
        {'MetricIntervalLowerBound': _STEP_BOUNDARY, 'ScalingAdjustment': _BIG_STEP},
    ], _COOLDOWN_S)
    stored = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyNames=[policy])['ScalingPolicies']
    assert len(stored) == 1, f'DescribeScalingPolicies returned {stored!r} for {policy!r}'
    assert stored[0]['StepScalingPolicyConfiguration']['Cooldown'] == _COOLDOWN_S, (
        f'the stored policy reports Cooldown '
        f'{stored[0]["StepScalingPolicyConfiguration"].get("Cooldown")!r}, expected {_COOLDOWN_S}')

    alarm = ctx.unique_name('sim2real-behav-aas-cdnetalarm-')
    _alarm(ctx, cw, alarm, service, policy_arn, 'GreaterThanThreshold')

    def drive(value, want, leg):
        _drive(cw, alarm, service, value, want=want, leg=leg, timeout_s=_TRANSITION_S)

    # ---- Leg 1: the initiating scale-out; a small breach selects the +_SMALL_STEP step.
    drive(_THRESHOLD + 5.0, 'ALARM', 'leg 1')
    expected_first = initial + _SMALL_STEP
    first_count = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c != initial,
        timeout_s=_APPLY_S, interval_s=3.0,
        description=f'leg 1: desiredCount moving off {initial} after a breach inside the '
                    f'[0, {_STEP_BOUNDARY}) step')
    assert first_count == expected_first, (
        f'leg 1: desiredCount {first_count}; +{_SMALL_STEP} on {initial} is {expected_first}')
    first_activity = _poll_until(
        lambda: [a for a in _activities(aas, resource_id) if a.get('EndTime')], bool,
        timeout_s=_APPLY_S, interval_s=3.0,
        description='leg 1: the initiating activity reaching an EndTime, where the cooldown '
                    'starts')[0]
    assert first_activity['Description'] == f'Setting desired count to {expected_first}.', (
        f'leg 1: the activity described itself as {first_activity["Description"]!r}')
    cooldown_started = first_activity['EndTime']
    cooldown_ends = cooldown_started + datetime.timedelta(seconds=_COOLDOWN_S)

    # ---- Leg 2: a more aggressive step inside the window adds only the difference.
    drive(_THRESHOLD - 40.0, 'OK', 'leg 2 (returning to OK)')
    drive(_THRESHOLD + _STEP_BOUNDARY + 10.0, 'ALARM', 'leg 2')
    now = datetime.datetime.now(datetime.timezone.utc)
    assert now < cooldown_ends - datetime.timedelta(seconds=_INSIDE_MARGIN_S), (
        f'leg 2 reached ALARM at {now.isoformat()}, not inside the cooldown window '
        f'{cooldown_started.isoformat()} .. {cooldown_ends.isoformat()} with '
        f'{_INSIDE_MARGIN_S}s to spare')
    expected_second = initial + _BIG_STEP
    second_count = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c != first_count,
        timeout_s=min(_APPLY_S, (cooldown_ends - now).total_seconds()), interval_s=3.0,
        description=f'leg 2: desiredCount moving off {first_count} on a breach above the '
                    f'{_STEP_BOUNDARY} step boundary inside the {_COOLDOWN_S}s cooldown')
    assert second_count == expected_second, (
        f'leg 2: desiredCount {second_count}. Inside the cooldown the +{_SMALL_STEP} already '
        f'added counts toward the +{_BIG_STEP} step, so the count is {expected_second}; ignoring '
        f'the cooldown gives {first_count + _BIG_STEP}, a hard block leaves {first_count}')

    # ---- Leg 3: the same breach after the window adds the whole adjustment.
    drive(_THRESHOLD - 40.0, 'OK', 'leg 3 (returning to OK)')
    wait_for = ((cooldown_ends - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
                + _AFTER_MARGIN_S)
    assert wait_for <= _COOLDOWN_S + _AFTER_MARGIN_S, (
        f'leg 3 would wait {wait_for:.0f}s, longer than the {_COOLDOWN_S}s cooldown itself')
    wait_deadline = time.monotonic() + wait_for
    while time.monotonic() < wait_deadline:
        time.sleep(max(0.0, min(10.0, wait_deadline - time.monotonic())))
        frozen = _desired_count(ecs, cluster, service)
        assert frozen == second_count, (
            f'leg 3: desiredCount moved to {frozen} from {second_count} inside the window ending '
            f'{cooldown_ends.isoformat()} with no breach driven')
    drive(_THRESHOLD + _STEP_BOUNDARY + 10.0, 'ALARM', 'leg 3')
    expected_third = second_count + _BIG_STEP
    third_count = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c != second_count,
        timeout_s=_APPLY_S, interval_s=3.0,
        description=f'leg 3: desiredCount moving off {second_count} after the window closed at '
                    f'{cooldown_ends.isoformat()}')
    assert third_count == expected_third, (
        f'leg 3: desiredCount {third_count}; with no cooldown in effect +{_BIG_STEP} on '
        f'{second_count} is {expected_third}')
    newest = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: acts and acts[0]['Description'] == f'Setting desired count to {expected_third}.',
        timeout_s=_APPLY_S, interval_s=3.0,
        description=f'the newest activity naming "Setting desired count to {expected_third}."')
    assert newest[0]['StartTime'] >= cooldown_ends, (
        f'the after-window activity started {newest[0]["StartTime"].isoformat()}, before the '
        f'window closed at {cooldown_ends.isoformat()}')


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
