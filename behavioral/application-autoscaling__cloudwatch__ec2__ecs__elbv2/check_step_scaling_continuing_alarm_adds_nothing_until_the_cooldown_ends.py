"""step-scaling-continuing-alarm-adds-nothing-until-the-cooldown-ends."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "step-scaling-continuing-alarm-adds-nothing-until-the-cooldown-ends"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'cloudwatch', 'ecs', 'iam']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'ContinuingAlarmDriver'
_START_COUNT = 1
_MIN_CAPACITY = 1
_MAX_CAPACITY = 3
_STEP = 1
_COOLDOWN_S = 120
_THRESHOLD = 50.0
_BREACH = _THRESHOLD + 25.0
_ALARM_PERIOD_S = 10
_TRANSITION_S = 90.0
_APPLY_S = 150.0
#: Fargate tasks pull and start before runningCount reaches desiredCount.
_RUNNING_S = 180.0
#: A ceiling on the second action: the cooldown, the alarm's once-a-minute re-invocation of a
#: policy while it stays in ALARM, and the activity itself.
_SECOND_ACTION_S = _COOLDOWN_S + 150.0


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


def _transitions(cw, name):
    items = cw.describe_alarm_history(AlarmName=name, HistoryItemType='StateUpdate',
                                      MaxRecords=100)['AlarmHistoryItems']
    return [json.loads(i['HistoryData']) for i in items]


# timing:real-time — cooldown: 120 s
@tags('axis:negative-delivery', 'cap:c4', 'concern:metrics', 'plane:control', 'timing:real-time')
def run(ctx) -> None:
    """While a step policy's cooldown runs, an alarm that STAYS in ALARM keeps invoking the policy
    and adds nothing; once the cooldown has elapsed from the first activity's end, the same
    continuing alarm adds the next step.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    iam = ctx.client('iam')

    cluster, service, resource_id = _ecs_estate(ctx, iam, ecs, 'cdhold', _START_COUNT)
    _poll_until(lambda: _desired_count(ecs, cluster, service), lambda c: c == _START_COUNT,
                timeout_s=60, interval_s=3.0,
                description=f'ECS reporting desiredCount {_START_COUNT} for {service!r}')
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=_MIN_CAPACITY,
                                 MaxCapacity=_MAX_CAPACITY,
                                 Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'})
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    policy = ctx.unique_name('sim2real-behav-aas-cdholdpol-')
    policy_arn = _step_policy(ctx, aas, resource_id, policy,
                              [{'MetricIntervalLowerBound': 0.0, 'ScalingAdjustment': _STEP}],
                              _COOLDOWN_S)
    stored = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyNames=[policy])['ScalingPolicies']
    assert len(stored) == 1 and \
        stored[0]['StepScalingPolicyConfiguration']['Cooldown'] == _COOLDOWN_S, (
            f'the stored policy does not report Cooldown {_COOLDOWN_S}: {stored!r}')
    alarm = ctx.unique_name('sim2real-behav-aas-cdholdalarm-')
    _alarm(ctx, cw, alarm, service, policy_arn, 'GreaterThanThreshold')

    # Sustained breach from here on: every probe publishes, so the alarm stays in ALARM.
    _drive(cw, alarm, service, _BREACH, want='ALARM', leg='breach', timeout_s=_TRANSITION_S)

    def desired_while_breaching():
        _publish(cw, _BREACH, service)
        return _desired_count(ecs, cluster, service)

    first_desired = _poll_until(desired_while_breaching, lambda d: d > _START_COUNT,
                                timeout_s=_APPLY_S, interval_s=4.0,
                                description='the first scale-out from the breaching alarm')
    assert first_desired == _START_COUNT + _STEP, (
        f'the first action set desiredCount {first_desired}, expected {_START_COUNT + _STEP}')
    want_first = f'Setting desired count to {first_desired}.'

    def first_ended():
        _publish(cw, _BREACH, service)
        return [a for a in _activities(aas, resource_id)
                if a.get('Description') == want_first and a.get('EndTime')]

    first = _poll_until(first_ended, bool, timeout_s=_APPLY_S, interval_s=4.0,
                        description=f'the activity "{want_first}" reaching an EndTime')[0]
    window_ends = first['EndTime'] + datetime.timedelta(seconds=_COOLDOWN_S)

    samples = []

    def probe():
        d = desired_while_breaching()
        samples.append((datetime.datetime.now(datetime.timezone.utc), d))
        return d

    final = _poll_until(probe, lambda d: d > first_desired, timeout_s=_SECOND_ACTION_S,
                        interval_s=4.0,
                        description=f'the continuing alarm adding the next step after the '
                                    f'{_COOLDOWN_S}s cooldown (alarm {_alarm_state(cw, alarm)})')
    assert final == first_desired + _STEP, (
        f'desiredCount went {first_desired} -> {final}; one more step of {_STEP} is the only '
        f'correct result')
    early = [(t.isoformat(), d) for t, d in samples if t < window_ends and d != first_desired]
    assert not early, (
        f'desiredCount moved inside the cooldown window ending {window_ends.isoformat()}: {early!r}')
    want_second = f'Setting desired count to {final}.'
    second = _poll_until(
        lambda: [a for a in _activities(aas, resource_id) if a.get('Description') == want_second],
        bool, timeout_s=_APPLY_S, interval_s=4.0,
        description=f'the activity "{want_second}"')[0]
    assert second['StartTime'] >= window_ends, (
        f'the second scale-out started {second["StartTime"].isoformat()}, before the first '
        f'activity ended at {first["EndTime"].isoformat()} plus the {_COOLDOWN_S}s cooldown')
    assert alarm in second['Cause'] and policy in second['Cause'], (
        f'the second activity cause {second["Cause"]!r} does not name {alarm!r} and {policy!r}')
    left = [t for t in _transitions(cw, alarm) if t['oldState']['stateValue'] == 'ALARM']
    assert not left, (
        f'{alarm!r} left ALARM during the window, so the suppression is not shown: {left!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
