"""step-scaling-never-fed-alarm-stays-insufficient-while-fed-twin-scales."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "step-scaling-never-fed-alarm-stays-insufficient-while-fed-twin-scales"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'cloudwatch', 'ecs', 'iam']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'UnfedAlarmDriver'
_START_COUNT = 1
_MIN_CAPACITY = 1
_MAX_CAPACITY = 6
_THRESHOLD = 50.0
_BREACH = _THRESHOLD + 25.0
_CONTROL_COOLDOWN_S = 3600
_ALARM_PERIOD_S = 10
_TRANSITION_S = 90.0
_APPLY_S = 150.0
#: Fargate tasks pull and start before runningCount reaches desiredCount.
_RUNNING_S = 180.0
#: How long the never-fed alarm is watched AFTER the fed control alarm has already scaled.
_HOLD_S = 60.0


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


def _state_updates(cw, name):
    items = cw.describe_alarm_history(AlarmName=name, HistoryItemType='StateUpdate',
                                      MaxRecords=100)['AlarmHistoryItems']
    return [json.loads(i['HistoryData']) for i in items]


# timing:real-time — metric: 10 s
@tags('axis:negative-delivery', 'cap:c4', 'concern:metrics', 'concern:negative-classes',
      'plane:control', 'timing:real-time')
def run(ctx) -> None:
    """An alarm whose metric never receives a datapoint stays INSUFFICIENT_DATA and never drives its
    scaling policy, while a twin alarm on a fed series, on the same scalable target, in the same
    minutes, does; repointed at the fed series, the same alarm and policy scale.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    iam = ctx.client('iam')

    cluster, service, resource_id = _ecs_estate(ctx, iam, ecs, 'unfed', _START_COUNT)
    fed, ghost = service, f'{service}-never-published'
    _poll_until(lambda: _desired_count(ecs, cluster, service), lambda c: c == _START_COUNT,
                timeout_s=60, interval_s=3.0,
                description=f'ECS reporting desiredCount {_START_COUNT} for {service!r}')
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=_MIN_CAPACITY,
                                 MaxCapacity=_MAX_CAPACITY,
                                 Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'})
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    step = [{'MetricIntervalLowerBound': 0.0, 'ScalingAdjustment': 1}]
    control_policy = ctx.unique_name('sim2real-behav-aas-unfedctlpol-')
    control_arn = _step_policy(ctx, aas, resource_id, control_policy, step, _CONTROL_COOLDOWN_S)
    subject_policy = ctx.unique_name('sim2real-behav-aas-unfedsubpol-')
    subject_arn = _step_policy(ctx, aas, resource_id, subject_policy,
                               [{'MetricIntervalLowerBound': 0.0, 'ScalingAdjustment': 2}], 0)
    control_alarm = ctx.unique_name('sim2real-behav-aas-unfedctlal-')
    subject_alarm = ctx.unique_name('sim2real-behav-aas-unfedsubal-')
    _alarm(ctx, cw, control_alarm, fed, control_arn, 'GreaterThanThreshold', missing='missing')
    _alarm(ctx, cw, subject_alarm, ghost, subject_arn, 'GreaterThanThreshold', missing='missing')

    # ---- Positive control: the fed series breaches and the control alarm scales 1 -> 2.
    _drive(cw, control_alarm, fed, _BREACH, want='ALARM', leg='control', timeout_s=_TRANSITION_S)
    desired = _poll_until(lambda: _desired_count(ecs, cluster, service),
                          lambda d: d > _START_COUNT, timeout_s=_APPLY_S, interval_s=4.0,
                          description=f'desiredCount rising above {_START_COUNT} from the control '
                                      f'alarm on the fed series')
    assert desired == _START_COUNT + 1, (
        f'desiredCount became {desired}; only the +1 control policy should have acted, so '
        f'{_START_COUNT + 1} was the only correct value')

    # ---- The absence: the never-fed alarm stays INSUFFICIENT_DATA and scales nothing.
    hold_until = time.monotonic() + _HOLD_S
    samples = 0
    while time.monotonic() < hold_until:
        _publish(cw, _BREACH, fed)
        state = _alarm_state(cw, subject_alarm)
        assert state == 'INSUFFICIENT_DATA', (
            f'the alarm on the never-published series Driver={ghost!r} is in {state}; with no '
            f'datapoint ever published and TreatMissingData=missing it must stay '
            f'INSUFFICIENT_DATA')
        now_desired = _desired_count(ecs, cluster, service)
        assert now_desired == _START_COUNT + 1, (
            f'desiredCount moved to {now_desired} while only the never-fed alarm could still act; '
            f'the control policy is inside its {_CONTROL_COOLDOWN_S}s cooldown')
        samples += 1
        time.sleep(5)
    assert samples >= 5, f'the hold must be sampled at least 5 times, got {samples}'
    assert _state_updates(cw, subject_alarm) == [], (
        f'the never-fed alarm {subject_alarm!r} recorded state transitions '
        f'{_state_updates(cw, subject_alarm)!r}')
    named = [a['Cause'] for a in _activities(aas, resource_id) if subject_alarm in a['Cause']]
    assert named == [], f'scaling activities name the never-fed alarm: {named!r}'
    assert not cw.list_metrics(Namespace=_METRIC_NAMESPACE, MetricName=_METRIC_NAME,
                               Dimensions=[{'Name': 'Driver', 'Value': ghost}])['Metrics'], (
        f'CloudWatch lists a series for the never-published dimension {ghost!r}')

    # ---- Repair: the SAME alarm and policy, repointed at the fed series, now scale.
    _alarm(ctx, cw, subject_alarm, fed, subject_arn, 'GreaterThanThreshold', missing='missing')
    _drive(cw, subject_alarm, fed, _BREACH, want='ALARM', leg='repaired',
           timeout_s=_TRANSITION_S)
    desired_after = _poll_until(lambda: _desired_count(ecs, cluster, service),
                                lambda d: d > _START_COUNT + 1, timeout_s=_APPLY_S,
                                interval_s=4.0,
                                description='desiredCount rising above 2 from the repaired alarm')
    # The control policy's cooldown may net its +1 into the +2 step, so 3 or 4, never more.
    assert desired_after <= _START_COUNT + 1 + 2, (
        f'desiredCount became {desired_after}; the +2 subject policy from 2 gives at most 4')
    by_subject = _poll_until(
        lambda: [a for a in _activities(aas, resource_id) if subject_alarm in a['Cause']],
        bool, timeout_s=_APPLY_S, interval_s=4.0,
        description=f'a scaling activity naming the repaired alarm {subject_alarm!r}')
    assert subject_policy in by_subject[0]['Cause'], (
        f'the activity {by_subject[0]["Cause"]!r} does not name the policy {subject_policy!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
