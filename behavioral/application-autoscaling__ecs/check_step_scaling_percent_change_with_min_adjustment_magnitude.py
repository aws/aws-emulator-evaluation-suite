"""step-scaling-percent-change-with-min-adjustment-magnitude."""
from __future__ import annotations

import datetime
import json
import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# AWS starts no new scaling activity on a resource while a prior one is InProgress, so each
# arithmetic leg runs on its own cluster, service, scalable target, policy and alarm. The subject is
# AWS's worked example: 25% of 4 is 1, floored by MinAdjustmentMagnitude 2 to 2 (4 -> 6), and 60% of
# 6 is 3.6, rounded down to 3 (6 -> 9). Leg 3 deletes the step policy: the alarm stays, its action goes.

CHECK = "step-scaling-percent-change-with-min-adjustment-magnitude"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'ecs']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'StepDriver'

_THRESHOLD = 50.0
_MIN_CAPACITY = 1
_MAX_CAPACITY = 40
_MIN_MAGNITUDE = 2

#: Leg "floor": 25% of 4 is 1.0, which is not more than 1 and so needs no rounding, but
#: MinAdjustmentMagnitude 2 floors the adjustment at 2 regardless -- AWS's own worked example.
_FLOOR_START = 4
_FLOOR_PERCENT = 25
#: Leg "round": AWS's own worked example continues from the RESULT of leg "floor" (6); this leg
#: runs on its own independent target, so 6 is a literal matching that continuation. 60% of 6 is
#: 3.6, strictly more than 1, so it rounds DOWN to 3, and MinAdjustmentMagnitude 2 does not bind.
_ROUND_START = 6
_ROUND_PERCENT = 60

_ALARM_PERIOD_S = 10
_TRANSITION_S = 150.0
_APPLY_S = 180.0
_ESTATE_S = 90.0
#: Fargate tasks pull and start before the service's runningCount reaches its desiredCount.
_RUNNING_S = 300.0
#: Long enough that the alarm, still in ALARM, cannot re-invoke the policy on the new capacity.
_COOLDOWN_S = 600
_TASK_CPU = '256'
_TASK_MEMORY = '512'
_CANDIDATE_S = 60.0
#: Two independent legs, each able to need its own full budget; leg 3 reuses leg "floor"'s estate.
_TOTAL_BUDGET_S = 2 * (_ESTATE_S + _RUNNING_S + _TRANSITION_S + _APPLY_S + _CANDIDATE_S) + 120.0


# ===== helpers =====
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


def _deregister(aas, resource_id):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=_DIM)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _delete_policy(aas, resource_id, policy):
    try:
        aas.delete_scaling_policy(ServiceNamespace=_NS, ResourceId=resource_id,
                                  ScalableDimension=_DIM, PolicyName=policy)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _delete_alarm(cw, name):
    try:
        cw.delete_alarms(AlarmNames=[name])
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("ResourceNotFound",):
            raise RuntimeError(
                f'alarm {name!r} not deleted: {exc.response.get("Error", {}).get("Code")}'
            ) from exc


def _delete_service(ecs, cluster, service):
    try:
        ecs.update_service(cluster=cluster, service=service, desiredCount=0)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') not in ('ServiceNotFoundException',
                                                             'ServiceNotActiveException'):
            raise
    try:
        ecs.delete_service(cluster=cluster, service=service, force=True)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ServiceNotFoundException':
            raise


def _delete_cluster(ecs, cluster):
    """DeleteCluster fails while any service or task is still draining; retry, then say so out loud."""
    for _ in range(16):
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ClusterNotFoundException':
                return
            if code not in ('ClusterContainsServicesException', 'ClusterContainsTasksException'):
                raise RuntimeError(f'cluster {cluster!r} not deleted: {code}') from exc
            time.sleep(8)
    raise RuntimeError(
        f'cluster {cluster!r} still contains a draining service or task after retries'
    )


def _deregister_task_definition(ecs, arn):
    try:
        _retire_task_definition(ecs, arn)
    except ClientError as exc:
        raise RuntimeError(f'task definition {arn!r} not deregistered: '
                           f'{exc.response.get("Error", {}).get("Code")}') from exc


def _detach_role_policy(iam, role_name, policy_arn):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'NoSuchEntity':
            raise


def _delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'NoSuchEntity':
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
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _detach_role_policy(iam, role_name, policy_arn))
    return role_arn


def _ecs_estate(ctx, iam, ecs, slug, desired):
    """A Fargate cluster, a task definition and a service with `desired` tasks; cleanups registered.

    Step scaling computes its adjustment from the service's RUNNING capacity, so the tasks must
    actually run: Fargate, in the run's shared network, gives them placement capacity.
    """
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
        cpu=_TASK_CPU, memory=_TASK_MEMORY, executionRoleArn=role_arn,
        containerDefinitions=[{
            'name': 'sim2real-idle',
            'image': 'public.ecr.aws/docker/library/busybox:1.36',
            'essential': True, 'command': ['sh', '-c', 'sleep 3600'],
        }],
        tags=pairs,
    )['taskDefinition']['taskDefinitionArn']
    ctx.on_cleanup(lambda: _deregister_task_definition(ecs, task_def))
    ecs.create_service(
        cluster=cluster, serviceName=service, taskDefinition=task_def, desiredCount=desired,
        launchType='FARGATE',
        networkConfiguration={'awsvpcConfiguration': {
            'subnets': list(net.subnet_ids), 'securityGroups': [net.security_group_id],
            'assignPublicIp': 'ENABLED'}},
        tags=pairs)
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, service))
    return cluster, service, f'service/{cluster}/{service}'


def _running_count(ecs, cluster, service):
    described = ecs.describe_services(cluster=cluster, services=[service])['services']
    assert len(described) == 1, (
        f'DescribeServices returned {len(described)} services for {service!r}: {described!r}'
    )
    return described[0]['runningCount']


def _desired_count(ecs, cluster, service):
    """The terminal read, at the CONSUMER: ECS's own view of the service it was told to resize."""
    described = ecs.describe_services(cluster=cluster, services=[service])['services']
    assert len(described) == 1, (
        f'DescribeServices returned {len(described)} services for {service!r} in cluster '
        f'{cluster!r}, expected exactly 1: {described!r}'
    )
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
    assert len(alarms) == 1, (
        f'DescribeAlarms returned {len(alarms)} alarms named {name!r}, expected exactly 1'
    )
    return alarms[0]['StateValue']


def _percent_adjustment(capacity, percent, min_magnitude):
    """The documented PercentChangeInCapacity arithmetic, written as the rule not the answer.

    Positive adjustments only, which is all this check drives:
      raw = capacity * percent / 100
      raw > 1        -> rounded DOWN   ("12.7 is rounded to 12")
      0 < raw <= 1   -> rounded to 1   (".67 is rounded to 1")
    then MinAdjustmentMagnitude is a FLOOR on the magnitude, not a replacement for it.
    """
    raw = capacity * percent / 100.0
    rounded = math.floor(raw) if raw > 1.0 else 1
    return max(rounded, min_magnitude)


def _run_leg(ctx, aas, cw, ecs, iam, account, *, slug, start, percent, leg):
    """One PercentChangeInCapacity + MinAdjustmentMagnitude decision, on its OWN independent
    cluster/service/scalable target/policy/alarm: a shared resource across sequential breaches
    shows only its first decision.

    Returns (resource_id, policy_name, policy_arn, alarm_name) so leg "floor" can be handed to
    leg 3.
    """
    cluster, service, resource_id = _ecs_estate(ctx, iam, ecs, slug, start)
    initial = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c == start,
        timeout_s=_ESTATE_S, interval_s=3.0,
        description=f'{leg}: ECS reporting desiredCount {start} for {service!r} before anything '
                    f'scales it')
    assert initial == start, (
        f'{leg}: ECS reports desiredCount {initial} for the freshly created service {service!r} '
        f'in region {ctx.region} of account {account}, expected {start}; the documented '
        f'arithmetic below is anchored on that starting capacity'
    )
    _poll_until(
        lambda: _running_count(ecs, cluster, service), lambda c: c == start,
        timeout_s=_RUNNING_S, interval_s=5.0,
        description=f'{leg}: ECS reporting runningCount {start} for {service!r}, the capacity '
                    f'step scaling reads')

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    policy_name = ctx.unique_name(f'sim2real-behav-aas-{slug}-pol-')
    put = aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy_name, PolicyType='StepScaling',
        StepScalingPolicyConfiguration={
            'AdjustmentType': 'PercentChangeInCapacity',
            'MinAdjustmentMagnitude': _MIN_MAGNITUDE,
            'MetricAggregationType': 'Maximum',
            'Cooldown': _COOLDOWN_S,
            'StepAdjustments': [{'MetricIntervalLowerBound': 0.0, 'ScalingAdjustment': percent}],
        },
    )
    ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, policy_name))
    assert put.get('Alarms', []) == [], (
        f'{leg}: PutScalingPolicy for a StepScaling policy returned alarms {put.get("Alarms")!r}; '
        f'step scaling requires the CALLER to supply the alarm, so Application Auto Scaling must '
        f'not mint one -- if it does, the alarm this check creates is not the one driving the policy'
    )
    stored = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyNames=[policy_name])['ScalingPolicies']
    assert len(stored) == 1, (
        f'{leg}: DescribeScalingPolicies returned {len(stored)} policies named {policy_name!r}: '
        f'{stored!r}'
    )
    config = stored[0]['StepScalingPolicyConfiguration']
    assert config['MinAdjustmentMagnitude'] == _MIN_MAGNITUDE, (
        f'{leg}: the stored policy reports MinAdjustmentMagnitude '
        f'{config.get("MinAdjustmentMagnitude")!r}, expected {_MIN_MAGNITUDE}; the arithmetic '
        f'below cannot be attributed to a field the target did not keep'
    )
    policy_arn = put['PolicyARN']

    alarm_name = ctx.unique_name(f'sim2real-behav-aas-{slug}-al-')
    cw.put_metric_alarm(
        AlarmName=alarm_name, AlarmDescription=f'sim2real {CHECK}',
        Namespace=_METRIC_NAMESPACE, MetricName=_METRIC_NAME,
        Dimensions=[{'Name': 'ServiceName', 'Value': service}],
        Statistic='Maximum', Period=_ALARM_PERIOD_S, EvaluationPeriods=1, DatapointsToAlarm=1,
        Threshold=_THRESHOLD, ComparisonOperator='GreaterThanThreshold',
        TreatMissingData='notBreaching', AlarmActions=[policy_arn],
        Tags=[{'Key': 'sim2real', 'Value': CHECK},
              {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    ctx.on_cleanup(lambda: _delete_alarm(cw, alarm_name))
    wired = cw.describe_alarms(AlarmNames=[alarm_name])['MetricAlarms']
    assert len(wired) == 1 and wired[0]['AlarmActions'] == [policy_arn], (
        f'{leg}: the alarm {alarm_name!r} lists alarm actions '
        f'{[a.get("AlarmActions") for a in wired]!r}; it must point at exactly the step policy '
        f'{policy_arn!r} or a breach reaches nothing'
    )

    def _publish(value):
        cw.put_metric_data(
            Namespace=_METRIC_NAMESPACE,
            MetricData=[{
                'MetricName': _METRIC_NAME,
                'Dimensions': [{'Name': 'ServiceName', 'Value': service}],
                'Timestamp': datetime.datetime.now(datetime.timezone.utc),
                'Value': value, 'Unit': 'Percent', 'StorageResolution': 1,
            }],
        )

    known_ids = {a['ActivityId'] for a in _activities(aas, resource_id)}
    breach_value = _THRESHOLD + 5.0

    deadline = time.monotonic() + _TRANSITION_S
    last = None
    while time.monotonic() < deadline:
        _publish(breach_value)
        last = _alarm_state(cw, alarm_name)
        if last == 'ALARM':
            break
        time.sleep(5.0)
    else:
        raise AssertionError(
            f'{leg}: alarm {alarm_name!r} never reached ALARM within {_TRANSITION_S}s of '
            f'publishing {breach_value} against a threshold of {_THRESHOLD}; last saw {last!r}')

    expected_after = start + _percent_adjustment(start, percent, _MIN_MAGNITUDE)

    def _probe():
        _publish(breach_value)
        return _desired_count(ecs, cluster, service)

    try:
        after = _poll_until(
            _probe, lambda c: c != start, timeout_s=_APPLY_S, interval_s=4.0,
            description=f'{leg}: ECS desiredCount for {service!r} moving off {start} after the '
                        f'step policy fired on a breach of {breach_value} ({percent}% step)')
    except AssertionError as exc:
        dump = [{k: a.get(k) for k in
                 ('ActivityId', 'StatusCode', 'Description', 'NotScaledReasons')}
                for a in _activities(aas, resource_id)]
        raise AssertionError(f'{exc} -- DEBUG all activities: {dump!r}') from None

    assert after == expected_after, (
        f'{leg}: ECS reports desiredCount {after} for {service!r}; {percent}% of {start} is '
        f'{start * percent / 100.0}, and MinAdjustmentMagnitude {_MIN_MAGNITUDE} '
        f'{"floors" if _percent_adjustment(start, percent, _MIN_MAGNITUDE) == _MIN_MAGNITUDE else "does not bind, so rounding decides"} '
        f'the adjustment, giving {expected_after}. An implementation that stores '
        f'MinAdjustmentMagnitude and ignores it, or rounds the raw percentage differently, answers '
        f'something else'
    )

    def _new_candidate():
        for activity in _activities(aas, resource_id):
            if (activity['ActivityId'] not in known_ids
                    and activity.get('Description') == f'Setting desired count to {after}.'
                    and activity['StatusCode'] not in ('PendingBeforeAlarmThreshold',
                                                       'PendingBeforeCooldownAfterInternal',
                                                       'PendingSchedule')):
                return activity
        return None

    newest = _poll_until(
        _new_candidate, lambda a: a is not None, timeout_s=_CANDIDATE_S, interval_s=3.0,
        description=f'{leg}: a new, past-its-initial-pending-state scaling activity describing '
                    f'"Setting desired count to {after}."')
    assert newest['Cause'] == f'monitor alarm {alarm_name} in state ALARM triggered policy ' \
                              f'{policy_name}', (
        f'{leg}: the scaling activity attributes itself to {newest["Cause"]!r}; real AWS names '
        f'the alarm {alarm_name!r} and the policy {policy_name!r}'
    )
    assert newest['ServiceNamespace'] == _NS, (
        f'{leg}: the activity carried service namespace {newest["ServiceNamespace"]!r}, expected '
        f'{_NS!r}'
    )
    return resource_id, policy_name, policy_arn, alarm_name


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics', 'plane:control', "timing:real-time")
def run(ctx) -> None:
    """A step policy invoked by a CloudWatch alarm breach applies the documented
    PercentChangeInCapacity arithmetic to the ECS service's desiredCount: MinAdjustmentMagnitude
    floors 25% of 4 to +2, and 60% of 6 rounds down to +3.
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    iam = ctx.client('iam')
    account = ctx.client('sts').get_caller_identity()['Account']

    assert 0.0 < _FLOOR_START * _FLOOR_PERCENT / 100.0 <= 1.0, (
        f'leg floor is misconfigured: {_FLOOR_PERCENT}% of {_FLOOR_START} is '
        f'{_FLOOR_START * _FLOOR_PERCENT / 100.0}, expected in (0, 1] so MinAdjustmentMagnitude is '
        f'the binding constraint, not the rounding rule'
    )
    assert _ROUND_START * _ROUND_PERCENT / 100.0 > _MIN_MAGNITUDE, (
        f'leg round is misconfigured: {_ROUND_PERCENT}% of {_ROUND_START} is '
        f'{_ROUND_START * _ROUND_PERCENT / 100.0}, expected greater than MinAdjustmentMagnitude '
        f'{_MIN_MAGNITUDE} so rounding, not the magnitude floor, decides the answer'
    )

    floor_resource_id, floor_policy_name, floor_policy_arn, floor_alarm = _run_leg(
        ctx, aas, cw, ecs, iam, account, slug='floor', start=_FLOOR_START, percent=_FLOOR_PERCENT,
        leg='leg floor')
    _run_leg(
        ctx, aas, cw, ecs, iam, account, slug='round', start=_ROUND_START, percent=_ROUND_PERCENT,
        leg='leg round')

    # ---- Leg 3: the documented delete ASYMMETRY, reusing leg "floor"'s resource -- it needs no
    # new scaling decision, only a delete-and-observe, so it is safe on an already-used target.
    # DeleteScalingPolicy's own API reference says: "Deleting a step scaling policy deletes the
    # underlying alarm action, but does not delete the CloudWatch alarm associated with the scaling
    # policy, even if it no longer has an associated action." That is the opposite of the
    # target-tracking case, whose minted alarms are deleted with the policy: the alarm here belongs
    # to the customer, not to Application Auto Scaling.
    aas.delete_scaling_policy(ServiceNamespace=_NS, ResourceId=floor_resource_id,
                              ScalableDimension=_DIM, PolicyName=floor_policy_name)
    assert aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=floor_resource_id,
        ScalableDimension=_DIM)['ScalingPolicies'] == [], (
        f'DescribeScalingPolicies still lists a policy for {floor_resource_id!r} after leg '
        f'floor\'s policy was deleted'
    )
    orphaned = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[floor_alarm])['MetricAlarms'],
        lambda found: len(found) == 1 and found[0]['AlarmActions'] == [],
        timeout_s=60, interval_s=3.0,
        description=f'the check-owned alarm {floor_alarm!r} SURVIVING the deletion of leg '
                    f'floor\'s step policy with its alarm action stripped')
    assert len(orphaned) == 1, (
        f'deleting the step scaling policy also deleted the alarm {floor_alarm!r}, which the '
        f'check created and Application Auto Scaling does not own; CloudWatch reports '
        f'{orphaned!r}. Target-tracking policies DO delete their own alarms -- applying that rule '
        f'to a step policy destroys a customer resource'
    )
    assert orphaned[0]['AlarmActions'] == [], (
        f'the surviving alarm {floor_alarm!r} still lists alarm actions '
        f'{orphaned[0]["AlarmActions"]!r} pointing at the deleted policy {floor_policy_arn!r}; '
        f'DeleteScalingPolicy must strip the underlying alarm action even though it leaves the '
        f'alarm in place, or the next breach dispatches to a policy that no longer exists'
    )
    assert orphaned[0]['Threshold'] == _THRESHOLD, (
        f'the surviving alarm {floor_alarm!r} reports threshold {orphaned[0]["Threshold"]!r}; '
        f'only the action may be stripped, and the rest of the alarm this check created must be '
        f'untouched'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")
