"""step-scaling-adjustment-is-clamped-into-the-current-registered-bounds."""
from __future__ import annotations

import datetime
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "step-scaling-adjustment-is-clamped-into-the-current-registered-bounds"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'ecs']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'ClampDriver'

_THRESHOLD = 50.0
_START_COUNT = 4
_MIN_CAPACITY = 4
_MAX_CAPACITY = 6
#: Deliberately far larger than the width of the registered range, so an unclamped implementation
#: overshoots by a margin no rounding rule could explain.
_OUT_ADJ = 10
_IN_ADJ = -10

_ALARM_PERIOD_S = 10
_TRANSITION_S = 90.0
_APPLY_S = 45.0
_ESTATE_S = 90.0
_CANDIDATE_S = 60.0
#: The two legs run concurrently on separate targets, so the check needs one leg's budget.
_TOTAL_BUDGET_S = _ESTATE_S + _TRANSITION_S + _APPLY_S + _CANDIDATE_S


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition',
                ctx=None):
    """Bounded retry with a deadline that RAISES on timeout, never returns its last value."""
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
    """DeleteCluster fails while any service is still draining; retry, then say so out loud."""
    for _ in range(16):
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ClusterNotFoundException':
                return
            if code != 'ClusterContainsServicesException':
                raise RuntimeError(f'cluster {cluster!r} not deleted: {code}') from exc
            time.sleep(3)
    raise RuntimeError(
        f'cluster {cluster!r} still contains a draining service after retries'
    )


def _deregister_task_definition(ecs, arn):
    try:
        _retire_task_definition(ecs, arn)
    except ClientError as exc:
        raise RuntimeError(f'task definition {arn!r} not deregistered: '
                           f'{exc.response.get("Error", {}).get("Code")}') from exc


def _ecs_estate(ctx, ecs, slug, desired):
    """A cluster, a task definition and a service with `desired` tasks; cleanups registered.

    Bridge mode on EC2 needs no VPC. No task is ever placed (the cluster has no container
    instances): the subject is the integer the scaling engine computes.
    """
    cluster = ctx.unique_name(f'sim2real-behav-aas-{slug}-cl-')
    service = ctx.unique_name(f'sim2real-behav-aas-{slug}-svc-')
    family = ctx.unique_name(f'sim2real-behav-aas-{slug}-td-')
    pairs = [{'key': 'sim2real', 'value': CHECK}, {'key': 'owner', 'value': 'sim2real-behav-aas'}]

    ecs.create_cluster(clusterName=cluster, tags=pairs)
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    task_def = ecs.register_task_definition(
        family=family, networkMode='bridge', requiresCompatibilities=['EC2'],
        containerDefinitions=[{
            'name': 'sim2real-idle',
            'image': 'public.ecr.aws/docker/library/busybox:1.36',
            'memory': 128, 'essential': True, 'command': ['sh', '-c', 'sleep 3600'],
        }],
        tags=pairs,
    )['taskDefinition']['taskDefinitionArn']
    ctx.on_cleanup(lambda: _deregister_task_definition(ecs, task_def))
    ecs.create_service(cluster=cluster, serviceName=service, taskDefinition=task_def,
                       desiredCount=desired, launchType='EC2', tags=pairs)
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, service))
    return cluster, service, f'service/{cluster}/{service}'


def _desired_count(ecs, cluster, service):
    """ECS's own view of the desiredCount of the service it was told to resize."""
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


def _run_leg(ctx, aas, cw, ecs, account, *, slug, start, adjustment, lower, upper, operator,
            breach_value, bound_kind, leg):
    """One clamp direction, on its OWN independent cluster/service/scalable target/policy/alarm.

    AWS starts no new scaling activity on a resource while a prior one is unresolved, and with no
    container instances an activity here stays InProgress, so legs cannot share a target.
    """
    cluster, service, resource_id = _ecs_estate(ctx, ecs, slug, start)
    initial = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c == start,
        timeout_s=_budget_s(ctx, _ESTATE_S), interval_s=1.0,
        description=f'{leg}: ECS reporting desiredCount {start} for {service!r} before '
                    f'anything scales it', ctx=ctx)
    assert initial == start, (
        f'{leg}: ECS reports desiredCount {initial} for the freshly created service {service!r} '
        f'in region {ctx.region} of account {account}, expected {start}'
    )

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    def _bounds():
        """The bounds as the scalable target reports them now; the expectations derive from this."""
        targets = aas.describe_scalable_targets(
            ServiceNamespace=_NS, ResourceIds=[resource_id],
            ScalableDimension=_DIM)['ScalableTargets']
        assert len(targets) == 1, (
            f'DescribeScalableTargets returned {len(targets)} targets for {resource_id!r}, '
            f'expected exactly 1: {targets!r}'
        )
        return targets[0]['MinCapacity'], targets[0]['MaxCapacity']

    assert _bounds() == (_MIN_CAPACITY, _MAX_CAPACITY), (
        f'{leg}: the registered bounds came back as {_bounds()!r}, expected '
        f'({_MIN_CAPACITY}, {_MAX_CAPACITY})'
    )

    policy_name = ctx.unique_name(f'sim2real-behav-aas-{slug}-pol-')
    step = {'ScalingAdjustment': adjustment}
    if lower is not None:
        step['MetricIntervalLowerBound'] = lower
    if upper is not None:
        step['MetricIntervalUpperBound'] = upper
    put = aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy_name, PolicyType='StepScaling',
        StepScalingPolicyConfiguration={
            'AdjustmentType': 'ChangeInCapacity',
            'MetricAggregationType': 'Maximum',
            'Cooldown': 0,
            'StepAdjustments': [step],
        },
    )
    ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, policy_name))
    stored = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyNames=[policy_name])['ScalingPolicies']
    assert len(stored) == 1, (
        f'DescribeScalingPolicies returned {len(stored)} policies named {policy_name!r}: {stored!r}'
    )
    held = stored[0]['StepScalingPolicyConfiguration']['StepAdjustments'][0]
    assert held['ScalingAdjustment'] == adjustment, (
        f'{leg}: the stored policy {policy_name!r} reports ScalingAdjustment '
        f'{held.get("ScalingAdjustment")!r}, expected {adjustment}; the clamp below cannot be '
        f'attributed to an adjustment the target did not keep'
    )
    policy_arn = put['PolicyARN']

    alarm_name = ctx.unique_name(f'sim2real-behav-aas-{slug}-al-')
    cw.put_metric_alarm(
        AlarmName=alarm_name, AlarmDescription=f'sim2real {CHECK}',
        Namespace=_METRIC_NAMESPACE, MetricName=_METRIC_NAME,
        Dimensions=[{'Name': 'ServiceName', 'Value': service}, {'Name': 'Leg', 'Value': slug}],
        Statistic='Maximum', Period=_ALARM_PERIOD_S, EvaluationPeriods=1, DatapointsToAlarm=1,
        Threshold=_THRESHOLD, ComparisonOperator=operator,
        TreatMissingData='notBreaching', AlarmActions=[policy_arn],
        Tags=[{'Key': 'sim2real', 'Value': CHECK},
              {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    ctx.on_cleanup(lambda: _delete_alarm(cw, alarm_name))
    wired = cw.describe_alarms(AlarmNames=[alarm_name])['MetricAlarms']
    assert len(wired) == 1 and wired[0]['AlarmActions'] == [policy_arn], (
        f'{leg}: the alarm {alarm_name!r} lists alarm actions '
        f'{[a.get("AlarmActions") for a in wired]!r}; it must point at exactly {policy_arn!r}'
    )

    def _publish(value):
        cw.put_metric_data(
            Namespace=_METRIC_NAMESPACE,
            MetricData=[{
                'MetricName': _METRIC_NAME,
                'Dimensions': [{'Name': 'ServiceName', 'Value': service},
                                {'Name': 'Leg', 'Value': slug}],
                'Timestamp': datetime.datetime.now(datetime.timezone.utc),
                'Value': value, 'Unit': 'None', 'StorageResolution': 1,
            }],
        )

    known_ids = {a['ActivityId'] for a in _activities(aas, resource_id)}

    transition_s = _budget_s(ctx, _TRANSITION_S)
    deadline = time.monotonic() + transition_s
    last = None
    while time.monotonic() < deadline:
        _publish(breach_value)
        last = _alarm_state(cw, alarm_name)
        if last == 'ALARM':
            break
        time.sleep(2.0)
    else:
        if _budget_spent(ctx):
            raise TimeoutError(f'{leg}: alarm {alarm_name!r} reaching ALARM: the run budget '
                               'ended first; not graded')
        raise AssertionError(
            f'{leg}: alarm {alarm_name!r} never reached ALARM within {transition_s:.0f}s of '
            f'publishing {breach_value} against a threshold of {_THRESHOLD}; last saw {last!r}')

    current_bounds = _bounds()
    bound = current_bounds[1] if bound_kind == 'MaxCapacity' else current_bounds[0]

    try:
        after = _poll_until(
            lambda: _desired_count(ecs, cluster, service), lambda c: c != start,
            timeout_s=_budget_s(ctx, _APPLY_S), interval_s=1.0,
            description=f'{leg}: ECS desiredCount for {service!r} moving off {start} after '
                        f'a ChangeInCapacity {adjustment:+d} that overshoots the {bound_kind} of '
                        f'{bound}', ctx=ctx)
    except AssertionError as exc:
        dump = [{k: a.get(k) for k in
                 ("ActivityId", "StatusCode", "Description", "StatusMessage", "NotScaledReasons")}
                for a in _activities(aas, resource_id)]
        raise AssertionError(f'{exc} -- DEBUG all activities: {dump!r}') from None

    assert after == bound, (
        f'{leg}: ECS reports desiredCount {after} for {service!r}. ChangeInCapacity '
        f'{adjustment:+d} from {start} recommends {start + adjustment}, which is '
        f'past the {bound_kind} the target itself reports ({bound}), so the activity must land on '
        f'exactly {bound}. An implementation that clamps nothing answers '
        f'{start + adjustment}'
    )
    if bound_kind == 'MinCapacity':
        assert after > 0, (
            f'{leg}: ECS reports desiredCount {after}; clamping a large scale-in against 0 rather '
            f'than against MinCapacity {bound} takes the service down'
        )

    def _new_candidate():
        for activity in _activities(aas, resource_id):
            if (activity['ActivityId'] not in known_ids
                    and activity.get('Description') == f'Setting desired count to {after}.'
                    and activity['StatusCode'] not in ('Pending', 'PendingBeforeAlarmThreshold',
                                                       'PendingBeforeCooldownAfterInternal',
                                                       'PendingSchedule')):
                return activity
        return None

    newest = _poll_until(
        _new_candidate, lambda a: a is not None, timeout_s=_budget_s(ctx, _CANDIDATE_S),
        interval_s=1.0,
        description=f'{leg}: a new, past-its-initial-pending-state scaling activity describing '
                    f'"Setting desired count to {after}."', ctx=ctx)
    assert newest['StatusCode'] in ('Successful', 'InProgress'), (
        f'{leg}: the clamped activity reports StatusCode {newest["StatusCode"]!r}. Measured on '
        f'real AWS with no ECS container instances to fulfil the change, this activity stays '
        f'"InProgress" (never reaching "Successful") without ever becoming a not-scaled or failed '
        f'outcome -- {newest["StatusCode"]!r} is neither'
    )
    assert f'{after}' in newest.get('StatusMessage', ''), (
        f'{leg}: the activity status message was {newest.get("StatusMessage")!r}, which does not '
        f'name the clamped count {after}'
    )
    assert not newest.get('NotScaledReasons'), (
        f'{leg}: the clamped activity carries NotScaledReasons '
        f'{newest.get("NotScaledReasons")!r}; the documented reason codes attach to activities '
        f'that did NOT scale, and this one moved capacity to {after}'
    )
    print(f'[MEASURE] {leg} clamped activity, IncludeNotScaledActivities=True: '
          f'{ {k: newest.get(k) for k in ("StatusCode", "Description", "StatusMessage", "NotScaledReasons")} !r}')
    return after


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics', 'plane:control', "timing:real-time")
def run(ctx) -> None:
    """A step scaling adjustment that would overshoot the registered bounds is clamped to the bound
    and still performed, in both directions: ECS desiredCount lands exactly on Max/MinCapacity and
    the activity names the clamped count with no NotScaledReasons.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-step-scaling-policies.html
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    account = ctx.client('sts').get_caller_identity()['Account']

    assert _START_COUNT + _OUT_ADJ > _MAX_CAPACITY and _MAX_CAPACITY + _IN_ADJ < _MIN_CAPACITY, (
        f'this check is misconfigured: from a start of {_START_COUNT}, {_OUT_ADJ:+d} must '
        f'overshoot MaxCapacity {_MAX_CAPACITY}; from a start of {_MAX_CAPACITY}, {_IN_ADJ:+d} '
        f'must overshoot MinCapacity {_MIN_CAPACITY}; or there is no clamp to observe'
    )

    # Each leg starts at the opposite bound: starting at the bound it clamps into makes AWS report
    # NotScaledReasons=[AlreadyAtMinCapacity] instead of scaling. The legs share no resource, so
    # they run concurrently.
    with ThreadPoolExecutor(max_workers=2) as pool:
        legs = [
            pool.submit(lambda: _run_leg(
                ctx, aas, cw, ecs, account, slug='clampout', start=_START_COUNT,
                adjustment=_OUT_ADJ, lower=0.0, upper=None, operator='GreaterThanThreshold',
                breach_value=_THRESHOLD + 5.0, bound_kind='MaxCapacity', leg='leg out')),
            pool.submit(lambda: _run_leg(
                ctx, aas, cw, ecs, account, slug='clampin', start=_MAX_CAPACITY,
                adjustment=_IN_ADJ, lower=None, upper=0.0, operator='LessThanThreshold',
                breach_value=_THRESHOLD - 5.0, bound_kind='MinCapacity', leg='leg in')),
        ]
        for future in legs:
            future.result()


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
