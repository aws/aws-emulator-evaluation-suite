"""step-scaling-exact-bound-picks-the-step-farther-from-the-threshold-on-both-sides."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Each leg has its own ECS service, scalable target, policy and alarm, so each breach is the first
# and only scaling activity on its target and no leg waits out another leg's cooldown.

CHECK = "step-scaling-exact-bound-picks-the-step-farther-from-the-threshold-on-both-sides"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'cloudwatch', 'ecs', 'iam']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'BoundaryDriver'

_THRESHOLD = 50.0
_BOUND = 10.0
_MIN_CAPACITY = 1
_MAX_CAPACITY = 20
_OUT_NEAR = 2       # ChangeInCapacity for the [0, _BOUND) step
_OUT_FAR = 7        # ChangeInCapacity for the [_BOUND, null) step
_IN_NEAR = -1       # ChangeInCapacity for the (-_BOUND, 0] step
_IN_FAR = -3        # ChangeInCapacity for the (null, -_BOUND] step
_OUT_START = 2
_IN_START = 5

_ALARM_PERIOD_S = 10
_TRANSITION_S = 90.0
_APPLY_S = 90.0
#: Fargate tasks pull and start before runningCount reaches desiredCount.
_RUNNING_S = 180.0
#: Longer than the rest of the run, so a re-invocation while an alarm stays in ALARM adds nothing
#: (scale-out) or is blocked (scale-in); no leg waits it out.
_COOLDOWN_S = 300

#: (leg, alarm operator, starting count, metric value, expected adjustment, its interval,
#: the adjustment an inverted bound inclusivity selects instead)
_LEGS = (
    ('out-on-bound', 'GreaterThanThreshold', _OUT_START, _THRESHOLD + _BOUND, _OUT_FAR,
     f'[{_BOUND}, null)', _OUT_NEAR),
    ('out-below-bound', 'GreaterThanThreshold', _OUT_START, _THRESHOLD + _BOUND - 1.0, _OUT_NEAR,
     f'[0, {_BOUND})', _OUT_FAR),
    ('in-on-bound', 'LessThanThreshold', _IN_START, _THRESHOLD - _BOUND, _IN_FAR,
     f'(null, {-_BOUND}]', _IN_NEAR),
    ('in-above-bound', 'LessThanThreshold', _IN_START, _THRESHOLD - _BOUND + 1.0, _IN_NEAR,
     f'({-_BOUND}, 0]', _IN_FAR),
)


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=3.0, description='condition'):
    """Bounded retry with a deadline (capped by the run budget) that RAISES on timeout."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
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


def _ecs_estate(ctx, iam, ecs, slug, counts):
    """A Fargate cluster with one service per entry of `counts`, each at that many running tasks.

    Application Auto Scaling adjusts ecs:service:DesiredCount from the running tasks, so they must
    actually run: Fargate, in the run's shared network, gives them placement capacity."""
    net = ctx.network()
    role_arn = _execution_role(ctx, iam)
    cluster = ctx.unique_name(f'sim2real-behav-aas-{slug}-cl-')
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
            # PID 1 has no SIGTERM handler, so a stop waits out stopTimeout before SIGKILL.
            'stopTimeout': 2,
        }],
        tags=pairs,
    )['taskDefinition']['taskDefinitionArn']
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def))
    services = []
    for desired in counts:
        service = ctx.unique_name(f'sim2real-behav-aas-{slug}-svc-')
        ecs.create_service(
            cluster=cluster, serviceName=service, taskDefinition=task_def, desiredCount=desired,
            launchType='FARGATE',
            networkConfiguration={'awsvpcConfiguration': {
                'subnets': list(net.subnet_ids), 'securityGroups': [net.security_group_id],
                'assignPublicIp': 'ENABLED'}},
            tags=pairs)
        ctx.on_cleanup(lambda s=service: _delete_service(ecs, cluster, s))
        services.append(service)
    for service, desired in zip(services, counts):
        _poll_until(ctx, lambda s=service: _service_counts(ecs, cluster, s),
                    lambda c, d=desired: c == (d, d), timeout_s=_RUNNING_S, interval_s=5.0,
                    description=f'ECS reporting desiredCount and runningCount {desired} for '
                                f'{service!r}')
    return cluster, services


def _service_counts(ecs, cluster, service):
    described = ecs.describe_services(cluster=cluster, services=[service])['services']
    assert len(described) == 1, (
        f'DescribeServices returned {len(described)} services for {service!r}: {described!r}')
    return described[0]['desiredCount'], described[0]['runningCount']


def _desired_count(ecs, cluster, service):
    """ECS's own view of the service Application Auto Scaling resizes."""
    return _service_counts(ecs, cluster, service)[0]


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


# timing:real-time — metric: 10 s
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics', 'plane:control',
      'timing:real-time')
def run(ctx) -> None:
    """A step policy selects the step whose interval contains the metric; above the threshold the
    lower bound is inclusive, below it the upper bound is, so a metric exactly on a bound takes the
    step farther from the threshold on both sides, and the neighbouring value the nearer step.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    iam = ctx.client('iam')

    cluster, services = _ecs_estate(ctx, iam, ecs, 'xbound', [leg[2] for leg in _LEGS])

    legs = []
    for (leg, operator, start, metric, adjustment, interval, rival), service in zip(_LEGS, services):
        resource_id = f'service/{cluster}/{service}'
        aas.register_scalable_target(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
            Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'})
        ctx.on_cleanup(lambda r=resource_id: _deregister(aas, r))
        if operator == 'GreaterThanThreshold':
            steps = [
                {'MetricIntervalLowerBound': 0.0, 'MetricIntervalUpperBound': _BOUND,
                 'ScalingAdjustment': _OUT_NEAR},
                {'MetricIntervalLowerBound': _BOUND, 'ScalingAdjustment': _OUT_FAR},
            ]
        else:
            steps = [
                {'MetricIntervalLowerBound': -_BOUND, 'MetricIntervalUpperBound': 0.0,
                 'ScalingAdjustment': _IN_NEAR},
                {'MetricIntervalUpperBound': -_BOUND, 'ScalingAdjustment': _IN_FAR},
            ]
        policy = ctx.unique_name('sim2real-behav-aas-xboundpol-')
        put = aas.put_scaling_policy(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyName=policy, PolicyType='StepScaling',
            StepScalingPolicyConfiguration={
                'AdjustmentType': 'ChangeInCapacity', 'MetricAggregationType': 'Maximum',
                'Cooldown': _COOLDOWN_S, 'StepAdjustments': steps,
            },
        )
        ctx.on_cleanup(lambda r=resource_id, p=policy: _delete_policy(aas, r, p))
        assert put.get('Alarms', []) == [], (
            f'{leg}: PutScalingPolicy for the StepScaling policy {policy!r} returned alarms '
            f'{put.get("Alarms")!r}; step scaling takes the caller\'s alarm and creates none')
        stored = aas.describe_scaling_policies(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyNames=[policy])['ScalingPolicies']
        assert len(stored) == 1, f'{leg}: DescribeScalingPolicies returned {stored!r}'
        held = stored[0]['StepScalingPolicyConfiguration']['StepAdjustments']
        assert sorted(held, key=lambda s: s['ScalingAdjustment']) == sorted(
            steps, key=lambda s: s['ScalingAdjustment']), (
            f'{leg}: the stored policy reports step adjustments {held!r}, expected {steps!r}')

        alarm = ctx.unique_name('sim2real-behav-aas-xboundal-')
        cw.put_metric_alarm(
            AlarmName=alarm, AlarmDescription=f'sim2real {CHECK} {leg}',
            Namespace=_METRIC_NAMESPACE, MetricName=_METRIC_NAME,
            Dimensions=[{'Name': 'ServiceName', 'Value': service}, {'Name': 'Leg', 'Value': leg}],
            Statistic='Maximum', Period=_ALARM_PERIOD_S, EvaluationPeriods=1, DatapointsToAlarm=1,
            Threshold=_THRESHOLD, ComparisonOperator=operator, TreatMissingData='notBreaching',
            AlarmActions=[put['PolicyARN']],
            Tags=[{'Key': 'sim2real', 'Value': CHECK},
                  {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
        )
        ctx.on_cleanup(lambda n=alarm: _delete_alarm(cw, n))
        wired = cw.describe_alarms(AlarmNames=[alarm])['MetricAlarms']
        assert len(wired) == 1 and wired[0]['AlarmActions'] == [put['PolicyARN']], (
            f'{leg}: the alarm {alarm!r} lists alarm actions '
            f'{[a.get("AlarmActions") for a in wired]!r}; it must point at exactly '
            f'{put["PolicyARN"]!r}')
        assert (wired[0]['Threshold'], wired[0]['Period']) == (_THRESHOLD, _ALARM_PERIOD_S), (
            f'{leg}: the alarm {alarm!r} reports threshold {wired[0].get("Threshold")!r} and '
            f'period {wired[0].get("Period")!r}, expected {_THRESHOLD} and {_ALARM_PERIOD_S}')
        legs.append({'leg': leg, 'service': service, 'resource_id': resource_id, 'alarm': alarm,
                     'start': start, 'metric': metric, 'adjustment': adjustment,
                     'interval': interval, 'rival': rival})

    # ---- Every leg's metric is published until every alarm reports ALARM; a stream left
    # unpublished returns its alarm to OK (notBreaching) before the others catch up.
    deadline = time.monotonic() + min(_TRANSITION_S, ctx.time_left() or _TRANSITION_S)
    states = {}
    while time.monotonic() < deadline:
        now = datetime.datetime.now(datetime.timezone.utc)
        cw.put_metric_data(
            Namespace=_METRIC_NAMESPACE,
            MetricData=[
                {'MetricName': _METRIC_NAME,
                 'Dimensions': [{'Name': 'ServiceName', 'Value': entry['service']},
                                {'Name': 'Leg', 'Value': entry['leg']}],
                 'Timestamp': now, 'Value': entry['metric'], 'Unit': 'None',
                 'StorageResolution': 1}
                for entry in legs
            ],
        )
        states = {entry['leg']: _alarm_state(cw, entry['alarm']) for entry in legs}
        if set(states.values()) == {'ALARM'}:
            break
        time.sleep(3.0)
    assert set(states.values()) == {'ALARM'}, (
        f'the alarms never all reached ALARM within {_TRANSITION_S}s of publishing '
        f'{[(e["leg"], e["metric"]) for e in legs]!r} against a threshold of {_THRESHOLD}; last '
        f'saw {states!r}')

    # ---- Each target moves by the step whose interval holds its metric.
    for entry in legs:
        leg, start, adjustment = entry['leg'], entry['start'], entry['adjustment']
        after = _poll_until(
            ctx, lambda e=entry: _desired_count(ecs, cluster, e['service']),
            lambda c, s=start: c != s, timeout_s=_APPLY_S, interval_s=3.0,
            description=f'{leg}: ECS desiredCount for {entry["service"]!r} moving off {start} after '
                        f'a metric of {entry["metric"]} selected the {entry["interval"]} step')
        assert after == start + adjustment, (
            f'{leg}: ECS reports desiredCount {after}. The metric was {entry["metric"]} against the '
            f'threshold {_THRESHOLD}, so the {entry["interval"]} step applies and ChangeInCapacity '
            f'{adjustment} takes {start} to {start + adjustment}; an inverted bound inclusivity '
            f'selects the neighbouring step and answers {start + entry["rival"]}')
        scaled = [a for a in _activities(aas, entry['resource_id']) if not a.get('NotScaledReasons')]
        assert scaled and {a['Description'] for a in scaled} == {
            f'Setting desired count to {after}.'}, (
            f'{leg}: the target reports scaling activities {[a["Description"] for a in scaled]!r}, '
            f'expected only "Setting desired count to {after}."')
        assert _MIN_CAPACITY < after < _MAX_CAPACITY, (
            f'{leg}: desiredCount {after} is on or outside the registered bounds '
            f'({_MIN_CAPACITY}, {_MAX_CAPACITY}), so a clamp could explain it')


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
