"""two-policies-triggered-together-scale-by-the-largest-not-the-sum."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# The service runs on a cluster with no container instances, so its scaling activities never reach
# steady state: the check names the winning policy and cross-checks the activity log against ECS's
# desiredCount rather than deriving the count from before + adjustment.

CHECK = "two-policies-triggered-together-scale-by-the-largest-not-the-sum"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'ecs']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'ArbitrationDriver'

_THRESHOLD = 50.0
_START_COUNT = 5
_MIN_CAPACITY = 1
_MAX_CAPACITY = 60
_SMALL_OUT = 2
_BIG_OUT = 9
_SMALL_IN = -3
_BIG_IN = -9

_QUIET_OUT = _THRESHOLD - 20.0
_QUIET_IN = _THRESHOLD + 20.0
_ALARM_PERIOD_S = 10
_TRANSITION_S = 90.0
_APPLY_S = 45.0
_SIMULTANEITY_S = 60.0
_SETTLE_S = 45.0

#: Worst-case wall clock: ~55s estate, policies and alarms, 90s initial poll, 90s _TRANSITION_S,
#: 45s _APPLY_S and the 45s _SETTLE_S window, with headroom.
_WORST_CASE_BUDGET_S = 450.0

#: (slug, ScalingAdjustment, MetricIntervalLowerBound, MetricIntervalUpperBound, ComparisonOperator)
_ARMS = (
    ('smallout', _SMALL_OUT, 0.0, None, 'GreaterThanThreshold'),
    ('bigout', _BIG_OUT, 0.0, None, 'GreaterThanThreshold'),
    ('smallin', _SMALL_IN, None, 0.0, 'LessThanThreshold'),
    ('bigin', _BIG_IN, None, 0.0, 'LessThanThreshold'),
)
_ADJUSTMENTS = {slug: adjustment for slug, adjustment, *_ in _ARMS}


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
    """DeleteCluster fails while any service is still draining; retry, then say so out loud."""
    for _ in range(8):
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ClusterNotFoundException':
                return
            if code != 'ClusterContainsServicesException':
                raise RuntimeError(f'cluster {cluster!r} not deleted: {code}') from exc
            time.sleep(6)
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

    networkMode bridge with requiresCompatibilities EC2 needs no networkConfiguration, so no VPC
    and no ambient default VPC is assumed. No task is ever placed -- the cluster has no
    container instances -- because the subject is the integer the scaling engine computes.
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


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics', 'plane:control', 'timing:real-time')
def run(ctx) -> None:
    """Two scale-out step policies triggered together are arbitrated: only the one giving the
    largest capacity leaves a scaling activity, the other leaves none, and desiredCount settles once
    and matches the winner's activity, never the sum or the loser's result."""
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    account = ctx.client('sts').get_caller_identity()['Account']

    assert _BIG_OUT > _SMALL_OUT > 0 > _SMALL_IN > _BIG_IN, (
        f'this check is misconfigured: the four adjustments '
        f'({_SMALL_OUT}, {_BIG_OUT}, {_SMALL_IN}, {_BIG_IN}) must bracket zero with the "big" pair '
        f'strictly further from it, or the arbitration has nothing to choose between'
    )

    cluster, service, resource_id = _ecs_estate(ctx, ecs, 'arb', _START_COUNT)
    initial = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c == _START_COUNT,
        timeout_s=90, interval_s=3.0,
        description=f'ECS reporting desiredCount {_START_COUNT} for {service!r} before anything '
                    f'scales it')
    assert initial == _START_COUNT, (
        f'ECS reports desiredCount {initial} for the freshly created service {service!r} in region '
        f'{ctx.region} of account {account}, expected {_START_COUNT}'
    )

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    alarms = {}
    policies = {}
    for slug, adjustment, lower, upper, operator in _ARMS:
        policy = ctx.unique_name(f'sim2real-behav-aas-{slug}pol-')
        step = {'ScalingAdjustment': adjustment}
        if lower is not None:
            step['MetricIntervalLowerBound'] = lower
        if upper is not None:
            step['MetricIntervalUpperBound'] = upper
        put = aas.put_scaling_policy(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyName=policy, PolicyType='StepScaling',
            StepScalingPolicyConfiguration={
                'AdjustmentType': 'ChangeInCapacity', 'MetricAggregationType': 'Maximum',
                # 0 everywhere: cooldown must not be what suppresses the second policy, or this
                # check would be measuring cooldown instead of arbitration.
                'Cooldown': 0, 'StepAdjustments': [step],
            },
        )
        ctx.on_cleanup(lambda n=policy: _delete_policy(aas, resource_id, n))
        alarm = ctx.unique_name(f'sim2real-behav-aas-{slug}al-')
        cw.put_metric_alarm(
            AlarmName=alarm, AlarmDescription=f'sim2real {CHECK} {slug}',
            Namespace=_METRIC_NAMESPACE, MetricName=_METRIC_NAME,
            Dimensions=[{'Name': 'ServiceName', 'Value': service},
                        {'Name': 'Arm', 'Value': slug}],
            Statistic='Maximum', Period=_ALARM_PERIOD_S, EvaluationPeriods=1, DatapointsToAlarm=1,
            Threshold=_THRESHOLD, ComparisonOperator=operator,
            TreatMissingData='notBreaching', AlarmActions=[put['PolicyARN']],
            Tags=[{'Key': 'sim2real', 'Value': CHECK},
                  {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
        )
        ctx.on_cleanup(lambda n=alarm: _delete_alarm(cw, n))
        wired = cw.describe_alarms(AlarmNames=[alarm])['MetricAlarms']
        assert len(wired) == 1 and wired[0]['AlarmActions'] == [put['PolicyARN']], (
            f'the {slug} alarm {alarm!r} lists alarm actions '
            f'{[a.get("AlarmActions") for a in wired]!r}; it must point at exactly '
            f'{put["PolicyARN"]!r}'
        )
        alarms[slug] = alarm
        policies[slug] = policy

    stored = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM)['ScalingPolicies']
    assert len(stored) == len(_ARMS), (
        f'DescribeScalingPolicies reports {len(stored)} policies on {resource_id!r}, expected '
        f'{len(_ARMS)}; the arbitration this check probes needs all four to exist at once, and if '
        f'the target refuses more than one policy per dimension THAT is the finding'
    )

    def _publish(values):
        now = datetime.datetime.now(datetime.timezone.utc)
        cw.put_metric_data(
            Namespace=_METRIC_NAMESPACE,
            MetricData=[
                {'MetricName': _METRIC_NAME,
                 'Dimensions': [{'Name': 'ServiceName', 'Value': service},
                                {'Name': 'Arm', 'Value': slug}],
                 'Timestamp': now, 'Value': value, 'Unit': 'None', 'StorageResolution': 1}
                for slug, value in values.items()
            ],
        )

    def _drive(want, values, *, leg):
        """Hold all four streams until the four alarms report `want`. Bounded; raises."""
        deadline = time.monotonic() + _TRANSITION_S
        last = None
        while time.monotonic() < deadline:
            _publish(values)
            last = {slug: _alarm_state(cw, name) for slug, name in alarms.items()}
            if last == want:
                return
            time.sleep(5.0)
        raise AssertionError(
            f'{leg}: alarm states never reached {want!r} within {_TRANSITION_S}s of publishing '
            f'{values!r} against a threshold of {_THRESHOLD}; last saw {last!r}')

    def _assert_simultaneous(pair, *, leg):
        described = cw.describe_alarms(
            AlarmNames=[alarms[slug] for slug in pair])['MetricAlarms']
        assert len(described) == 2, (
            f'{leg}: DescribeAlarms returned {len(described)} of the two alarms '
            f'{[alarms[s] for s in pair]!r}'
        )
        stamps = {a['AlarmName']: a['StateUpdatedTimestamp'] for a in described}
        spread = abs((max(stamps.values()) - min(stamps.values())).total_seconds())
        assert spread <= _SIMULTANEITY_S, (
            f'{leg}: the two alarms transitioned {spread:.1f}s apart '
            f'({ {k: v.isoformat() for k, v in stamps.items()} !r}), more than the '
            f'{_SIMULTANEITY_S}s this check treats as "at the same time". The arbitration claim is '
            f'only about simultaneous triggers, so this leg cannot be interpreted -- raise '
            f'_SIMULTANEITY_S after measuring what real AWS actually does, and do not read the '
            f'capacity below as an arbitration verdict'
        )
        return stamps

    def _arbitrate(before, loser_slug, winner_slug, *, leg, direction):
        loser = _ADJUSTMENTS[loser_slug]
        winner = _ADJUSTMENTS[winner_slug]
        rival_sum = before + loser + winner
        rival_loser_wins = before + loser
        loser_policy = policies[loser_slug]
        winner_policy = policies[winner_slug]
        try:
            after = _poll_until(
                lambda: _desired_count(ecs, cluster, service), lambda c: c != before,
                timeout_s=_APPLY_S, interval_s=3.0,
                description=f'{leg}: ECS desiredCount for {service!r} moving off {before} after two '
                            f'{direction} policies ({loser:+d} and {winner:+d}) were triggered together')
        except AssertionError:
            print(f'[DEBUG-TIMEOUT] {leg}: no movement off {before}; activities='
                  f'{[(a.get("StatusCode"), a.get("Description"), a.get("Cause")) for a in _activities(aas, resource_id)]!r}')
            raise
        # A sequential second adjustment would land within 3+ alarm periods of the first.
        left = ctx.time_left()
        if left is not None and left < _SETTLE_S:
            raise TimeoutError(f'{leg}: the run budget ends before the {_SETTLE_S:.0f}s settle window')
        settle = [after]
        settle_end = time.monotonic() + _SETTLE_S
        while time.monotonic() < settle_end:
            time.sleep(2)
            settle.append(_desired_count(ecs, cluster, service))
        activities = _activities(aas, resource_id)
        print(f'[DEBUG] {leg}: before={before} loser={loser:+d} winner={winner:+d} '
              f'settle={settle!r} activities='
              f'{[(a.get("StatusCode"), a.get("Description"), a.get("Cause")) for a in activities]!r}')
        assert len(set(settle)) == 1, (
            f'{leg}: ECS desiredCount for {service!r} moved through {settle!r} over the '
            f'{_SETTLE_S:.0f}s after the arbitration. Two triggers must '
            f'produce ONE outcome; a second adjustment arriving during this window is the '
            f'apply-both implementation caught in the act'
        )

        # The count is cross-checked between AAS's activity log and ECS's own read, not derived from
        # before + winner: the loser must leave no activity and the winner's must match ECS.
        attributable_to_loser = [a for a in activities if loser_policy in (a.get('Cause') or '')]
        assert not attributable_to_loser, (
            f'{leg}: DescribeScalingActivities recorded {len(attributable_to_loser)} activity(ies) '
            f'attributable to the LOSING policy {loser_policy!r} ({loser:+d}) even though the '
            f'policy providing the largest resulting capacity must fully suppress the other: '
            f'{attributable_to_loser!r}'
        )
        attributable_to_winner = [a for a in activities if winner_policy in (a.get('Cause') or '')]
        assert attributable_to_winner, (
            f'{leg}: no activity in DescribeScalingActivities is attributable to the WINNING '
            f'policy {winner_policy!r} ({winner:+d}); something else must have moved desiredCount '
            f'to {settle[-1]}'
        )
        successful = [a for a in activities if a.get('StatusCode') == 'Successful']
        assert successful, (
            f'{leg}: DescribeScalingActivities has no successful activity even though desiredCount '
            f'moved to {settle[-1]}'
        )
        # One arbitration records several activities with mixed status codes; the count-naming
        # entry is found by its Description, whatever its position or status.
        matching = [a for a in activities
                    if a.get('Description') == f'Setting desired count to {settle[-1]}.']
        assert matching, (
            f'{leg}: no activity in DescribeScalingActivities describes itself as "Setting desired '
            f'count to {settle[-1]}." even though ECS independently reports desiredCount {settle[-1]} '
            f'for {service!r}; AAS\'s own ledger must agree with ECS\'s independent read: '
            f'{activities!r}'
        )
        assert settle[-1] != rival_sum, (
            f'{leg}: desiredCount is {settle[-1]}, which equals before({before}) + loser({loser:+d}) '
            f'+ winner({winner:+d}) = {rival_sum} -- an apply-both implementation, not arbitration'
        )
        assert settle[-1] != rival_loser_wins, (
            f"{leg}: desiredCount is {settle[-1]}, which equals before({before}) + loser({loser:+d}) "
            f'= {rival_loser_wins} -- the LOSING policy was applied instead of the one providing the '
            f'largest resulting capacity'
        )
        print(f'[MEASURE] {leg} activities after arbitrating {loser:+d} against {winner:+d}: '
              f'{[(a.get("StatusCode"), a.get("Description")) for a in activities]!r}')
        return settle[-1]

    # ---- Two SCALE-OUT policies together. Largest capacity == the bigger adjustment.
    _drive({'smallout': 'ALARM', 'bigout': 'ALARM', 'smallin': 'OK', 'bigin': 'OK'},
           {'smallout': _THRESHOLD + 5.0, 'bigout': _THRESHOLD + 5.0,
            'smallin': _QUIET_IN, 'bigin': _QUIET_IN}, leg='leg 1')
    _assert_simultaneous(('smallout', 'bigout'), leg='leg 1')
    after_1 = _arbitrate(_START_COUNT, 'smallout', 'bigout', leg='leg 1', direction='scale-out')
    assert _START_COUNT < after_1 < _MAX_CAPACITY, (
        f'this check ended at desiredCount {after_1}, on or outside the registered bounds '
        f'({_MIN_CAPACITY}, {_MAX_CAPACITY}) or not above the starting count {_START_COUNT}; no '
        f'rival answer may be clamped into agreement with the right one'
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
