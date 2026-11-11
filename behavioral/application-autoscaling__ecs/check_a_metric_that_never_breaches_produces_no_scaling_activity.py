"""a-metric-that-never-breaches-produces-no-scaling-activity."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Both targets are ECS services on clusters with no container instances. On such a service a
# negative step adjustment executes and a positive one does not, so the control scales in.

CHECK = "a-metric-that-never-breaches-produces-no-scaling-activity"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'ecs']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'NonBreachDriver'

_START_COUNT = 6
_MIN_CAPACITY = 1
_MAX_CAPACITY = 40
#: Scale in: on this zero-container-instance estate only a negative adjustment executes.
_IN_ADJ = -3
#: The single value published to BOTH targets' streams, unchanged for the whole check. The only
#: difference between the subject and the control is which side of its own threshold this sits on.
_DRIVE_VALUE = 50.0
#: LessThanThreshold alarms: the control's threshold sits ABOVE the drive value (breaches), the
#: subject's sits BELOW it (never breaches).
_CONTROL_THRESHOLD = 90.0
_SUBJECT_THRESHOLD = 10.0

_ALARM_PERIOD_S = 10
_CONTROL_S = 120.0
_MIN_HOLD_S = 90.0
_HOLD_MULTIPLIER = 3.0
_MAX_HOLD_S = 180.0
_REPAIR_S = 120.0
_PUBLISH_INTERVAL_S = 5.0


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
        code = exc.response.get('Error', {}).get('Code')
        if code not in ('ServiceNotFoundException', 'ServiceNotActiveException'):
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


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags('axis:negative-delivery', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics',
      'plane:control', 'timing:real-time')
def run(ctx) -> None:
    """A metric that never crosses its alarm threshold produces no scaling activity, successful or
    not-scaled, while an identically wired twin whose threshold the same metric value does cross
    scales in at the same time; raising the subject's threshold then scales it in too."""
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    account = ctx.client('sts').get_caller_identity()['Account']

    assert _SUBJECT_THRESHOLD < _DRIVE_VALUE < _CONTROL_THRESHOLD, (
        f'this check is misconfigured: with LessThanThreshold alarms, the single published value '
        f'{_DRIVE_VALUE} must sit strictly below the control threshold {_CONTROL_THRESHOLD} (so it '
        f'breaches) and strictly above the subject threshold {_SUBJECT_THRESHOLD} (so it never does), '
        f'or the two arms are not doing the same work'
    )

    estates = {}
    for role, slug, threshold in (('control', 'nbctl', _CONTROL_THRESHOLD),
                                  ('subject', 'nbsub', _SUBJECT_THRESHOLD)):
        cluster, service, resource_id = _ecs_estate(ctx, ecs, slug, _START_COUNT)
        estates[role] = {'cluster': cluster, 'service': service, 'resource_id': resource_id,
                         'threshold': threshold}
    for role, estate in estates.items():
        count = _poll_until(
            lambda e=estate: _desired_count(ecs, e['cluster'], e['service']),
            lambda c: c == _START_COUNT, timeout_s=90, interval_s=3.0,
            description=f'ECS reporting desiredCount {_START_COUNT} for the {role} service '
                        f'{estate["service"]!r} before anything scales it')
        assert count == _START_COUNT, (
            f'ECS reports desiredCount {count} for the {role} service {estate["service"]!r} in '
            f'region {ctx.region} of account {account}, expected {_START_COUNT}'
        )

    for role, estate in estates.items():
        aas.register_scalable_target(
            ServiceNamespace=_NS, ResourceId=estate['resource_id'], ScalableDimension=_DIM,
            MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
            Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas', 'role': role},
        )
        ctx.on_cleanup(lambda e=estate: _deregister(aas, e['resource_id']))
        assert _activities(aas, estate['resource_id']) == [], (
            f'the {role} target {estate["resource_id"]!r} has a non-empty activity history before '
            f'this check published anything: '
            f'{_activities(aas, estate["resource_id"])!r}'
        )

        policy = ctx.unique_name(f'sim2real-behav-aas-{role[:3]}nbpol-')
        put = aas.put_scaling_policy(
            ServiceNamespace=_NS, ResourceId=estate['resource_id'], ScalableDimension=_DIM,
            PolicyName=policy, PolicyType='StepScaling',
            StepScalingPolicyConfiguration={
                'AdjustmentType': 'ChangeInCapacity', 'MetricAggregationType': 'Maximum',
                'Cooldown': 0,
                'StepAdjustments': [
                    {'MetricIntervalUpperBound': 0.0, 'ScalingAdjustment': _IN_ADJ},
                ],
            },
        )
        ctx.on_cleanup(lambda e=estate, n=policy: _delete_policy(aas, e['resource_id'], n))
        estate['policy_arn'] = put['PolicyARN']
        estate['policy_name'] = policy

        alarm = ctx.unique_name(f'sim2real-behav-aas-{role[:3]}nbal-')
        estate['alarm'] = alarm

    def _put_alarm(estate, threshold):
        cw.put_metric_alarm(
            AlarmName=estate['alarm'], AlarmDescription=f'sim2real {CHECK}',
            Namespace=_METRIC_NAMESPACE, MetricName=_METRIC_NAME,
            Dimensions=[{'Name': 'ServiceName', 'Value': estate['service']}],
            Statistic='Maximum', Period=_ALARM_PERIOD_S, EvaluationPeriods=1, DatapointsToAlarm=1,
            Threshold=threshold, ComparisonOperator='LessThanThreshold',
            TreatMissingData='notBreaching', AlarmActions=[estate['policy_arn']],
            Tags=[{'Key': 'sim2real', 'Value': CHECK},
                  {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
        )
        wired = cw.describe_alarms(AlarmNames=[estate['alarm']])['MetricAlarms']
        assert len(wired) == 1, (
            f'DescribeAlarms returned {len(wired)} alarms named {estate["alarm"]!r}, expected 1'
        )
        assert wired[0]['AlarmActions'] == [estate['policy_arn']], (
            f'the alarm {estate["alarm"]!r} lists alarm actions {wired[0]["AlarmActions"]!r}; it '
            f'must point at exactly {estate["policy_arn"]!r} or this arm reaches nothing'
        )
        assert wired[0]['Threshold'] == threshold, (
            f'the alarm {estate["alarm"]!r} reports threshold {wired[0]["Threshold"]!r}, expected '
            f'{threshold}'
        )
        return wired[0]

    for estate in estates.values():
        _put_alarm(estate, estate['threshold'])
        ctx.on_cleanup(lambda n=estate['alarm']: _delete_alarm(cw, n))

    subject, control = estates['subject'], estates['control']
    control_alarms = cw.describe_alarms(
        AlarmNames=[control['alarm'], subject['alarm']])['MetricAlarms']
    shapes = {a['AlarmName']: (a['Namespace'], a['MetricName'], a['Statistic'], a['Period'],
                               a['EvaluationPeriods'], a['ComparisonOperator'],
                               a['TreatMissingData']) for a in control_alarms}
    assert len(set(shapes.values())) == 1, (
        f'the subject and control alarms differ in more than their thresholds: {shapes!r}. The '
        f'twin control is only a control if the THRESHOLD is the single difference'
    )

    def _publish():
        now = datetime.datetime.now(datetime.timezone.utc)
        cw.put_metric_data(
            Namespace=_METRIC_NAMESPACE,
            MetricData=[
                {'MetricName': _METRIC_NAME,
                 'Dimensions': [{'Name': 'ServiceName', 'Value': estate['service']}],
                 'Timestamp': now, 'Value': _DRIVE_VALUE, 'Unit': 'None', 'StorageResolution': 1}
                for estate in estates.values()
            ],
        )

    # ---- Leg 1: the positive control. The SAME value, published to both streams, crosses the
    # control's threshold. This also MEASURES the delivery latency L that leg 2's window is built on.
    started = time.monotonic()
    deadline = started + _CONTROL_S
    control_after = None
    while time.monotonic() < deadline:
        _publish()
        seen = _desired_count(ecs, control['cluster'], control['service'])
        if seen != _START_COUNT:
            control_after = seen
            break
        time.sleep(_PUBLISH_INTERVAL_S)
    latency_s = time.monotonic() - started
    assert control_after is not None, (
        f'leg 1: the control service {control["service"]!r} never moved off desiredCount '
        f'{_START_COUNT} within {_CONTROL_S}s of publishing {_DRIVE_VALUE} against its threshold of '
        f'{_CONTROL_THRESHOLD}. The positive control is mandatory: without it the absence in leg 2 '
        f'would be satisfied by a target with no scaling engine at all'
    )
    assert _MIN_CAPACITY <= control_after < _START_COUNT, (
        f'leg 1: the control reached desiredCount {control_after}, expected a real decrease from '
        f'{_START_COUNT} bounded below by MinCapacity {_MIN_CAPACITY} -- the exact post-scale count '
        f'is a separate, already-filed finding (Application Auto Scaling computes it from the ECS '
        f"deployment's own lagging desiredCount, not the service's), so this checks only that a "
        f'scale-IN genuinely happened'
    )
    assert _alarm_state(cw, control['alarm']) == 'ALARM', (
        f'leg 1: the control alarm {control["alarm"]!r} is not in ALARM even though its capacity '
        f'moved; the delivery cannot be attributed to this wiring'
    )

    # ---- Leg 2: the absence, held for a window derived from the MEASURED control latency.
    hold_s = min(max(latency_s * _HOLD_MULTIPLIER, _MIN_HOLD_S), _MAX_HOLD_S)
    assert hold_s >= latency_s * _HOLD_MULTIPLIER or hold_s == _MAX_HOLD_S, (
        f'leg 2: the absence window {hold_s}s is shorter than {_HOLD_MULTIPLIER} times the measured '
        f'control latency {latency_s:.1f}s and is not at the {_MAX_HOLD_S}s ceiling; a window '
        f'shorter than the check\'s own positive latency scores a correct but slower target as '
        f'having blocked'
    )
    # The subject alarm may still be on its first, pre-evaluation INSUFFICIENT_DATA read here --
    # leg 1's LessThanThreshold control can breach and fire before the subject has even one
    # completed period of its own. That is a transient every target passes through identically, so
    # wait it out before the strict "must stay OK" window below.
    _poll_until(
        lambda: (_publish(), _alarm_state(cw, subject['alarm']))[1],
        lambda s: s != 'INSUFFICIENT_DATA', timeout_s=60, interval_s=_PUBLISH_INTERVAL_S,
        description=f'the subject alarm {subject["alarm"]!r} leaving INSUFFICIENT_DATA')
    hold_deadline = time.monotonic() + hold_s
    while time.monotonic() < hold_deadline:
        _publish()
        state = _alarm_state(cw, subject['alarm'])
        assert state == 'OK', (
            f'leg 2: the subject alarm {subject["alarm"]!r} reports {state!r} while the published '
            f'value is {_DRIVE_VALUE} against its threshold of {_SUBJECT_THRESHOLD}; a '
            f'LessThanThreshold alarm must stay OK, and if it does not then any absence below is '
            f'CloudWatch\'s doing rather than Application Auto Scaling\'s'
        )
        held = _desired_count(ecs, subject['cluster'], subject['service'])
        assert held == _START_COUNT, (
            f'leg 2: ECS reports desiredCount {held} for the subject service {subject["service"]!r} '
            f'after {hold_s:.0f}s of publishing {_DRIVE_VALUE}, which never crosses its threshold '
            f'of {_SUBJECT_THRESHOLD}. Nothing may scale, so it must still be {_START_COUNT}; the '
            f'control moved to {control_after} on the same value and the same wiring, so the '
            f'delivery path is demonstrably live'
        )
        time.sleep(_PUBLISH_INTERVAL_S)
    subject_history = _activities(aas, subject['resource_id'])
    assert subject_history == [], (
        f'leg 2: DescribeScalingActivities with IncludeNotScaledActivities=True reports '
        f'{len(subject_history)} entries for the subject {subject["resource_id"]!r} whose metric '
        f'never breached: '
        f'{[(a.get("StatusCode"), a.get("Description"), a.get("NotScaledReasons")) for a in subject_history]!r}. '
        f'A never-breaching metric must produce no record at all -- not even a not-scaled one'
    )

    # ---- Leg 3: repair only the withheld thing. Raise the SUBJECT's threshold to the control's, on
    # the same alarm, with the same value still flowing, and demand the scale-in.
    _put_alarm(subject, _CONTROL_THRESHOLD)
    repair_deadline = time.monotonic() + _REPAIR_S
    subject_after = None
    while time.monotonic() < repair_deadline:
        _publish()
        seen = _desired_count(ecs, subject['cluster'], subject['service'])
        if seen != _START_COUNT:
            subject_after = seen
            break
        time.sleep(_PUBLISH_INTERVAL_S)
    assert subject_after is not None, (
        f'leg 3: the subject service {subject["service"]!r} never moved off desiredCount '
        f'{_START_COUNT} within {_REPAIR_S}s of its threshold being raised from '
        f'{_SUBJECT_THRESHOLD} to {_CONTROL_THRESHOLD}, with {_DRIVE_VALUE} still being published. '
        f'The repair proves the subject\'s own wiring was live all along, so without it leg 2 could '
        f'be explained by a broken subject rather than by a non-breaching metric'
    )
    assert _MIN_CAPACITY <= subject_after < _START_COUNT, (
        f'leg 3: the subject reached desiredCount {subject_after}, expected a real decrease from '
        f'{_START_COUNT} bounded below by MinCapacity {_MIN_CAPACITY}, the same shape of adjustment '
        f'the control got in leg 1 (see leg 1 for why the exact count is not pinned)'
    )
    # With no container instances ECS never places the new tasks, so the activity stays
    # InProgress with a fixed StatusMessage; a "Successful" or generic message fails.
    repaired = _poll_until(
        lambda: _activities(aas, subject['resource_id']),
        lambda acts: bool(acts) and acts[0].get('Description'),
        timeout_s=30, interval_s=5.0,
        description=f"the subject's newest scaling activity appearing")
    assert repaired[0]['StatusCode'] == 'InProgress', (
        f'leg 3: the subject\'s newest activity is '
        f'{[(a.get("StatusCode"), a.get("Description")) for a in repaired[:2]]!r}, expected '
        f'InProgress -- this estate has no container instances, so ECS can never finish fulfilling '
        f'the new desiredCount and the activity cannot reach a different terminal state'
    )
    assert repaired[0]['Description'] == f'Setting desired count to {subject_after}.', (
        f'leg 3: the subject\'s newest activity described itself as '
        f'{repaired[0]["Description"]!r}, expected "Setting desired count to {subject_after}."'
    )
    assert repaired[0].get('StatusMessage') == (
        f'Successfully set desired count to {subject_after}. Waiting for change to be fulfilled '
        f'by ecs.'
    ), (
        f'leg 3: the subject\'s newest activity reports StatusMessage '
        f'{repaired[0].get("StatusMessage")!r}, expected the ecs-fulfilment-pending wording for '
        f'desiredCount {subject_after}'
    )
    assert subject['alarm'] in repaired[0].get('Cause', '') and subject['policy_name'] in repaired[
        0].get('Cause', ''), (
        f'leg 3: the subject\'s newest activity Cause {repaired[0].get("Cause")!r} does not name '
        f'both the alarm {subject["alarm"]!r} and the policy {subject["policy_name"]!r} that '
        f'fired; the activity cannot be attributed to this wiring'
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
