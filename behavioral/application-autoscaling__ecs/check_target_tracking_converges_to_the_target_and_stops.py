"""target-tracking-converges-to-the-target-and-stops."""
from __future__ import annotations

import datetime
import math
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# A TargetTrackingScaling policy with a CustomizedMetricSpecification is accepted on
# ecs:service:DesiredCount. The metric is _OFFERED_LOAD / capacity, so the achieved-metric bound is
# the capacity band inverted; one scaling event yields a "Setting desired count to N." record and a
# separate "Attempting to scale" record, so the sizing record is found by its Description.

CHECK = "target-tracking-converges-to-the-target-and-stops"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'ecs']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'ConvergenceUtilisation'

#: Offered load, in the same made-up units the metric reports. The controller's fixed point is
#: _OFFERED_LOAD / _TARGET_VALUE, which must be strictly inside (Min, Max) so that a BOUND is never
#: what stops the controller -- that is a different check.
_OFFERED_LOAD = 400.0
_TARGET_VALUE = 50.0
_START_COUNT = 2
_MIN_CAPACITY = 1
_MAX_CAPACITY = 20

#: The band, as factors on the fixed point. Wide on purpose: the docs promise proportional control
#: and conservative rounding, not an exact landing point.
_BAND_LOW_FACTOR = 0.6
_BAND_HIGH_FACTOR = 1.75

_WARMUP_S = 70.0
_RISE_S = 300.0
_CONVERGE_S = 300.0
_FREEZE_READS = 6
_FREEZE_INTERVAL_S = 20.0
_PUBLISH_INTERVAL_S = 10.0


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
    """Create a cluster, a task definition and a service with `desired` tasks; register cleanup.

    networkMode bridge with requiresCompatibilities EC2 needs no networkConfiguration, so no VPC
    and no ambient default VPC is assumed. No task is ever placed -- the cluster has no
    container instances -- because the subject is the desiredCount integer the scaling engine
    writes, not a running container.
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


class _Publisher:
    """Closes the loop: publishes _OFFERED_LOAD / (capacity ECS reports) until told to stop.

    Deliberately NOT a threading.Thread subclass. A subclass would have to override a method called
    ``run``, and a second definition of that name beside the module-level ``run`` function is
    ambiguous. It drives a plain Thread with a target instead.

    The worker records the first exception it hits instead of swallowing it, and the body asserts
    ``publisher.error is None`` -- a worker that swallowed a broad exception silently would let a broken
    metric stream read as "the controller declined to act".
    """

    def __init__(self, cw, ecs, cluster, service):
        self._cw, self._ecs = cw, ecs
        self._cluster, self._service = cluster, service
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self.error = None
        self.published = 0
        self.last_value = None

    def start(self):
        self._thread.start()

    def stop(self, join_timeout_s=20.0):
        self._stop.set()
        self._thread.join(timeout=join_timeout_s)
        if self._thread.is_alive():
            raise RuntimeError(f'metric publisher thread for {self._service!r} did not stop within '
                               f'{join_timeout_s}s')

    def _loop(self):
        while not self._stop.is_set():
            try:
                capacity = _desired_count(self._ecs, self._cluster, self._service)
                value = _OFFERED_LOAD / float(max(capacity, 1))
                self._cw.put_metric_data(
                    Namespace=_METRIC_NAMESPACE,
                    MetricData=[{
                        'MetricName': _METRIC_NAME,
                        'Dimensions': [{'Name': 'ServiceName', 'Value': self._service}],
                        'Timestamp': datetime.datetime.now(datetime.timezone.utc),
                        'Value': value,
                        'Unit': 'None',
                        'StorageResolution': 1,
                    }],
                )
                self.published += 1
                self.last_value = value
            except (ClientError, AssertionError) as exc:  # recorded, never swallowed
                self.error = exc
                return
            self._stop.wait(_PUBLISH_INTERVAL_S)


# timing:real-time — metric: 180 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-target-tracking.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics', 'plane:control', "timing:real-time")
def run(ctx) -> None:
    """A target tracking policy driven by a metric that responds to capacity moves capacity in the
    right direction and then stops near the fixed point _OFFERED_LOAD / _TARGET_VALUE, without
    oscillating and without being stopped by a bound.
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    account = ctx.client('sts').get_caller_identity()['Account']

    fixed_point = _OFFERED_LOAD / _TARGET_VALUE
    band_low = max(_MIN_CAPACITY + 1, math.floor(fixed_point * _BAND_LOW_FACTOR))
    band_high = math.ceil(fixed_point * _BAND_HIGH_FACTOR)
    assert band_high < _MAX_CAPACITY, (
        f'this check is misconfigured: the convergence band tops out at {band_high} against a '
        f'MaxCapacity of {_MAX_CAPACITY}, so a target that always answers MaxCapacity would land '
        f'inside the band and the check would not discriminate'
    )
    assert band_low > _START_COUNT, (
        f'this check is misconfigured: the band starts at {band_low}, not above the starting '
        f'capacity {_START_COUNT}, so a target that never scales would already be inside it'
    )

    cluster, service, resource_id = _ecs_estate(ctx, ecs, 'conv', _START_COUNT)
    initial = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c == _START_COUNT,
        timeout_s=90, interval_s=3.0,
        description=f'ECS reporting desiredCount {_START_COUNT} for {service!r} before anything '
                    f'scales it')
    assert initial == _START_COUNT, (
        f'ECS reports desiredCount {initial} for the freshly created service {service!r} in region '
        f'{ctx.region} of account {account}, expected {_START_COUNT}; the convergence band is '
        f'anchored on that starting capacity'
    )

    # The publisher starts BEFORE the policy so the metric exists when Application Auto Scaling
    # first evaluates it; a target tracking alarm over a metric with no datapoints sits in
    # INSUFFICIENT_DATA and "Application Auto Scaling cannot scale your scalable target until new
    # data points are found".
    publisher = _Publisher(cw, ecs, cluster, service)
    ctx.on_cleanup(publisher.stop)
    publisher.start()
    _poll_until(lambda: publisher.published, lambda n: n >= 3, timeout_s=_WARMUP_S,
                interval_s=5.0,
                description=f'the metric publisher landing at least 3 datapoints on '
                            f'{_METRIC_NAMESPACE}/{_METRIC_NAME} for {service!r} before the policy '
                            f'is created')
    assert publisher.error is None, (
        f'the metric publisher failed before the policy was created: {publisher.error!r}; without '
        f'a live metric this check would measure INSUFFICIENT_DATA, not convergence'
    )

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    policy = ctx.unique_name('sim2real-behav-aas-convpol-')
    aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy, PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration={
            'TargetValue': _TARGET_VALUE,
            'CustomizedMetricSpecification': {
                'MetricName': _METRIC_NAME,
                'Namespace': _METRIC_NAMESPACE,
                'Dimensions': [{'Name': 'ServiceName', 'Value': service}],
                'Statistic': 'Average',
            },
            # Cooldowns at 0 so that what stops the controller is the controller, not a timer. The
            # ecs namespace defaults BOTH to 300 (see the per-namespace default table in
            # target-tracking-scaling-policy-overview.html), which would confound the freeze leg.
            'ScaleOutCooldown': 0,
            'ScaleInCooldown': 0,
        },
    )
    ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, policy))
    stored = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyNames=[policy])['ScalingPolicies']
    assert len(stored) == 1, (
        f'DescribeScalingPolicies returned {len(stored)} policies named {policy!r}: {stored!r}'
    )
    config = stored[0]['TargetTrackingScalingPolicyConfiguration']
    assert config['TargetValue'] == _TARGET_VALUE, (
        f'the stored policy reports TargetValue {config.get("TargetValue")!r}, expected '
        f'{_TARGET_VALUE}; the band below cannot be attributed to a target the engine did not keep'
    )
    assert config['CustomizedMetricSpecification']['MetricName'] == _METRIC_NAME, (
        f'the stored policy tracks {config["CustomizedMetricSpecification"].get("MetricName")!r}, '
        f'not the metric {_METRIC_NAME!r} this check publishes'
    )

    # ---- Leg 1: direction. The metric starts at _OFFERED_LOAD/_START_COUNT, far ABOVE the target,
    # so the only correct direction is out.
    risen = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c > _START_COUNT,
        timeout_s=_RISE_S, interval_s=10.0,
        description=f'ECS desiredCount for {service!r} rising above {_START_COUNT} while the '
                    f'tracked metric sits at {_OFFERED_LOAD / _START_COUNT} against a target of '
                    f'{_TARGET_VALUE}')
    assert risen > _START_COUNT, (
        f'ECS reports desiredCount {risen} for {service!r}; the tracked metric was '
        f'{_OFFERED_LOAD / _START_COUNT} against a target of {_TARGET_VALUE}, which is '
        f'{_OFFERED_LOAD / _START_COUNT / _TARGET_VALUE:.1f}x the target, so the only correct '
        f'direction is OUT'
    )

    # ---- Leg 2: convergence into a band derived from the fixed point, and NOT onto a bound.
    settled = _poll_until(
        lambda: _desired_count(ecs, cluster, service),
        lambda c: band_low <= c <= band_high, timeout_s=_CONVERGE_S, interval_s=10.0,
        description=f'ECS desiredCount for {service!r} reaching the convergence band '
                    f'[{band_low}, {band_high}] around the fixed point {fixed_point} '
                    f'(= {_OFFERED_LOAD} offered load / {_TARGET_VALUE} target)')
    assert band_low <= settled <= band_high, (
        f'ECS reports desiredCount {settled} for {service!r}; a controller holding the metric at '
        f'{_TARGET_VALUE} against {_OFFERED_LOAD} units of offered load must land in '
        f'[{band_low}, {band_high}] around {fixed_point}. A target that treats every breach as '
        f'"go to MaxCapacity" answers {_MAX_CAPACITY}; one that stores the policy and computes '
        f'nothing answers {_START_COUNT}'
    )
    assert settled != _MAX_CAPACITY, (
        f'ECS reports desiredCount {settled}, which is exactly MaxCapacity; the controller must '
        f'stop because the metric reached its target, not because it ran into a bound -- the '
        f'fixed point {fixed_point} is strictly inside ({_MIN_CAPACITY}, {_MAX_CAPACITY})'
    )
    # The metric is _OFFERED_LOAD / capacity -- inversely proportional -- so the bound on the
    # achieved metric is the band's bound on capacity, INVERTED, not the same factors re-applied to
    # _TARGET_VALUE directly.
    achieved = _OFFERED_LOAD / float(settled)
    achieved_low = _OFFERED_LOAD / band_high
    achieved_high = _OFFERED_LOAD / band_low
    assert achieved_low <= achieved <= achieved_high, (
        f'at desiredCount {settled} the tracked metric works out to {achieved:.1f} against a '
        f'target of {_TARGET_VALUE}; a settled capacity in the band [{band_low}, {band_high}] '
        f'must put the metric, which is {_OFFERED_LOAD} / desiredCount, in '
        f'[{achieved_low:.1f}, {achieved_high:.1f}]'
    )

    # ---- Leg 3: it STOPS. Freeze detector, with the publisher still feeding the loop -- so this
    # is not a quiet period, it is the controller declining to act on a metric at its target.
    readings = []
    for _ in range(_FREEZE_READS):
        time.sleep(_FREEZE_INTERVAL_S)
        readings.append(_desired_count(ecs, cluster, service))
    assert publisher.error is None, (
        f'the metric publisher failed during the settle window: {publisher.error!r}; a stalled '
        f'metric stream would make "capacity stopped moving" unattributable'
    )
    assert len(set(readings)) == 1, (
        f'ECS desiredCount for {service!r} moved through {readings!r} over the '
        f'{_FREEZE_READS * _FREEZE_INTERVAL_S:.0f}s after it converged, while the metric was held '
        f'at approximately the target value {_TARGET_VALUE}; a converged target tracking policy '
        f'must stop, not oscillate'
    )
    assert readings[0] == settled, (
        f'ECS desiredCount for {service!r} was {settled} at convergence and {readings[0]} through '
        f'the settle window; the two must agree or the band assertion measured a value the '
        f'controller had already left'
    )
    assert min(readings) >= band_low and max(readings) <= band_high, (
        f'the settle window saw {readings!r}, outside the convergence band '
        f'[{band_low}, {band_high}]'
    )

    # ---- Leg 4: the history agrees, and the engine did not thrash to get there.
    #
    # AWS splits this into (at least) two records: a "Setting desired
    # count to N." activity that can still read StatusCode=InProgress at describe time even though
    # ECS's own desiredCount has already moved (AAS's own bookkeeping lags ECS by a few seconds),
    # alongside an "Attempting to scale due to alarm triggered" wrapper that IS already Successful.
    # So the terminal proof that capacity moved stays with ECS's DescribeServices (already asserted
    # above); this leg is corroborating evidence from the OTHER side of the API, tolerant of
    # that lag via a short bounded poll rather than a guess about which record ends up Successful.
    activities = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: any(
            a.get('Description') == f'Setting desired count to {settled}.' for a in acts
        ),
        timeout_s=60, interval_s=5.0,
        description=f'DescribeScalingActivities for {resource_id!r} recording an activity '
                    f'"Setting desired count to {settled}."')
    scaled = [a for a in activities if a.get('StatusCode') == 'Successful']
    assert 1 <= len(scaled) <= 6, (
        f'DescribeScalingActivities reports {len(scaled)} successful activities reaching '
        f'desiredCount {settled} from {_START_COUNT}: '
        f'{[a.get("Description") for a in activities]!r}. At least one is required (something must '
        f'have moved capacity) and more than six from {_START_COUNT} to {settled} is thrashing, '
        f'not proportional control'
    )
    sizing = [a for a in activities if a.get('Description') == f'Setting desired count to {settled}.']
    assert sizing, (
        f'no activity for {resource_id!r} describes itself as "Setting desired count to '
        f'{settled}.", though ECS independently reports desiredCount {settled}; got descriptions '
        f'{[a.get("Description") for a in activities]!r}'
    )
    assert sizing[0]['ServiceNamespace'] == _NS, (
        f'the sizing activity carried service namespace {sizing[0]["ServiceNamespace"]!r}, '
        f'expected {_NS!r}'
    )
    assert policy in sizing[0]['Cause'], (
        f'the sizing activity attributes itself to {sizing[0]["Cause"]!r}, which does not name the '
        f'policy {policy!r} this check created; the capacity change must be attributable to this '
        f'policy and not to something else in the account'
    )
    assert policy in scaled[0]['Cause'], (
        f'the newest successful activity attributes itself to {scaled[0]["Cause"]!r}, which does '
        f'not name the policy {policy!r} this check created; the capacity change must be '
        f'attributable to this policy and not to something else in the account'
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
