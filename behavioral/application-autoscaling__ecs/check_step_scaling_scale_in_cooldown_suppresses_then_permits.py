"""step-scaling-scale-in-cooldown-suppresses-then-permits."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Documented (step-scaling-policy-overview.html): "scale-in activities are BLOCKED until the
# scale-in cooldown period has expired. However, if another alarm triggers a scale-out activity
# during the scale-in cooldown period, Application Auto Scaling scales out the target immediately.
# In this case, the scale-in cooldown period STOPS and doesn't complete." The window is derived from
# the first activity's reported EndTime plus the policy's reported Cooldown. The Fargate service is
# left to converge before each scaling decision, which reads the deployment's running baseline.

CHECK = "step-scaling-scale-in-cooldown-suppresses-then-permits"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'ecs']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'CooldownDriver'

_THRESHOLD = 50.0
_START_COUNT = 12
_MIN_CAPACITY = 1
_MAX_CAPACITY = 40
_IN_ADJ = -2
_OUT_ADJ = 3
#: Long enough that a full OK -> ALARM -> OK -> ALARM cycle provably fits inside it,
#: short enough to fit the declared budget.
_COOLDOWN_S = 180

_QUIET_OUT = _THRESHOLD - 20.0
_QUIET_IN = _THRESHOLD + 20.0
#: High resolution, so a cycle costs tens of seconds rather than minutes.
_ALARM_PERIOD_S = 10
_TRANSITION_S = 90.0
#: Covers BOTH the desiredCount field flipping (near-instant) and the scaling activity's own
#: StatusCode reaching 'Successful' (real Fargate task stop/start).
_APPLY_S = 90.0
_HOLD_S = 60.0


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
    """DeleteCluster fails while any service/task is still draining; retry, then say so out loud."""
    _drain_and_delete_ecs_cluster(ecs, cluster)


def _deregister_task_definition(ecs, arn):
    try:
        _retire_task_definition(ecs, arn)
    except ClientError as exc:
        raise RuntimeError(f'task definition {arn!r} not deregistered: '
                           f'{exc.response.get("Error", {}).get("Code")}') from exc


def _default_vpc(ec2, *, ctx):
    """(vpc_id, subnet_id, sg_id) from the run's shared network; raises with a named subject
    rather than a bare IndexError if absent."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])['Vpcs']
    assert len(vpcs) == 1, f'expected exactly one shared network, found {len(vpcs)}: {vpcs!r}'
    vpc_id = vpcs[0]['VpcId']
    subnets = ec2.describe_subnets(Filters=[
        {'Name': 'vpc-id', 'Values': [vpc_id]},
        {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])['Subnets']
    assert subnets, f'shared network {vpc_id!r} has no default-for-az subnet to place a Fargate ENI'
    subnet_id = sorted(subnets, key=lambda s: s['SubnetId'])[0]['SubnetId']
    sgs = ec2.describe_security_groups(Filters=[
        {'Name': 'vpc-id', 'Values': [vpc_id]},
        {'Name': 'group-name', 'Values': ['default']},
    ])['SecurityGroups']
    assert len(sgs) == 1, f'expected exactly one default security group in {vpc_id!r}, found {sgs!r}'
    return vpc_id, subnet_id, sgs[0]['GroupId']


def _execution_role(ctx, iam):
    """A task execution role trusting ecs-tasks.amazonaws.com, so Fargate can actually pull the
    image and place a task -- the estate needs REAL placement capacity (see the deployment
    convergence comment in run()), and Fargate supplies it without a self-managed container
    instance.
    """
    name = ctx.unique_name('sim2real-behav-aas-coolexec-')
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            'Version': '2012-10-17',
            'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
                           'Action': 'sts:AssumeRole'}],
        }),
        Tags=[{'Key': 'sim2real', 'Value': CHECK}, {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )['Role']['Arn']

    def _drop():
        try:
            iam.detach_role_policy(
                RoleName=name,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy')
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') != 'NoSuchEntity':
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') != 'NoSuchEntity':
                raise

    ctx.on_cleanup(_drop)
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy')
    _poll_until(
        lambda: iam.list_attached_role_policies(RoleName=name)['AttachedPolicies'],
        lambda pols: any(p['PolicyName'] == 'AmazonECSTaskExecutionRolePolicy' for p in pols),
        timeout_s=60, interval_s=2.0,
        description=f'role {name!r} reporting its execution policy attached')
    time.sleep(10)  # trust-policy propagation to ecs-tasks.amazonaws.com, not the assertion
    return role


def _ecs_estate(ctx, ecs, slug, desired):
    """A cluster, a task definition and a service with `desired` tasks; cleanups registered.

    Fargate gives the service real placement capacity; the deployment must still converge
    (`_primary_deployment` polled in `run()`) before the first scaling decision reads it.
    """
    ec2 = ctx.client('ec2')
    iam = ctx.client('iam')
    vpc_id, subnet_id, sg_id = _default_vpc(ec2, ctx=ctx)
    execution_role_arn = _execution_role(ctx, iam)

    cluster = ctx.unique_name(f'sim2real-behav-aas-{slug}-cl-')
    service = ctx.unique_name(f'sim2real-behav-aas-{slug}-svc-')
    family = ctx.unique_name(f'sim2real-behav-aas-{slug}-td-')
    pairs = [{'key': 'sim2real', 'value': CHECK}, {'key': 'owner', 'value': 'sim2real-behav-aas'}]

    ecs.create_cluster(clusterName=cluster, tags=pairs)
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    task_def = ecs.register_task_definition(
        family=family, networkMode='awsvpc', requiresCompatibilities=['FARGATE'],
        cpu='256', memory='512', executionRoleArn=execution_role_arn,
        containerDefinitions=[{
            'name': 'sim2real-idle',
            'image': 'public.ecr.aws/docker/library/busybox:1.36',
            'essential': True, 'command': ['sh', '-c', 'sleep 3600'],
        }],
        tags=pairs,
    )['taskDefinition']['taskDefinitionArn']
    ctx.on_cleanup(lambda: _deregister_task_definition(ecs, task_def))
    ecs.create_service(
        cluster=cluster, serviceName=service, taskDefinition=task_def,
        desiredCount=desired, launchType='FARGATE', tags=pairs,
        networkConfiguration={'awsvpcConfiguration': {
            'subnets': [subnet_id], 'securityGroups': [sg_id], 'assignPublicIp': 'ENABLED'}},
    )
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


def _primary_deployment(ecs, cluster, service):
    """The service's PRIMARY deployment (its desiredCount/runningCount, not the top-level
    service fields, is what Application Auto Scaling's ChangeInCapacity arithmetic actually
    reads -- see the deployment convergence comment in run())."""
    described = ecs.describe_services(cluster=cluster, services=[service])['services']
    assert len(described) == 1, (
        f'DescribeServices returned {len(described)} services for {service!r}, expected 1'
    )
    deployments = [d for d in described[0]['deployments'] if d.get('status') == 'PRIMARY']
    assert len(deployments) == 1, (
        f'{service!r} reports {len(deployments)} PRIMARY deployments, expected exactly 1: '
        f'{described[0]["deployments"]!r}'
    )
    return deployments[0]


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


# timing:real-time — cooldown: 180 s https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html
@tags('axis:negative-delivery', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics',
      'plane:control', "timing:real-time")
def run(ctx) -> None:
    """A step policy's scale-in Cooldown suppresses a second scale-in inside the window and permits
    it outside, while a scale-out fired inside the window is not suppressed and cancels the cooldown.
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    account = ctx.client('sts').get_caller_identity()['Account']

    cluster, service, resource_id = _ecs_estate(ctx, ecs, 'cool', _START_COUNT)
    initial = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c == _START_COUNT,
        timeout_s=90, interval_s=3.0,
        description=f'ECS reporting desiredCount {_START_COUNT} for {service!r} before anything '
                    f'scales it')
    assert initial == _START_COUNT, (
        f'ECS reports desiredCount {initial} for the freshly created service {service!r} in region '
        f'{ctx.region} of account {account}, expected {_START_COUNT}'
    )
    # The service-level desiredCount above is set the instant CreateService returns, but
    # Application Auto Scaling's ChangeInCapacity arithmetic reads the PRIMARY DEPLOYMENT's own
    # desiredCount, which only catches up to the service's target once the deployment converges
    # (a Fargate deployment's desiredCount can lag at a stale value for tens of seconds while its
    # tasks are still placing/pulling/starting). An alarm breach inside that window can clamp the
    # target to MinCapacity. So this check WAITS for the deployment to actually converge
    # (runningCount == desiredCount == _START_COUNT) before registering the scalable target.
    converged = _poll_until(
        lambda: _primary_deployment(ecs, cluster, service), lambda d: d.get('runningCount') == _START_COUNT
        and d.get('desiredCount') == _START_COUNT,
        timeout_s=180, interval_s=5.0,
        description=f'the PRIMARY deployment for {service!r} converging to desiredCount == '
                    f'runningCount == {_START_COUNT} before any scaling policy exists')
    assert converged['desiredCount'] == _START_COUNT and converged['runningCount'] == _START_COUNT, (
        f'the PRIMARY deployment for {service!r} reports desiredCount '
        f'{converged.get("desiredCount")!r} / runningCount {converged.get("runningCount")!r}, '
        f'expected both to equal {_START_COUNT} -- the baseline Application Auto Scaling will '
        f'compute the first ChangeInCapacity against must be settled before it is measured'
    )

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    in_policy = ctx.unique_name('sim2real-behav-aas-coolin-')
    out_policy = ctx.unique_name('sim2real-behav-aas-coolout-')
    in_put = aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=in_policy, PolicyType='StepScaling',
        StepScalingPolicyConfiguration={
            'AdjustmentType': 'ChangeInCapacity',
            'MetricAggregationType': 'Maximum',
            'Cooldown': _COOLDOWN_S,
            'StepAdjustments': [
                {'MetricIntervalUpperBound': 0.0, 'ScalingAdjustment': _IN_ADJ},
            ],
        },
    )
    ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, in_policy))
    out_put = aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=out_policy, PolicyType='StepScaling',
        StepScalingPolicyConfiguration={
            'AdjustmentType': 'ChangeInCapacity',
            'MetricAggregationType': 'Maximum',
            # 0 so leg 4 tests the SCALE-IN cooldown's exception, not a scale-out cooldown.
            'Cooldown': 0,
            'StepAdjustments': [
                {'MetricIntervalLowerBound': 0.0, 'ScalingAdjustment': _OUT_ADJ},
            ],
        },
    )
    ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, out_policy))

    stored = {p['PolicyName']: p for p in aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=resource_id,
        ScalableDimension=_DIM)['ScalingPolicies']}
    assert set(stored) == {in_policy, out_policy}, (
        f'DescribeScalingPolicies reports {sorted(stored)!r}, expected exactly '
        f'{sorted((in_policy, out_policy))!r}'
    )
    held_cooldown = stored[in_policy]['StepScalingPolicyConfiguration'].get('Cooldown')
    assert held_cooldown == _COOLDOWN_S, (
        f'the stored scale-in policy {in_policy!r} reports Cooldown {held_cooldown!r}, expected '
        f'{_COOLDOWN_S}; the documented default is 300, and every window below is derived from the '
        f'cooldown the TARGET reports rather than the one this check sent'
    )
    assert stored[out_policy]['StepScalingPolicyConfiguration'].get('Cooldown') == 0, (
        f'the stored scale-out policy {out_policy!r} reports Cooldown '
        f'{stored[out_policy]["StepScalingPolicyConfiguration"].get("Cooldown")!r}, expected 0; a '
        f'non-zero scale-out cooldown would confound leg 4'
    )

    in_alarm = ctx.unique_name('sim2real-behav-aas-coolinal-')
    out_alarm = ctx.unique_name('sim2real-behav-aas-cooloutal-')

    def _put_alarm(name, leg, operator, policy_arn):
        cw.put_metric_alarm(
            AlarmName=name, AlarmDescription=f'sim2real {CHECK}',
            Namespace=_METRIC_NAMESPACE, MetricName=_METRIC_NAME,
            Dimensions=[{'Name': 'ServiceName', 'Value': service},
                        {'Name': 'Leg', 'Value': leg}],
            Statistic='Maximum', Period=_ALARM_PERIOD_S, EvaluationPeriods=1, DatapointsToAlarm=1,
            Threshold=_THRESHOLD, ComparisonOperator=operator,
            TreatMissingData='notBreaching', AlarmActions=[policy_arn],
            Tags=[{'Key': 'sim2real', 'Value': CHECK},
                  {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
        )
        ctx.on_cleanup(lambda: _delete_alarm(cw, name))
        wired = cw.describe_alarms(AlarmNames=[name])['MetricAlarms']
        assert len(wired) == 1 and wired[0]['AlarmActions'] == [policy_arn], (
            f'the alarm {name!r} lists alarm actions '
            f'{[a.get("AlarmActions") for a in wired]!r}; it must point at exactly {policy_arn!r}'
        )
        assert wired[0]['Period'] == _ALARM_PERIOD_S, (
            f'the alarm {name!r} reports Period {wired[0]["Period"]!r}, expected '
            f'{_ALARM_PERIOD_S}; the whole schedule of this check depends on a high-resolution '
            f'evaluation window'
        )

    _put_alarm(in_alarm, 'in', 'LessThanThreshold', in_put['PolicyARN'])
    _put_alarm(out_alarm, 'out', 'GreaterThanThreshold', out_put['PolicyARN'])

    def _publish(out_value, in_value):
        now = datetime.datetime.now(datetime.timezone.utc)
        cw.put_metric_data(
            Namespace=_METRIC_NAMESPACE,
            MetricData=[
                {'MetricName': _METRIC_NAME,
                 'Dimensions': [{'Name': 'ServiceName', 'Value': service},
                                {'Name': 'Leg', 'Value': leg}],
                 'Timestamp': now, 'Value': value, 'Unit': 'None', 'StorageResolution': 1}
                for leg, value in (('out', out_value), ('in', in_value))
            ],
        )

    def _drive(out_value, in_value, *, want_out, want_in, leg):
        deadline = time.monotonic() + _TRANSITION_S
        last = None
        while time.monotonic() < deadline:
            _publish(out_value, in_value)
            last = (_alarm_state(cw, out_alarm), _alarm_state(cw, in_alarm))
            if last == (want_out, want_in):
                return
            time.sleep(5.0)
        raise AssertionError(
            f'{leg}: alarms ({out_alarm!r}, {in_alarm!r}) never reached ({want_out}, {want_in}) '
            f'within {_TRANSITION_S}s of publishing out={out_value} in={in_value} against a '
            f'threshold of {_THRESHOLD}; last saw {last!r}')

    def _successful(activities):
        return [a for a in activities if a.get('StatusCode') == 'Successful']

    def _await_successful_count(n, *, timeout_s, description):
        """Poll until DescribeScalingActivities reports exactly `n` Successful activities.

        A ChangeInCapacity activity's StatusCode is 'InProgress' -- not yet
        'Successful' -- until ECS has actually finished reconciling to the new desiredCount
        (real placement work: stopping/starting Fargate tasks), which measurably lags the
        desiredCount field itself reflecting the new target. This estate has real placement
        capacity from Fargate (unlike a zero-container-instance EC2 estate, where the activity
        would never resolve at all), so
        waiting here is a bounded wait for genuine convergence, not a stand-in for capacity
        that will never arrive.
        """
        return _poll_until(
            lambda: _successful(_activities(aas, resource_id)), lambda acts: len(acts) == n,
            timeout_s=timeout_s, interval_s=5.0, description=description)

    # ---- Leg 1: the first scale-in. Its EndTime starts the cooldown clock.
    _drive(_QUIET_OUT, _THRESHOLD - 5.0, want_out='OK', want_in='ALARM', leg='leg 1')
    after_1 = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c != _START_COUNT,
        timeout_s=_APPLY_S, interval_s=3.0,
        description=f'leg 1: ECS desiredCount for {service!r} moving off {_START_COUNT} after the '
                    f'scale-in policy fired')
    assert after_1 == _START_COUNT + _IN_ADJ, (
        f'leg 1: ECS reports desiredCount {after_1} for {service!r}; ChangeInCapacity {_IN_ADJ} '
        f'from {_START_COUNT} is {_START_COUNT + _IN_ADJ}'
    )
    first = _await_successful_count(
        1, timeout_s=_APPLY_S,
        description=f'leg 1: exactly one Successful scaling activity for {resource_id!r} once '
                    f'ECS finishes reconciling to {after_1}')
    cooldown_from = first[0]['EndTime']
    assert cooldown_from > first[0]['StartTime'], (
        f'leg 1: the activity reports EndTime {first[0]["EndTime"]!r}, not after its StartTime '
        f'{first[0]["StartTime"]!r}; the cooldown window is derived from that EndTime'
    )
    cooldown_until = cooldown_from + datetime.timedelta(seconds=held_cooldown)

    # ---- Leg 2: the same breach again, INSIDE the window. It must be suppressed.
    _drive(_QUIET_OUT, _QUIET_IN, want_out='OK', want_in='OK', leg='leg 2 (returning to OK)')
    _drive(_QUIET_OUT, _THRESHOLD - 5.0, want_out='OK', want_in='ALARM', leg='leg 2')
    now = datetime.datetime.now(datetime.timezone.utc)
    assert now < cooldown_until, (
        f'leg 2 could not be run: the second breach landed at {now.isoformat()}, at or after the '
        f'scale-in cooldown expiry {cooldown_until.isoformat()} derived from the first activity\'s '
        f'EndTime plus its {held_cooldown}s Cooldown. The alarm cycle is slower than this check '
        f'assumed -- RAISE _COOLDOWN_S; do not shorten any wait, and do not interpret the absence '
        f'below, because it would be indistinguishable from leg 3'
    )
    deadline = time.monotonic() + _HOLD_S
    while time.monotonic() < deadline:
        assert _alarm_state(cw, in_alarm) == 'ALARM', (
            f'leg 2: the scale-in alarm {in_alarm!r} left ALARM during the suppression window, so '
            f'an unchanged capacity would prove nothing about the cooldown'
        )
        held = _desired_count(ecs, cluster, service)
        assert held == after_1, (
            f'leg 2: ECS reports desiredCount {held} for {service!r} at '
            f'{datetime.datetime.now(datetime.timezone.utc).isoformat()}, which is before the '
            f'scale-in cooldown expiry {cooldown_until.isoformat()}; a second scale-in inside the '
            f'window must be BLOCKED, leaving {after_1}'
        )
        time.sleep(5.0)
    assert datetime.datetime.now(datetime.timezone.utc) < cooldown_until, (
        f'leg 2: the {_HOLD_S}s absence window ran past the cooldown expiry '
        f'{cooldown_until.isoformat()}, so part of it proves nothing; RAISE _COOLDOWN_S'
    )
    during = _activities(aas, resource_id)
    assert len(_successful(during)) == 1, (
        f'leg 2: DescribeScalingActivities reports {len(_successful(during))} successful activities '
        f'inside the scale-in cooldown window, expected still exactly the one from leg 1: '
        f'{[(a.get("StatusCode"), a.get("Description")) for a in during]!r}'
    )
    # Printed, not asserted: the docs list no not-scaled reason code for a cooldown suppression.
    print(f'[MEASURE] activities inside the scale-in cooldown, IncludeNotScaledActivities=True: '
          f'{[(a.get("StatusCode"), a.get("Description"), a.get("NotScaledReasons")) for a in during]!r}')

    # ---- Leg 3: the same breach, OUTSIDE the window. It must now be permitted. The alarm is
    # already in ALARM and has been throughout, so the only thing that changed is the clock.
    wait_for = (cooldown_until - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    assert wait_for <= held_cooldown, (
        f'leg 3: computed a wait of {wait_for}s for a {held_cooldown}s cooldown, which cannot be '
        f'right; refusing to wait on arithmetic that does not hold'
    )
    _poll_until(
        lambda: datetime.datetime.now(datetime.timezone.utc),
        lambda now_: now_ > cooldown_until, timeout_s=max(wait_for, 0.0) + 30.0, interval_s=5.0,
        description=f'the {held_cooldown}s scale-in cooldown started by leg 1\'s activity to expire '
                    f'at {cooldown_until.isoformat()}; leg 3 exists to show the SAME breach is '
                    f'permitted once it has, so the clock is the only thing this waits on')
    # CloudWatch invokes an alarm action only on a state TRANSITION, so the expired cooldown has to
    # be given a fresh breach to act on -- the cooldown is what leg 2 proved absent, not the alarm.
    _drive(_QUIET_OUT, _QUIET_IN, want_out='OK', want_in='OK', leg='leg 3 (returning to OK)')
    _drive(_QUIET_OUT, _THRESHOLD - 5.0, want_out='OK', want_in='ALARM', leg='leg 3')
    breach_at = datetime.datetime.now(datetime.timezone.utc)
    assert breach_at > cooldown_until, (
        f'leg 3: the third breach landed at {breach_at.isoformat()}, still inside the cooldown '
        f'window that ends at {cooldown_until.isoformat()}'
    )
    after_3 = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c != after_1,
        timeout_s=_APPLY_S, interval_s=3.0,
        description=f'leg 3: ECS desiredCount for {service!r} moving off {after_1} once the '
                    f'{held_cooldown}s scale-in cooldown that ended at '
                    f'{cooldown_until.isoformat()} has expired')
    assert after_3 == after_1 + _IN_ADJ, (
        f'leg 3: ECS reports desiredCount {after_3} for {service!r}; the same ChangeInCapacity '
        f'{_IN_ADJ} that was suppressed inside the window must apply in full outside it, taking '
        f'{after_1} to {after_1 + _IN_ADJ}'
    )
    second = _await_successful_count(
        2, timeout_s=_APPLY_S,
        description=f'leg 3: a second Successful scaling activity for {resource_id!r} once ECS '
                    f'finishes reconciling to {after_3}')
    cooldown_2_until = second[0]['EndTime'] + datetime.timedelta(seconds=held_cooldown)

    # ---- Leg 4: a SCALE-OUT inside the fresh scale-in cooldown is not suppressed. This is the
    # selectivity claim: one boolean for "in cooldown" fails here and nowhere else.
    _drive(_THRESHOLD + 5.0, _QUIET_IN, want_out='ALARM', want_in='OK', leg='leg 4')
    now = datetime.datetime.now(datetime.timezone.utc)
    assert now < cooldown_2_until, (
        f'leg 4 could not be run: the scale-out breach landed at {now.isoformat()}, at or after the '
        f'scale-in cooldown expiry {cooldown_2_until.isoformat()} started by leg 3; RAISE '
        f'_COOLDOWN_S rather than interpreting a scale-out that was never inside a cooldown'
    )
    after_4 = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c != after_3,
        timeout_s=_APPLY_S, interval_s=3.0,
        description=f'leg 4: ECS desiredCount for {service!r} moving off {after_3} on a SCALE-OUT '
                    f'breach that fell inside the scale-in cooldown ending at '
                    f'{cooldown_2_until.isoformat()}')
    assert after_4 == after_3 + _OUT_ADJ, (
        f'leg 4: ECS reports desiredCount {after_4} for {service!r}; a scale-out inside a scale-in '
        f'cooldown is documented to proceed IMMEDIATELY, so ChangeInCapacity {_OUT_ADJ} must take '
        f'{after_3} to {after_3 + _OUT_ADJ}. An implementation with a single "in cooldown" flag '
        f'covering both directions leaves {after_3}'
    )
    assert _MIN_CAPACITY < after_4 < _MAX_CAPACITY, (
        f'this check ended at desiredCount {after_4}, on or outside the registered bounds '
        f'({_MIN_CAPACITY}, {_MAX_CAPACITY}); no leg here may be explained by a clamp'
    )


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError:
                pass
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
