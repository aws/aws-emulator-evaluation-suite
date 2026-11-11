"""percent-change-sub-unit-rounding-and-magnitude-floor."""
from __future__ import annotations

import datetime
import json
import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Application Auto Scaling computes a step adjustment from the RUNNING count, so the service runs
# real Fargate tasks; Cooldown is enforced across the whole scalable target, so run() waits it out
# before driving the next leg. Documented rounding
# (https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html):
# values between 0 and 1 round to 1, values between 0 and -1 round to -1, and MinAdjustmentMagnitude
# then floors the absolute value:
#   leg 1  +_PCT (10)% of 8 =  0.8 -> rounds to +1                                   -> 9
#   leg 2  -_PCT (10)% of 9 = -0.9 -> rounds to -1                                   -> 8
#   leg 3  -_PCT (10)% of 8 = -0.8 -> rounds to -1, then MinAdjustmentMagnitude 3     -> 5

CHECK = "percent-change-sub-unit-rounding-and-magnitude-floor"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'ecs']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'RoundingDriver'

_THRESHOLD = 50.0
#: 8 so that 10 percent of every capacity this check visits (8, 9, 8) is strictly between 0 and 1
#: in magnitude -- which is the whole subject -- and so no leg lands on a bound or on the
#: unspecified |raw| == 1 boundary.
_START_COUNT = 8
_MIN_CAPACITY = 1
_MAX_CAPACITY = 40
_PCT = 10
_MAGNITUDE = 3

_QUIET_OUT = _THRESHOLD - 20.0
_QUIET_IN = _THRESHOLD + 20.0
_ALARM_PERIOD_S = 30
_TRANSITION_S = 120.0
#: Bound for the adjustment to land once the service has real (Fargate) placement capacity.
_APPLY_S = 120.0
#: Real compute converging: 8 Fargate tasks reaching RUNNING initially, and one task's worth of
#: delta converging between legs.
_INITIAL_STEADY_S = 240.0
_CONVERGE_S = 200.0
#: A StepScaling Cooldown is enforced across the whole scalable target and bounds AAS's own
#: retry-and-recompute window (~70s) to a single fire; run() waits it out before the next leg.
_COOLDOWN_S = 90
_COOLDOWN_MARGIN_S = 30
_TASK_CPU = '256'
_TASK_MEMORY = '512'


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


#: A force-deleted Fargate service can still leave its last task
#: mid-STOPPING (ENI detach lags the service delete), which DeleteCluster reports as
#: ClusterContainsTasksException rather than ClusterContainsServicesException -- retry on both.
_CLUSTER_DELETE_RETRIES = 16


def _delete_cluster(ecs, cluster):
    """DeleteCluster fails while any service or task is still draining; retry, then say so out loud."""
    for _ in range(_CLUSTER_DELETE_RETRIES):
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


def _detach_delete_igw(ec2, igw_id, vpc_id):
    try:
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') not in ('Gateway.NotAttached',
                                                             'InvalidInternetGatewayID.NotFound'):
            raise
    try:
        _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'InvalidInternetGatewayID.NotFound':
            raise


def _delete_route_table(ec2, rt_id, assoc_id):
    try:
        ec2.disassociate_route_table(AssociationId=assoc_id)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'InvalidAssociationID.NotFound':
            raise
    try:
        _delete_net(ec2, "delete_route_table", RouteTableId=rt_id)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'InvalidRouteTableID.NotFound':
            raise


def _delete_subnet(ec2, subnet_id):
    for _ in range(12):
        try:
            _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'InvalidSubnetID.NotFound':
                return
            if code != 'DependencyViolation':
                raise RuntimeError(f'subnet {subnet_id!r} not deleted: {code}') from exc
            time.sleep(6)
    raise RuntimeError(f'subnet {subnet_id!r} still has a dependency after retries')


def _delete_vpc(ec2, vpc_id):
    for _ in range(12):
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'InvalidVpcID.NotFound':
                return
            if code != 'DependencyViolation':
                raise RuntimeError(f'vpc {vpc_id!r} not deleted: {code}') from exc
            time.sleep(6)
    raise RuntimeError(f'vpc {vpc_id!r} still has a dependency after retries')


def _network(ctx, ec2):
    """A minimal self-contained public VPC (no ambient default VPC assumed).

    Fargate tasks pulling from public ECR need internet egress; there is no NAT-less path for that
    from a private subnet, so the subnet gets a route to an Internet Gateway and public IPs.
    """
    pairs = [{'Key': 'sim2real', 'Value': CHECK}, {'Key': 'owner', 'Value': 'sim2real-behav-aas'}]
    vpc_id = ec2.create_vpc(
        CidrBlock='10.95.0.0/16',
        TagSpecifications=[{'ResourceType': 'vpc', 'Tags': pairs}])['Vpc']['VpcId']
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={'Value': True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{'ResourceType': 'internet-gateway', 'Tags': pairs}]
    )['InternetGateway']['InternetGatewayId']
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _detach_delete_igw(ec2, igw_id, vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock='10.95.1.0/24',
        TagSpecifications=[{'ResourceType': 'subnet', 'Tags': pairs}])['Subnet']['SubnetId']
    ctx.on_cleanup(lambda: _delete_subnet(ec2, subnet_id))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={'Value': True})

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[{'ResourceType': 'route-table', 'Tags': pairs}]
    )['RouteTable']['RouteTableId']
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock='0.0.0.0/0', GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)['AssociationId']
    ctx.on_cleanup(lambda: _delete_route_table(ec2, rt_id, assoc_id))

    sg_id = ec2.describe_security_groups(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'group-name', 'Values': ['default']}]
    )['SecurityGroups'][0]['GroupId']
    return subnet_id, sg_id


def _delete_role(iam, role_name, policy_arn):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'NoSuchEntity':
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'NoSuchEntity':
            raise


def _execution_role(ctx, iam):
    """A minimal Fargate task-execution role, in case the target enforces registry-auth pulls."""
    role_name = ctx.unique_name('sim2real-behav-aas-fgexec-')[:64]
    trust = {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
         'Action': 'sts:AssumeRole'},
    ]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['Role']['Arn']
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_arn))
    return role_arn


def _ecs_estate(ctx, ec2, iam, ecs, slug, desired):
    """A VPC, a Fargate-backed cluster, a task definition and a service with `desired` tasks.

    Fargate gives the service real placement capacity -- up to _MAX_CAPACITY tasks -- with no EC2
    container instance to manage, so runningCount can actually converge to desiredCount between
    legs: Application Auto Scaling's step-scaling arithmetic reads RUNNING
    capacity, not desired, so this convergence is the subject's real prerequisite, not incidental.
    """
    subnet_id, sg_id = _network(ctx, ec2)
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
            'subnets': [subnet_id], 'securityGroups': [sg_id], 'assignPublicIp': 'ENABLED'}},
        tags=pairs)
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, service))
    return cluster, service, f'service/{cluster}/{service}'


def _service_counts(ecs, cluster, service):
    described = ecs.describe_services(cluster=cluster, services=[service])['services']
    assert len(described) == 1, (
        f'DescribeServices returned {len(described)} services for {service!r} in cluster '
        f'{cluster!r}, expected exactly 1: {described!r}'
    )
    return described[0]['desiredCount'], described[0]['runningCount']


def _desired_count(ecs, cluster, service):
    """The terminal read, at the CONSUMER: ECS's own view of the service it was told to resize."""
    return _service_counts(ecs, cluster, service)[0]


def _running_count(ecs, cluster, service):
    """What Application Auto Scaling actually reads as "current capacity" (the running count)."""
    return _service_counts(ecs, cluster, service)[1]


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


def _percent_adjustment(capacity, percent, min_magnitude=None):
    """The documented PercentChangeInCapacity arithmetic, as the RULE and never as the answer.

    raw = capacity * percent / 100, then:
      raw >  1  -> rounded DOWN     ("12.7 is rounded to 12")
      0 < raw <= 1 -> 1             (".67 is rounded to 1"; exactly 1 needs no rounding)
      -1 <= raw < 0 -> -1           ("-.58 is rounded to -1"; exactly -1 needs no rounding)
      raw < -1  -> rounded UP       ("-6.67 is rounded to -6")
    and MinAdjustmentMagnitude, when set, is a floor on the ABSOLUTE value of the result -- it is
    documented as "the minimum value to scale by", a magnitude, so it must not change the sign.
    """
    raw = capacity * percent / 100.0
    if raw > 1.0:
        rounded = math.floor(raw)
    elif raw > 0.0:
        rounded = 1
    elif raw == 0.0:
        rounded = 0
    elif raw >= -1.0:
        rounded = -1
    else:
        rounded = math.ceil(raw)
    if min_magnitude is None or rounded == 0:
        return rounded
    sign = 1 if rounded > 0 else -1
    return sign * max(abs(rounded), min_magnitude)


# timing:real-time — cooldown: 90 s https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics', 'plane:control', "timing:real-time")
def run(ctx) -> None:
    """A PercentChangeInCapacity adjustment whose raw value is a fraction of one unit rounds away
    from zero to a whole unit in both directions, and MinAdjustmentMagnitude then floors its absolute
    size without changing its sign: int() or round() stalls, max(adj, magnitude) scales out.
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    ec2 = ctx.client('ec2')
    iam = ctx.client('iam')
    account = ctx.client('sts').get_caller_identity()['Account']

    cluster, service, resource_id = _ecs_estate(ctx, ec2, iam, ecs, 'round', _START_COUNT)
    initial = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c == _START_COUNT,
        timeout_s=90, interval_s=3.0,
        description=f'ECS reporting desiredCount {_START_COUNT} for {service!r} before anything '
                    f'scales it')
    assert initial == _START_COUNT, (
        f'ECS reports desiredCount {initial} for the freshly created service {service!r} in region '
        f'{ctx.region} of account {account}, expected {_START_COUNT}'
    )
    running = _poll_until(
        lambda: _running_count(ecs, cluster, service), lambda r: r == _START_COUNT,
        timeout_s=_INITIAL_STEADY_S, interval_s=5.0,
        description=f'ECS reporting runningCount {_START_COUNT} for {service!r} once its Fargate '
                    f'tasks have started -- the capacity every leg below is arithmetic on')
    assert running == _START_COUNT, (
        f'ECS reports runningCount {running} for {service!r}, expected {_START_COUNT} before any '
        f'scaling policy fires; Application Auto Scaling reads running capacity, not desired, so '
        f'a mismatch here would confound every leg'
    )
    assert 0.0 < abs(_START_COUNT * _PCT / 100.0) < 1.0, (
        f'this check is misconfigured: {_PCT}% of {_START_COUNT} is '
        f'{_START_COUNT * _PCT / 100.0}, which is not strictly inside (0, 1), so leg 1 would not '
        f'probe the sub-unit rounding rule at all'
    )

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    out_policy = ctx.unique_name('sim2real-behav-aas-rndout-')
    in_policy = ctx.unique_name('sim2real-behav-aas-rndin-')

    def _put(name, adjustment, upper, lower, magnitude=None):
        """Upsert a one-step PercentChangeInCapacity policy; returns its ARN."""
        step = {'ScalingAdjustment': adjustment}
        if lower is not None:
            step['MetricIntervalLowerBound'] = lower
        if upper is not None:
            step['MetricIntervalUpperBound'] = upper
        config = {
            'AdjustmentType': 'PercentChangeInCapacity',
            'MetricAggregationType': 'Maximum',
            # Nonzero, and enforced target-wide: see _COOLDOWN_S above.
            'Cooldown': _COOLDOWN_S,
            'StepAdjustments': [step],
        }
        if magnitude is not None:
            config['MinAdjustmentMagnitude'] = magnitude
        put = aas.put_scaling_policy(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyName=name, PolicyType='StepScaling',
            StepScalingPolicyConfiguration=config)
        ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, name))
        stored = aas.describe_scaling_policies(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyNames=[name])['ScalingPolicies']
        assert len(stored) == 1, (
            f'DescribeScalingPolicies returned {len(stored)} policies named {name!r}: {stored!r}'
        )
        held = stored[0]['StepScalingPolicyConfiguration']
        assert held['AdjustmentType'] == 'PercentChangeInCapacity', (
            f'the stored policy {name!r} reports AdjustmentType {held.get("AdjustmentType")!r}, '
            f'expected "PercentChangeInCapacity"'
        )
        if magnitude is None:
            assert 'MinAdjustmentMagnitude' not in held, (
                f'the stored policy {name!r} reports MinAdjustmentMagnitude '
                f'{held.get("MinAdjustmentMagnitude")!r} although none was sent; legs 1 and 2 '
                f'exercise the rounding rule with NO magnitude floor, so an invented default would '
                f'confound them'
            )
        else:
            assert held.get('MinAdjustmentMagnitude') == magnitude, (
                f'the stored policy {name!r} reports MinAdjustmentMagnitude '
                f'{held.get("MinAdjustmentMagnitude")!r}, expected {magnitude}; leg 3 cannot be '
                f'attributed to a field the target did not keep'
            )
        return put['PolicyARN']

    out_arn = _put(out_policy, _PCT, None, 0.0)
    in_arn = _put(in_policy, -_PCT, 0.0, None)

    out_alarm = ctx.unique_name('sim2real-behav-aas-rndoutal-')
    in_alarm = ctx.unique_name('sim2real-behav-aas-rndinal-')

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

    _put_alarm(out_alarm, 'out', 'GreaterThanThreshold', out_arn)
    _put_alarm(in_alarm, 'in', 'LessThanThreshold', in_arn)

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
        """Publish the breaching datapoint once, then poll for the transition. Bounded; raises."""
        _publish(out_value, in_value)
        deadline = time.monotonic() + _TRANSITION_S
        last = None
        while time.monotonic() < deadline:
            last = (_alarm_state(cw, out_alarm), _alarm_state(cw, in_alarm))
            if last == (want_out, want_in):
                return
            time.sleep(10.0)
        raise AssertionError(
            f'{leg}: alarms ({out_alarm!r}, {in_alarm!r}) never reached ({want_out}, {want_in}) '
            f'within {_TRANSITION_S}s of publishing out={out_value} in={in_value} against a '
            f'threshold of {_THRESHOLD}; last saw {last!r}')

    def _quiesce(*, leg):
        deadline = time.monotonic() + _TRANSITION_S
        last = None
        while time.monotonic() < deadline:
            _publish(_QUIET_OUT, _QUIET_IN)
            last = (_alarm_state(cw, out_alarm), _alarm_state(cw, in_alarm))
            if last == ('OK', 'OK'):
                return
            time.sleep(10.0)
        raise AssertionError(
            f'{leg}: alarms never both returned to OK within {_TRANSITION_S}s; last saw {last!r}. '
            f'CloudWatch invokes an alarm action only on a state TRANSITION, so the next leg cannot '
            f'fire until both are back in OK')

    def _apply(before, adjustment, *, leg, detail):
        assert adjustment != 0, (
            f'{leg} is misconfigured: the rule yields an adjustment of 0 from {before}, so nothing '
            f'would move and the poll below could not distinguish a correct target from an inert '
            f'one'
        )
        after = _poll_until(
            lambda: _desired_count(ecs, cluster, service), lambda c: c != before,
            timeout_s=_APPLY_S, interval_s=4.0,
            description=f'{leg}: ECS desiredCount for {service!r} moving off {before}; {detail}')
        assert after == before + adjustment, (
            f'{leg}: ECS reports desiredCount {after} for {service!r}, expected '
            f'{before + adjustment}. {detail}'
        )
        # CloudWatch re-invokes AlarmActions on every evaluation period while an alarm REMAINS in
        # ALARM, so the newest activity is not necessarily the one that produced `after`. Find the
        # one that did, and bound the wait for it to leave InProgress.
        newest = _poll_until(
            lambda: next((a for a in _activities(aas, resource_id)
                          if a['Description'] == f'Setting desired count to {after}.'), None),
            lambda a: a is not None and a['StatusCode'] != 'InProgress',
            timeout_s=60.0, interval_s=5.0,
            description=f'{leg}: a scaling activity setting desired count to {after} leaving '
                        f'InProgress')
        assert newest['StatusCode'] == 'Successful', (
            f'{leg}: the scaling activity that set desired count to {after} finished '
            f'{newest["StatusCode"]!r}, expected "Successful"'
        )
        assert _MIN_CAPACITY < after < _MAX_CAPACITY, (
            f'{leg}: desiredCount {after} is on or outside the registered bounds '
            f'({_MIN_CAPACITY}, {_MAX_CAPACITY}); no leg here may be explained by a clamp'
        )
        return after

    # The three legs share one loop so the Cooldown-margin wait below sits between them.
    before = _START_COUNT
    for leg in ('leg 1', 'leg 2', 'leg 3'):
        if leg == 'leg 1':
            # A raw adjustment strictly inside (0, 1) must round AWAY from zero to +1.
            _drive(_THRESHOLD + 5.0, _QUIET_IN, want_out='ALARM', want_in='OK', leg=leg)
            adjustment = _percent_adjustment(before, _PCT)
            raw = before * _PCT / 100.0
            detail = (f'{_PCT}% of {before} is {raw}, strictly inside (0, 1), and AWS documents '
                      f'that such a value is rounded to 1 -- so the adjustment is +1. Truncation '
                      f'and round-to-nearest both give 0 and leave desiredCount at {before}')
        elif leg == 'leg 2':
            # The negative direction, with no magnitude floor.
            _drive(_QUIET_OUT, _THRESHOLD - 5.0, want_out='OK', want_in='ALARM', leg=leg)
            adjustment = _percent_adjustment(before, -_PCT)
            raw = before * -_PCT / 100.0
            detail = (f'-{_PCT}% of {before} is {raw}; a value in [-1, 0) rounds to -1, so the '
                      f'adjustment is -1 and this is a SCALE-IN. An implementation that truncates '
                      f'leaves desiredCount at {before}')
        else:
            # The same negative percentage, now with MinAdjustmentMagnitude. The floor applies to
            # the MAGNITUDE, so the sign must survive it.
            _put(in_policy, -_PCT, 0.0, None, magnitude=_MAGNITUDE)
            _drive(_QUIET_OUT, _THRESHOLD - 5.0, want_out='OK', want_in='ALARM', leg=leg)
            adjustment = _percent_adjustment(before, -_PCT, _MAGNITUDE)
            raw = before * -_PCT / 100.0
            detail = (f'-{_PCT}% of {before} is {raw}, which rounds to -1, and '
                      f'MinAdjustmentMagnitude {_MAGNITUDE} then floors the MAGNITUDE at '
                      f'{_MAGNITUDE}, so the adjustment is -{_MAGNITUDE}. An implementation written '
                      f'as max(adjustment, magnitude) produces +{_MAGNITUDE} and scales OUT to '
                      f'{before + _MAGNITUDE}; one that ignores the field answers {before - 1}')

        after = _apply(before, adjustment, leg=leg, detail=detail)

        if leg == 'leg 2':
            assert after < before, (
                f'{leg}: desiredCount went from {before} to {after}; a negative ScalingAdjustment '
                f'on a LessThanThreshold breach must scale IN'
            )
        if leg == 'leg 3':
            assert after == before - _MAGNITUDE, (
                f'{leg}: desiredCount went from {before} to {after}; MinAdjustmentMagnitude '
                f'{_MAGNITUDE} on a negative adjustment must remove exactly {_MAGNITUDE}, giving '
                f'{before - _MAGNITUDE}'
            )

        if leg != 'leg 3':
            # Return both alarms to OK, wait for RUNNING capacity (what AAS's own arithmetic reads
            # next) to converge to `after`, then wait out the target-wide
            # Cooldown before the next leg may drive an alarm.
            fired_at = time.monotonic()
            _quiesce(leg=f'{leg} (returning to OK)')
            _poll_until(
                lambda: _running_count(ecs, cluster, service), lambda r, a=after: r == a,
                timeout_s=_CONVERGE_S, interval_s=5.0,
                description=f'{leg}: ECS runningCount for {service!r} converging to the new '
                            f'desiredCount {after} before the next leg reads its baseline')
            remaining = (_COOLDOWN_S + _COOLDOWN_MARGIN_S) - (time.monotonic() - fired_at)
            if remaining > 0:
                time.sleep(remaining)

        before = after


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A resource in this
# VPC deletes asynchronously, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails
# with DependencyViolation while its ENIs remain: retry that code inside one shared window, then
# raise naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


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
