"""step-scaling-three-adjustment-types-from-one-capacity."""
from __future__ import annotations

import base64
import datetime
import json
import math
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# "Current capacity" for ecs:service:DesiredCount is the service's runningCount, so the service
# runs on a real EC2 container instance and each leg waits for runningCount to converge.
#
# The three legs, arithmetic on the capacity ECS reports once each has settled:
#   leg 1  ChangeInCapacity        +_CHANGE_ADJ (5)  from 4 -> 9
#   leg 2  PercentChangeInCapacity  _PCT_ADJ   (50)% from 9 -> 9 + floor(4.5) = 13
#   leg 3  ExactCapacity            _EXACT_ADJ (20)  from 13 -> 20

CHECK = "step-scaling-three-adjustment-types-from-one-capacity"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling', 'ecs']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'AdjustmentTypeDriver'

_THRESHOLD = 50.0
_START_COUNT = 4
_MIN_CAPACITY = 1
#: 60 so that no WRONG answer in any leg is clamped -- a clamp would hide the divergence.
_MAX_CAPACITY = 60
_CHANGE_ADJ = 5
_PCT_ADJ = 50
_EXACT_ADJ = 20

_QUIET = _THRESHOLD - 20.0
_ALARM_PERIOD_S = 30
_TRANSITION_S = 120.0
_APPLY_S = 120.0
#: Bounds for an EC2 instance joining the cluster and runningCount catching up between legs.
_INSTANCE_TYPE = 't3.medium'
_INITIAL_STEADY_S = 240.0
_CONVERGE_S = 200.0
#: Above the ~70s window in which AAS re-evaluates one alarm against the same policy, so a leg
#: fires once. Cooldown is target-wide, so run() waits it out plus a margin before the next leg.
_COOLDOWN_S = 90
_COOLDOWN_MARGIN_S = 30

#: The three legs, in order. (slug, AdjustmentType, ScalingAdjustment).
_LEGS = (
    ('change', 'ChangeInCapacity', _CHANGE_ADJ),
    ('percent', 'PercentChangeInCapacity', _PCT_ADJ),
    ('exact', 'ExactCapacity', _EXACT_ADJ),
)


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


def _terminate_and_deregister(ec2, ecs, cluster, instance_id, ci_arn_holder):
    """Deregister the container instance, then terminate it even if the deregister raised."""
    ci_arn = ci_arn_holder.get('arn')
    try:
        if ci_arn:
            try:
                ecs.deregister_container_instance(cluster=cluster, containerInstance=ci_arn, force=True)
            except ClientError as exc:
                if exc.response.get('Error', {}).get('Code') != 'ClusterNotFoundException':
                    raise
    finally:
        _terminate_instance(ec2, instance_id)


def _terminate_instance(ec2, instance_id):
    # Run from a `finally:`: name the in-flight error so a teardown failure never hides it.
    found = sys.exc_info()[1]
    lead = f'{found!r}; ' if found else ''
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') == 'InvalidInstanceID.NotFound':
            return
        raise RuntimeError(f'{lead}instance {instance_id!r} not terminated: {exc}') from exc
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            reservations = ec2.describe_instances(InstanceIds=[instance_id])['Reservations']
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'InvalidInstanceID.NotFound':
                return
            raise RuntimeError(f'{lead}instance {instance_id!r} not described: {exc}') from exc
        if not reservations or reservations[0]['Instances'][0]['State']['Name'] == 'terminated':
            return
        time.sleep(2)
    raise RuntimeError(f'{lead}instance {instance_id!r} did not reach terminated within 120s')


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
    """A minimal self-contained public VPC.

    The task's public-ECR image pull needs internet egress, so the subnet routes to an IGW.
    """
    pairs = [{'Key': 'sim2real', 'Value': CHECK}, {'Key': 'owner', 'Value': 'sim2real-behav-aas'}]
    vpc_id = ec2.create_vpc(
        CidrBlock='10.94.0.0/16',
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
        VpcId=vpc_id, CidrBlock='10.94.1.0/24',
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


def _launch_container_instance(ctx, ec2, iam, ssm, ecs, cluster, subnet_id, sg_id):
    """A real EC2 host registered to `cluster` so ECS can actually place tasks on it."""
    ami_id = ssm.get_parameter(
        Name='/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id'
    )['Parameter']['Value']

    role_name = ctx.unique_name('sim2real-behav-aas-ecsrole-')[:64]
    trust = {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'},
    ]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role'
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name))
    profile_arn = iam.get_instance_profile(InstanceProfileName=role_name)['InstanceProfile']['Arn']

    user_data = f'#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n'
    encoded_user_data = base64.b64encode(user_data.encode()).decode()

    instance_id = None
    last_exc = None
    for _ in range(6):
        try:
            resp = ec2.run_instances(
                ImageId=ami_id, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
                IamInstanceProfile={'Arn': profile_arn}, SubnetId=subnet_id,
                SecurityGroupIds=[sg_id], UserData=encoded_user_data,
                TagSpecifications=[{'ResourceType': 'instance', 'Tags': [
                    {'Key': 'sim2real', 'Value': CHECK}, {'Key': 'owner', 'Value': 'sim2real-behav-aas'},
                ]}],
            )
            instance_id = resp['Instances'][0]['InstanceId']
            break
        except ClientError as exc:  # IAM instance-profile propagation lag surfaces as a ClientError
            last_exc = exc
            time.sleep(8)
    if instance_id is None:
        raise last_exc or RuntimeError('failed to launch the ECS container-instance host')
    ci_arn_holder: dict = {}
    ctx.on_cleanup(lambda: _terminate_and_deregister(ec2, ecs, cluster, instance_id, ci_arn_holder))

    def _find():
        arns = ecs.list_container_instances(cluster=cluster).get('containerInstanceArns', [])
        if not arns:
            return None
        described = ecs.describe_container_instances(
            cluster=cluster, containerInstances=arns)['containerInstances']
        for ci in described:
            if ci.get('ec2InstanceId') == instance_id:
                return ci
        return None

    ci = _poll_until(
        _find, lambda x: x is not None and x.get('status') == 'ACTIVE',
        timeout_s=_INITIAL_STEADY_S, interval_s=10.0,
        description=f'EC2 instance {instance_id!r} registering as an ACTIVE ECS container instance '
                    f'on cluster {cluster!r}')
    ci_arn_holder['arn'] = ci['containerInstanceArn']
    return ci


def _ecs_estate(ctx, ec2, iam, ssm, ecs, slug, desired):
    """A VPC, an EC2 container instance, a cluster, a task definition and a `desired`-task service.

    The instance has room for _MAX_CAPACITY tasks so runningCount can converge to desiredCount.
    """
    subnet_id, sg_id = _network(ctx, ec2)
    cluster = ctx.unique_name(f'sim2real-behav-aas-{slug}-cl-')
    pairs = [{'key': 'sim2real', 'value': CHECK}, {'key': 'owner', 'value': 'sim2real-behav-aas'}]
    ecs.create_cluster(clusterName=cluster, tags=pairs)
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    _launch_container_instance(ctx, ec2, iam, ssm, ecs, cluster, subnet_id, sg_id)

    service = ctx.unique_name(f'sim2real-behav-aas-{slug}-svc-')
    family = ctx.unique_name(f'sim2real-behav-aas-{slug}-td-')
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


def _service_counts(ecs, cluster, service):
    described = ecs.describe_services(cluster=cluster, services=[service])['services']
    assert len(described) == 1, (
        f'DescribeServices returned {len(described)} services for {service!r} in cluster '
        f'{cluster!r}, expected exactly 1: {described!r}'
    )
    return described[0]['desiredCount'], described[0]['runningCount']


def _desired_count(ecs, cluster, service):
    """ECS's own view of the service's desired count."""
    return _service_counts(ecs, cluster, service)[0]


def _running_count(ecs, cluster, service):
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


def _expected(before, adjustment_type, adjustment):
    """The documented scale-out arithmetic for each AdjustmentType."""
    if adjustment_type == 'ChangeInCapacity':
        return before + adjustment
    if adjustment_type == 'ExactCapacity':
        return adjustment
    raw = before * adjustment / 100.0
    return before + (math.floor(raw) if raw > 1.0 else 1)


def _rivals(before, adjustment_type, adjustment):
    """What the two OTHER readings of the same ScalingAdjustment would produce."""
    return {other: _expected(before, other, adjustment)
            for other in ('ChangeInCapacity', 'PercentChangeInCapacity', 'ExactCapacity')
            if other != adjustment_type}


# timing:real-time — cooldown: 90 s https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics', 'plane:control',
      'timing:real-time')
def run(ctx) -> None:
    """Alarm-driven step scaling applies each AdjustmentType's documented arithmetic to the ECS
    service's settled capacity: ChangeInCapacity adds, PercentChangeInCapacity adds a rounded-down
    percentage, ExactCapacity replaces; ECS DescribeServices reports each result.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    ec2 = ctx.client('ec2')
    iam = ctx.client('iam')
    ssm = ctx.client('ssm')
    account = ctx.client('sts').get_caller_identity()['Account']

    cluster, service, resource_id = _ecs_estate(ctx, ec2, iam, ssm, ecs, 'adj', _START_COUNT)
    initial = _poll_until(
        lambda: _desired_count(ecs, cluster, service), lambda c: c == _START_COUNT,
        timeout_s=90, interval_s=3.0,
        description=f'ECS reporting desiredCount {_START_COUNT} for {service!r} before anything '
                    f'scales it')
    assert initial == _START_COUNT, (
        f'ECS reports desiredCount {initial} for the freshly created service {service!r} in region '
        f'{ctx.region} of account {account}, expected {_START_COUNT}; every leg below is arithmetic '
        f'on the capacity ECS reports'
    )
    running = _poll_until(
        lambda: _running_count(ecs, cluster, service), lambda r: r == _START_COUNT,
        timeout_s=_INITIAL_STEADY_S, interval_s=5.0,
        description=f'ECS reporting runningCount {_START_COUNT} for {service!r} once its real '
                    f'container instance has placed the initial tasks -- the baseline every leg '
                    f'below is arithmetic on')
    assert running == _START_COUNT, (
        f'ECS reports runningCount {running} for {service!r}, expected {_START_COUNT} before any '
        f'scaling policy fires'
    )

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    alarms = {}
    for slug, adjustment_type, adjustment in _LEGS:
        policy = ctx.unique_name(f'sim2real-behav-aas-{slug}pol-')
        put = aas.put_scaling_policy(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyName=policy, PolicyType='StepScaling',
            StepScalingPolicyConfiguration={
                'AdjustmentType': adjustment_type,
                'MetricAggregationType': 'Maximum',
                # With Cooldown 0, a sustained alarm re-fires the policy against the new capacity.
                'Cooldown': _COOLDOWN_S,
                'StepAdjustments': [
                    {'MetricIntervalLowerBound': 0.0, 'ScalingAdjustment': adjustment},
                ],
            },
        )
        ctx.on_cleanup(lambda name=policy: _delete_policy(aas, resource_id, name))
        assert put.get('Alarms', []) == [], (
            f'PutScalingPolicy for the StepScaling policy {policy!r} returned alarms '
            f'{put.get("Alarms")!r}; step scaling requires the CALLER to supply the alarm, so '
            f'Application Auto Scaling must not mint one'
        )
        stored = aas.describe_scaling_policies(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyNames=[policy])['ScalingPolicies']
        assert len(stored) == 1, (
            f'DescribeScalingPolicies returned {len(stored)} policies named {policy!r}: {stored!r}'
        )
        config = stored[0]['StepScalingPolicyConfiguration']
        assert config['AdjustmentType'] == adjustment_type, (
            f'the stored policy {policy!r} reports AdjustmentType '
            f'{config.get("AdjustmentType")!r}, expected {adjustment_type!r}; the arithmetic below '
            f'cannot be attributed to an enum value the target did not keep'
        )
        assert config['StepAdjustments'][0]['ScalingAdjustment'] == adjustment, (
            f'the stored policy {policy!r} reports step adjustments '
            f'{config["StepAdjustments"]!r}, expected a single ScalingAdjustment {adjustment}'
        )

        alarm = ctx.unique_name(f'sim2real-behav-aas-{slug}al-')
        cw.put_metric_alarm(
            AlarmName=alarm, AlarmDescription=f'sim2real {CHECK} {slug}',
            Namespace=_METRIC_NAMESPACE, MetricName=_METRIC_NAME,
            Dimensions=[{'Name': 'ServiceName', 'Value': service},
                        {'Name': 'Leg', 'Value': slug}],
            Statistic='Maximum', Period=_ALARM_PERIOD_S, EvaluationPeriods=1, DatapointsToAlarm=1,
            Threshold=_THRESHOLD, ComparisonOperator='GreaterThanThreshold',
            TreatMissingData='notBreaching', AlarmActions=[put['PolicyARN']],
            Tags=[{'Key': 'sim2real', 'Value': CHECK},
                  {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
        )
        ctx.on_cleanup(lambda name=alarm: _delete_alarm(cw, name))
        wired = cw.describe_alarms(AlarmNames=[alarm])['MetricAlarms']
        assert len(wired) == 1 and wired[0]['AlarmActions'] == [put['PolicyARN']], (
            f'the alarm {alarm!r} lists alarm actions '
            f'{[a.get("AlarmActions") for a in wired]!r}; it must point at exactly the '
            f'{adjustment_type} policy {put["PolicyARN"]!r} or this leg reaches nothing'
        )
        alarms[slug] = alarm

    def _publish(values):
        now = datetime.datetime.now(datetime.timezone.utc)
        cw.put_metric_data(
            Namespace=_METRIC_NAMESPACE,
            MetricData=[
                {'MetricName': _METRIC_NAME,
                 'Dimensions': [{'Name': 'ServiceName', 'Value': service},
                                {'Name': 'Leg', 'Value': slug}],
                 'Timestamp': now, 'Value': value, 'Unit': 'None', 'StorageResolution': 1}
                for slug, value in values.items()
            ],
        )

    def _drive(hot, *, leg):
        """Breach exactly the `hot` stream and hold the other two in OK. Bounded; raises.

        Publishes the breaching datapoint once, then only polls, so no second breach is sent.
        """
        want = {slug: ('ALARM' if slug == hot else 'OK') for slug in alarms}
        values = {slug: (_THRESHOLD + 5.0 if slug == hot else _QUIET) for slug in alarms}
        _publish(values)
        deadline = time.monotonic() + _TRANSITION_S
        last = None
        while time.monotonic() < deadline:
            last = {slug: _alarm_state(cw, name) for slug, name in alarms.items()}
            if last == want:
                return
            time.sleep(10.0)
        raise AssertionError(
            f'{leg}: alarm states never reached {want!r} within {_TRANSITION_S}s of publishing '
            f'{values!r} once against a threshold of {_THRESHOLD}; last saw {last!r}')

    def _quiesce(*, leg):
        deadline = time.monotonic() + _TRANSITION_S
        last = None
        while time.monotonic() < deadline:
            _publish({slug: _QUIET for slug in alarms})
            last = {slug: _alarm_state(cw, name) for slug, name in alarms.items()}
            if set(last.values()) == {'OK'}:
                return
            time.sleep(10.0)
        raise AssertionError(
            f'{leg}: not every alarm returned to OK within {_TRANSITION_S}s of publishing '
            f'{_QUIET} against a threshold of {_THRESHOLD}; last saw {last!r}. CloudWatch invokes '
            f'an alarm action only on a state TRANSITION, so the next leg cannot fire until this '
            f'one is back in OK')

    before = _START_COUNT
    for index, (slug, adjustment_type, adjustment) in enumerate(_LEGS, start=1):
        leg = f'leg {index} ({adjustment_type})'
        _drive(slug, leg=leg)
        want = _expected(before, adjustment_type, adjustment)
        assert want != before, (
            f'{leg} is misconfigured: {adjustment_type} {adjustment} applied to {before} yields '
            f'{want}, so nothing would move and the poll below could not distinguish a correct '
            f'target from an inert one'
        )
        after = _poll_until(
            lambda: _desired_count(ecs, cluster, service), lambda c, b=before: c != b,
            timeout_s=_APPLY_S, interval_s=4.0,
            description=f'{leg}: ECS desiredCount for {service!r} moving off {before} after the '
                        f'{adjustment_type} policy fired')
        _quiesce(leg=f'{leg} (returning to OK)')
        rivals = _rivals(before, adjustment_type, adjustment)
        assert after == want, (
            f'{leg}: ECS reports desiredCount {after} for {service!r}. {adjustment_type} with '
            f'ScalingAdjustment {adjustment} applied to {before} is {want}. Reading the same '
            f'ScalingAdjustment under the other two adjustment types gives '
            f'{rivals!r}'
        )
        # The newest activity can be a redundant re-fire while the alarm stays in ALARM, so find
        # the activity that produced `after`.
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
            f'({_MIN_CAPACITY}, {_MAX_CAPACITY}); no leg here may be explained by a clamp, and no '
            f'rival answer may be clamped into agreement with the right one'
        )
        fired_at = time.monotonic()
        if index < len(_LEGS):
            # AAS reads runningCount as current capacity, so it must reach `after` first.
            _poll_until(
                lambda: _running_count(ecs, cluster, service), lambda r, a=after: r == a,
                timeout_s=_CONVERGE_S, interval_s=5.0,
                description=f'{leg}: ECS runningCount for {service!r} converging to the new '
                            f'desiredCount {after} before the next leg reads its baseline')
            # Cooldown blocks every policy on the scalable target, so wait it out explicitly.
            remaining = (_COOLDOWN_S + _COOLDOWN_MARGIN_S) - (time.monotonic() - fired_at)
            if remaining > 0:
                time.sleep(remaining)
        before = after


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)


# Network teardown waits for AWS-managed ENIs to leave, since resources in the VPC delete
# asynchronously and an immediate delete fails with DependencyViolation. Bounded; raises naming
# the ENIs still attached. One window is shared by all of a check's network deletes.
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
    """Deregister a task definition revision, then delete it.

    A deregistered revision stays INACTIVE until DeleteTaskDefinitions removes it.
    """
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
