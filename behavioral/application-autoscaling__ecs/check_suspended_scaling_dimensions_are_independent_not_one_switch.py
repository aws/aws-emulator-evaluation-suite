"""suspended-scaling-dimensions-are-independent-not-one-switch."""
from __future__ import annotations

import base64
import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "suspended-scaling-dimensions-are-independent-not-one-switch"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling', 'ecs']

_NS = 'ecs'
_DIM = 'ecs:service:DesiredCount'
_METRIC_NAMESPACE = 'sim2real/behav/application-autoscaling'
_METRIC_NAME = 'SuspensionDriver'

_THRESHOLD = 50.0
_START_COUNT = 8
_MIN_CAPACITY = 1
_MAX_CAPACITY = 40
_OUT_ADJ = 3
_IN_ADJ = -3
#: The scheduled action changes only the BOUNDS, and brackets the capacity held at that moment, so
#: the scheduled leg cannot move capacity and cannot interfere with the dynamic legs.
_SCHEDULED_MIN = 2
_SCHEDULED_MAX = 30

_QUIET_OUT = _THRESHOLD - 20.0
_QUIET_IN = _THRESHOLD + 20.0
_ALARM_PERIOD_S = 10
#: A quiesce publish followed at once by a breach publish can land in the same evaluation bucket,
#: where Statistic=Maximum hides the breach; one full period between them keeps them separate.
_PERIOD_SEPARATION_S = 30.0
_TRANSITION_S = 90.0
_APPLY_S = 120.0
_SCHEDULE_LEAD_S = 150
_DISPATCH_S = 120.0
_HOLD_S = 60.0
_FREEZE_READS = 4
_FREEZE_INTERVAL_S = 15.0
#: Resuming scale-in with the alarm already in ALARM produces no activity; this window samples
#: that absence.
_RESUME_DEAD_WINDOW_S = 60.0

#: Real compute: step scaling's baseline for ecs:service:DesiredCount is runningCount, not
#: desiredCount, so the service needs container instances for runningCount to move.
_INSTANCE_TYPE = 't3.medium'
_INITIAL_STEADY_S = 240.0
_CONVERGE_S = 200.0
#: With Cooldown 0, one sustained ALARM can be retried and recomputed against the new capacity
#: and fire the same policy twice; a nonzero Cooldown bounds each leg to one fire.
_COOLDOWN_S = 90

#: The subject's suspensions. DynamicScalingOutSuspended is False BY CONSTRUCTION: leg 1 asserts the
#: scale-out still lands, which is the orthogonality claim, and setting it would confound that.
_SUBJECT_SUSPENSIONS = {
    'DynamicScalingInSuspended': True,
    'DynamicScalingOutSuspended': False,
    'ScheduledScalingSuspended': True,
}
_TWIN_SUSPENSIONS = {
    'DynamicScalingInSuspended': False,
    'DynamicScalingOutSuspended': False,
    'ScheduledScalingSuspended': False,
}


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
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') == 'InvalidInstanceID.NotFound':
            return
        raise
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            reservations = ec2.describe_instances(InstanceIds=[instance_id])['Reservations']
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'InvalidInstanceID.NotFound':
                return
            raise
        if not reservations or reservations[0]['Instances'][0]['State']['Name'] == 'terminated':
            return
        time.sleep(2)
    raise RuntimeError(f'instance {instance_id!r} did not reach terminated within 120s')


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
    """A minimal self-contained public VPC shared by both estates.

    The task's image pull needs internet egress, so the subnet routes to an Internet Gateway.
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


def _instance_profile(ctx, iam):
    """One IAM role/instance-profile, SHARED by both estates' EC2 container instances."""
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
    return iam.get_instance_profile(InstanceProfileName=role_name)['InstanceProfile']['Arn']


def _launch_container_instance(ctx, ec2, ssm, ecs, cluster, subnet_id, sg_id, profile_arn):
    """A real EC2 host registered to `cluster` so ECS can actually place tasks on it."""
    ami_id = ssm.get_parameter(
        Name='/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id'
    )['Parameter']['Value']

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


def _ecs_estate(ctx, ec2, ssm, ecs, subnet_id, sg_id, profile_arn, slug, desired):
    """A cluster, an EC2 container instance, a task definition and a service with `desired` tasks.

    The container instance lets runningCount converge to desiredCount, which step scaling uses as
    its baseline.
    """
    cluster = ctx.unique_name(f'sim2real-behav-aas-{slug}-cl-')
    service = ctx.unique_name(f'sim2real-behav-aas-{slug}-svc-')
    family = ctx.unique_name(f'sim2real-behav-aas-{slug}-td-')
    pairs = [{'key': 'sim2real', 'value': CHECK}, {'key': 'owner', 'value': 'sim2real-behav-aas'}]

    ecs.create_cluster(clusterName=cluster, tags=pairs)
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    _launch_container_instance(ctx, ec2, ssm, ecs, cluster, subnet_id, sg_id, profile_arn)
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
    """The terminal read, at the CONSUMER: ECS's own view of the service it was told to resize."""
    return _service_counts(ecs, cluster, service)[0]


def _running_count(ecs, cluster, service):
    """Application Auto Scaling's step-scaling baseline for this dimension."""
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


def _delete_action(aas, resource_id, action):
    try:
        aas.delete_scheduled_action(ServiceNamespace=_NS, ResourceId=resource_id,
                                    ScalableDimension=_DIM, ScheduledActionName=action)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _next_cron_minute(min_lead_s):
    """The next whole UTC minute at least ``min_lead_s`` away, as a ONE-SHOT cron expression.

    Explicit year and day-of-month, so the expression names a single instant and never a recurrence.
    Cron granularity here is one minute, so the wait is bounded by 60 + min_lead_s.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    fire = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    while (fire - now).total_seconds() < min_lead_s:
        fire += datetime.timedelta(minutes=1)
    return f'cron({fire.minute} {fire.hour} {fire.day} {fire.month} ? {fire.year})', fire


# timing:real-time — schedule: 150 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-suspend-resume-scaling.html
@tags('axis:negative-delivery', 'cap:c1', 'cap:c4', 'concern:e2e', 'concern:metrics',
      'plane:control', 'timing:real-time')
def run(ctx) -> None:
    """The three SuspendedState flags are independent: with scale-in and scheduled scaling suspended,
    scale-out still lands while scale-in and the scheduled action are withheld, and resuming replays
    neither; scale-in returns only on a fresh alarm transition, the past scheduled action never.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-suspend-resume-scaling.html
    """
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    ecs = ctx.client('ecs')
    ec2 = ctx.client('ec2')
    iam = ctx.client('iam')
    ssm = ctx.client('ssm')
    account = ctx.client('sts').get_caller_identity()['Account']

    subnet_id, sg_id = _network(ctx, ec2)
    profile_arn = _instance_profile(ctx, iam)

    estates = {}
    for role, slug in (('subject', 'suspsub'), ('twin', 'susptwin')):
        cluster, service, resource_id = _ecs_estate(
            ctx, ec2, ssm, ecs, subnet_id, sg_id, profile_arn, slug, _START_COUNT)
        estates[role] = {'cluster': cluster, 'service': service, 'resource_id': resource_id}
    for role, estate in estates.items():
        count = _poll_until(
            lambda e=estate: _desired_count(ecs, e['cluster'], e['service']),
            lambda c: c == _START_COUNT, timeout_s=90, interval_s=3.0,
            description=f'ECS reporting desiredCount {_START_COUNT} for the {role} service '
                        f'{estate["service"]!r} before anything scales it')
        assert count == _START_COUNT, (
            f'ECS reports desiredCount {count} for the {role} service {estate["service"]!r} in '
            f'region {ctx.region} of account {account}, expected {_START_COUNT}; the subject and '
            f'the twin must start identical or the twin is not a control'
        )
        running = _poll_until(
            lambda e=estate: _running_count(ecs, e['cluster'], e['service']),
            lambda r: r == _START_COUNT, timeout_s=_INITIAL_STEADY_S, interval_s=5.0,
            description=f'ECS reporting runningCount {_START_COUNT} for the {role} service '
                        f'{estate["service"]!r} once its real container instance has placed the '
                        f'initial tasks -- the baseline every dynamic leg below is arithmetic on')
        assert running == _START_COUNT, (
            f'ECS reports runningCount {running} for the {role} service {estate["service"]!r}, '
            f'expected {_START_COUNT} before any scaling policy fires; Application Auto Scaling '
            f'computes this dimension\'s current capacity from runningCount, not desiredCount'
        )

    def _bounds(estate):
        targets = aas.describe_scalable_targets(
            ServiceNamespace=_NS, ResourceIds=[estate['resource_id']],
            ScalableDimension=_DIM)['ScalableTargets']
        assert len(targets) == 1, (
            f'DescribeScalableTargets returned {len(targets)} targets for '
            f'{estate["resource_id"]!r}, expected exactly 1: {targets!r}'
        )
        return targets[0]

    schedule, fire_at = _next_cron_minute(_SCHEDULE_LEAD_S)
    for role, estate in estates.items():
        suspensions = _SUBJECT_SUSPENSIONS if role == 'subject' else _TWIN_SUSPENSIONS
        aas.register_scalable_target(
            ServiceNamespace=_NS, ResourceId=estate['resource_id'], ScalableDimension=_DIM,
            MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
            SuspendedState=dict(suspensions),
            Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas', 'role': role},
        )
        ctx.on_cleanup(lambda e=estate: _deregister(aas, e['resource_id']))
        held = _bounds(estate).get('SuspendedState', {})
        assert {k: held.get(k) for k in suspensions} == suspensions, (
            f'the {role} target reports SuspendedState {held!r}, expected {suspensions!r}; every '
            f'leg below attributes behaviour to those exact flags'
        )

        for name_slug, adjustment, lower, upper in (('out', _OUT_ADJ, 0.0, None),
                                                    ('in', _IN_ADJ, None, 0.0)):
            policy = ctx.unique_name(f'sim2real-behav-aas-{role[:3]}{name_slug}pol-')
            step = {'ScalingAdjustment': adjustment}
            if lower is not None:
                step['MetricIntervalLowerBound'] = lower
            if upper is not None:
                step['MetricIntervalUpperBound'] = upper
            put = aas.put_scaling_policy(
                ServiceNamespace=_NS, ResourceId=estate['resource_id'], ScalableDimension=_DIM,
                PolicyName=policy, PolicyType='StepScaling',
                StepScalingPolicyConfiguration={
                    'AdjustmentType': 'ChangeInCapacity', 'MetricAggregationType': 'Maximum',
                    # Cooldown 0 lets one sustained ALARM fire the same policy twice.
                    'Cooldown': _COOLDOWN_S,
                    'StepAdjustments': [step],
                },
            )
            ctx.on_cleanup(
                lambda e=estate, n=policy: _delete_policy(aas, e['resource_id'], n))
            alarm = ctx.unique_name(f'sim2real-behav-aas-{role[:3]}{name_slug}al-')
            cw.put_metric_alarm(
                AlarmName=alarm, AlarmDescription=f'sim2real {CHECK} {role} {name_slug}',
                Namespace=_METRIC_NAMESPACE, MetricName=_METRIC_NAME,
                Dimensions=[{'Name': 'ServiceName', 'Value': estate['service']},
                            {'Name': 'Leg', 'Value': name_slug}],
                Statistic='Maximum', Period=_ALARM_PERIOD_S, EvaluationPeriods=1,
                DatapointsToAlarm=1, Threshold=_THRESHOLD,
                ComparisonOperator=('GreaterThanThreshold' if name_slug == 'out'
                                    else 'LessThanThreshold'),
                TreatMissingData='notBreaching', AlarmActions=[put['PolicyARN']],
                Tags=[{'Key': 'sim2real', 'Value': CHECK},
                      {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
            )
            ctx.on_cleanup(lambda n=alarm: _delete_alarm(cw, n))
            wired = cw.describe_alarms(AlarmNames=[alarm])['MetricAlarms']
            assert len(wired) == 1 and wired[0]['AlarmActions'] == [put['PolicyARN']], (
                f'the {role} {name_slug} alarm {alarm!r} lists alarm actions '
                f'{[a.get("AlarmActions") for a in wired]!r}; it must point at exactly '
                f'{put["PolicyARN"]!r}'
            )
            estate[f'{name_slug}_alarm'] = alarm

        action = ctx.unique_name(f'sim2real-behav-aas-{role[:3]}sa-')
        aas.put_scheduled_action(
            ServiceNamespace=_NS, ResourceId=estate['resource_id'], ScalableDimension=_DIM,
            ScheduledActionName=action, Schedule=schedule, Timezone='UTC',
            ScalableTargetAction={'MinCapacity': _SCHEDULED_MIN, 'MaxCapacity': _SCHEDULED_MAX},
        )
        ctx.on_cleanup(lambda e=estate, n=action: _delete_action(aas, e['resource_id'], n))
        stored = aas.describe_scheduled_actions(
            ServiceNamespace=_NS, ResourceId=estate['resource_id'],
            ScheduledActionNames=[action])['ScheduledActions']
        assert len(stored) == 1 and stored[0]['Schedule'] == schedule, (
            f'the {role} scheduled action did not come back as one entry carrying {schedule!r}: '
            f'{stored!r}'
        )
        estate['action'] = action

    def _publish(estate, out_value, in_value):
        now = datetime.datetime.now(datetime.timezone.utc)
        cw.put_metric_data(
            Namespace=_METRIC_NAMESPACE,
            MetricData=[
                {'MetricName': _METRIC_NAME,
                 'Dimensions': [{'Name': 'ServiceName', 'Value': estate['service']},
                                {'Name': 'Leg', 'Value': leg}],
                 'Timestamp': now, 'Value': value, 'Unit': 'None', 'StorageResolution': 1}
                for leg, value in (('out', out_value), ('in', in_value))
            ],
        )

    def _drive_both(out_value, in_value, *, want_out, want_in, leg):
        """Move BOTH targets' metric streams to (out_value, in_value) for all four alarms.

        Publishes once, then only polls: CloudWatch re-invokes a step-scaling AlarmAction on every
        period the alarm reports ALARM, so republishing would compound one fire into several.
        """
        want = {(role, kind): state
                for role in estates for kind, state in (('out', want_out), ('in', want_in))}
        for estate in estates.values():
            _publish(estate, out_value, in_value)
        deadline = time.monotonic() + _TRANSITION_S
        last = None
        while time.monotonic() < deadline:
            last = {(role, kind): _alarm_state(cw, estates[role][f'{kind}_alarm'])
                    for role in estates for kind in ('out', 'in')}
            if last == want:
                return
            time.sleep(5.0)
        raise AssertionError(
            f'{leg}: the four alarms never reached {want!r} within {_TRANSITION_S}s of publishing '
            f'out={out_value} in={in_value} once against a threshold of {_THRESHOLD}; last saw '
            f'{last!r}')

    def _drive_one(estate, out_value, in_value, *, want_out, want_in, leg):
        """Single-estate variant of _drive_both -- same single-publish-then-poll shape."""
        want = {'out': want_out, 'in': want_in}
        _publish(estate, out_value, in_value)
        deadline = time.monotonic() + _TRANSITION_S
        last = None
        while time.monotonic() < deadline:
            last = {kind: _alarm_state(cw, estate[f'{kind}_alarm']) for kind in ('out', 'in')}
            if last == want:
                return
            time.sleep(5.0)
        raise AssertionError(
            f'{leg}: the alarms for {estate["service"]!r} never reached {want!r} within '
            f'{_TRANSITION_S}s of publishing out={out_value} in={in_value} once against a threshold '
            f'of {_THRESHOLD}; last saw {last!r}')

    # ---- Leg 1: a policy-driven SCALE-OUT must land on BOTH targets. The subject has
    # DynamicScalingInSuspended and ScheduledScalingSuspended set; neither may stop a scale-out.
    _drive_both(_THRESHOLD + 5.0, _QUIET_IN, want_out='ALARM', want_in='OK', leg='leg 1')
    after_out = {}
    for role, estate in estates.items():
        after_out[role] = _poll_until(
            lambda e=estate: _desired_count(ecs, e['cluster'], e['service']),
            lambda c: c != _START_COUNT, timeout_s=_APPLY_S, interval_s=3.0,
            description=f'leg 1: ECS desiredCount for the {role} service {estate["service"]!r} '
                        f'moving off {_START_COUNT} on a scale-out breach')
        assert after_out[role] == _START_COUNT + _OUT_ADJ, (
            f'leg 1: ECS reports desiredCount {after_out[role]} for the {role} service '
            f'{estate["service"]!r}, expected {_START_COUNT + _OUT_ADJ}. The subject carries '
            f'{_SUBJECT_SUSPENSIONS!r}; DynamicScalingInSuspended suspends scale-IN only and '
            f'ScheduledScalingSuspended suspends SCHEDULED actions only, so neither may withhold '
            f'this scale-out. An implementation with a single suspension boolean leaves '
            f'{_START_COUNT}'
        )
    assert after_out['subject'] == after_out['twin'], (
        f'leg 1: the subject reached {after_out["subject"]} and the twin {after_out["twin"]}; they '
        f'must be identical here or the twin is not a control for the later legs'
    )
    assert _SCHEDULED_MIN < after_out['subject'] < _SCHEDULED_MAX, (
        f'this check is misconfigured: capacity {after_out["subject"]} is not strictly inside the '
        f'scheduled action\'s bounds ({_SCHEDULED_MIN}, {_SCHEDULED_MAX}), so the scheduled fire '
        f'would move capacity and confound the dynamic legs'
    )
    # Step scaling's baseline is runningCount, so later legs need it caught up to `after_out`.
    for role, estate in estates.items():
        _poll_until(
            lambda e=estate, r=role: _running_count(ecs, e['cluster'], e['service']),
            lambda r, a=after_out[role]: r == a, timeout_s=_CONVERGE_S, interval_s=5.0,
            description=f'leg 1: ECS runningCount for the {role} service {estate["service"]!r} '
                        f'converging to the new desiredCount {after_out[role]} before the later '
                        f'legs read their baseline off it')

    # ---- Leg 2: the scheduled minute. The twin's bounds must be rewritten; the subject's must not.
    twin_after = _poll_until(
        lambda: _bounds(estates['twin']),
        lambda t: (t['MinCapacity'], t['MaxCapacity']) == (_SCHEDULED_MIN, _SCHEDULED_MAX),
        timeout_s=_DISPATCH_S + _SCHEDULE_LEAD_S + 60.0, interval_s=5.0,
        description=f'leg 2: the twin\'s scheduled action {estates["twin"]["action"]!r} firing at '
                    f'{fire_at.isoformat()} and rewriting its bounds to '
                    f'({_SCHEDULED_MIN}, {_SCHEDULED_MAX})')
    assert (twin_after['MinCapacity'], twin_after['MaxCapacity']) == (
        _SCHEDULED_MIN, _SCHEDULED_MAX), (
        f'leg 2: the twin\'s bounds are '
        f'({twin_after["MinCapacity"]}, {twin_after["MaxCapacity"]}) after its scheduled action '
        f'fired, expected ({_SCHEDULED_MIN}, {_SCHEDULED_MAX})'
    )
    subject_bounds = _bounds(estates['subject'])
    assert (subject_bounds['MinCapacity'], subject_bounds['MaxCapacity']) == (
        _MIN_CAPACITY, _MAX_CAPACITY), (
        f'leg 2: the subject\'s bounds are '
        f'({subject_bounds["MinCapacity"]}, {subject_bounds["MaxCapacity"]}) at '
        f'{datetime.datetime.now(datetime.timezone.utc).isoformat()}, after its scheduled minute '
        f'{fire_at.isoformat()} passed. ScheduledScalingSuspended is True on the subject, so the '
        f'action must have been WITHHELD, leaving ({_MIN_CAPACITY}, {_MAX_CAPACITY}); the twin '
        f'proves the scheduler ran in that very minute'
    )
    subject_now = _desired_count(
        ecs, estates['subject']['cluster'], estates['subject']['service'])
    assert subject_now == after_out['subject'], (
        f'leg 2: the subject\'s desiredCount moved from {after_out["subject"]} to {subject_now} '
        f'across the scheduled minute; a withheld scheduled action must move nothing'
    )

    # ---- Leg 3: a policy-driven SCALE-IN. The twin scales in; the subject must not.
    _drive_both(_QUIET_OUT, _QUIET_IN, want_out='OK', want_in='OK', leg='leg 3 (returning to OK)')
    # Wait out one evaluation period before the next breach publish (see _PERIOD_SEPARATION_S).
    separation_deadline = time.monotonic() + _PERIOD_SEPARATION_S
    while time.monotonic() < separation_deadline:
        held = {role: _alarm_state(cw, estates[role]['in_alarm']) for role in estates}
        assert set(held.values()) == {'OK'}, (
            f'leg 3: the in-alarms read {held!r} while waiting out one evaluation period after '
            f'returning to OK; the next breach publish below depends on this holding steady, or '
            f'CloudWatch could aggregate it together with a leftover datapoint from this quiesce'
        )
        time.sleep(5.0)
    _drive_both(_QUIET_OUT, _THRESHOLD - 5.0, want_out='OK', want_in='ALARM', leg='leg 3')
    twin_in = _poll_until(
        lambda: _desired_count(ecs, estates['twin']['cluster'], estates['twin']['service']),
        lambda c: c != after_out['twin'], timeout_s=_APPLY_S, interval_s=3.0,
        description=f'leg 3: ECS desiredCount for the twin service '
                    f'{estates["twin"]["service"]!r} moving off {after_out["twin"]} on a scale-in '
                    f'breach -- the twin has no suspensions, so this is the positive control that '
                    f'the wiring delivers')
    assert twin_in == after_out['twin'] + _IN_ADJ, (
        f'leg 3: the twin reached desiredCount {twin_in}, expected '
        f'{after_out["twin"] + _IN_ADJ}; without a working positive control the subject\'s absence '
        f'below proves nothing'
    )
    deadline = time.monotonic() + _HOLD_S
    while time.monotonic() < deadline:
        assert _alarm_state(cw, estates['subject']['in_alarm']) == 'ALARM', (
            f'leg 3: the subject\'s scale-in alarm '
            f'{estates["subject"]["in_alarm"]!r} left ALARM during the absence window, so an '
            f'unchanged capacity would prove nothing about DynamicScalingInSuspended'
        )
        held = _desired_count(
            ecs, estates['subject']['cluster'], estates['subject']['service'])
        assert held == after_out['subject'], (
            f'leg 3: the subject reports desiredCount {held}, expected still '
            f'{after_out["subject"]}. DynamicScalingInSuspended is True, so the scale-in the twin '
            f'just performed must be withheld -- and DynamicScalingOutSuspended being False does '
            f'not license it'
        )
        time.sleep(5.0)
    withheld_view = _activities(aas, estates['subject']['resource_id'])
    print(f'[MEASURE] subject activities while DynamicScalingInSuspended withholds a scale-in, '
          f'IncludeNotScaledActivities=True: '
          f'{[(a.get("StatusCode"), a.get("Description"), a.get("NotScaledReasons")) for a in withheld_view]!r}')
    assert not [a for a in withheld_view
                if a.get('StatusCode') == 'Successful'
                and a.get('Description') == f'Setting desired count to '
                                            f'{after_out["subject"] + _IN_ADJ}.'], (
        f'leg 3: the subject has a SUCCESSFUL activity setting desired count to '
        f'{after_out["subject"] + _IN_ADJ} while DynamicScalingInSuspended is True: '
        f'{[a.get("Description") for a in withheld_view]!r}'
    )

    # ---- Leg 4: lift BOTH flags in one call. Neither resume replays a withheld action.
    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=estates['subject']['resource_id'],
        ScalableDimension=_DIM,
        SuspendedState={'DynamicScalingInSuspended': False, 'ScheduledScalingSuspended': False})
    resumed = _poll_until(
        lambda: _bounds(estates['subject']).get('SuspendedState', {}),
        lambda s: s.get('DynamicScalingInSuspended') is False
        and s.get('ScheduledScalingSuspended') is False,
        timeout_s=60, interval_s=3.0,
        description='leg 4: DescribeScalableTargets reporting both flags lifted on the subject')
    assert resumed.get('DynamicScalingOutSuspended') is False, (
        f'leg 4: the subject reports SuspendedState {resumed!r}; the resume call named two flags '
        f'and must not have disturbed the third'
    )

    # 4a: resuming does not replay an invocation CloudWatch sent while suspended; first a dead
    # window with no new activity, then a fresh OK->ALARM transition that must deliver.
    assert _alarm_state(cw, estates['subject']['in_alarm']) == 'ALARM', (
        f'leg 4a: the subject\'s scale-in alarm {estates["subject"]["in_alarm"]!r} is not in ALARM '
        f'at the resume, so there is no pre-existing breach for the dead-window check below to mean '
        f'anything'
    )
    baseline_activities = _activities(aas, estates['subject']['resource_id'])
    dead_window_deadline = time.monotonic() + _RESUME_DEAD_WINDOW_S
    while time.monotonic() < dead_window_deadline:
        held = _desired_count(ecs, estates['subject']['cluster'], estates['subject']['service'])
        assert held == after_out['subject'], (
            f'leg 4a: the subject reports desiredCount {held} within {_RESUME_DEAD_WINDOW_S:.0f}s '
            f'of resuming DynamicScalingInSuspended, expected still {after_out["subject"]}. The '
            f'alarm sat in the SAME ALARM state it was already in before the resume, with no fresh '
            f'transition -- an implementation that treats the resume CALL ITSELF as a trigger, or '
            f'that replays every withheld invocation on resume, scales here and would be wrong: '
            f'measured on real AWS, resuming does not retroactively replay a stale breach'
        )
        time.sleep(10.0)
    stale_activities = _activities(aas, estates['subject']['resource_id'])
    assert stale_activities == baseline_activities, (
        f'leg 4a: DescribeScalingActivities gained {len(stale_activities) - len(baseline_activities)} '
        f'entr{"y" if len(stale_activities) - len(baseline_activities) == 1 else "ies"} within '
        f'{_RESUME_DEAD_WINDOW_S:.0f}s of resuming, with no fresh alarm transition: '
        f'{[a.get("Description") for a in stale_activities]!r}. Resume must not itself generate an '
        f'activity -- successful OR not-scaled -- against a breach it did not freshly observe'
    )

    # Only the subject needs a fresh transition after the resume.
    _drive_one(estates['subject'], _QUIET_OUT, _QUIET_IN, want_out='OK', want_in='OK',
               leg='leg 4a (re-quiesce before a fresh transition)')
    # Wait out one evaluation period before the fresh breach publish, as in leg 3.
    separation_deadline_4a = time.monotonic() + _PERIOD_SEPARATION_S
    while time.monotonic() < separation_deadline_4a:
        held_state = _alarm_state(cw, estates['subject']['in_alarm'])
        assert held_state == 'OK', (
            f'leg 4a: the subject\'s in-alarm read {held_state!r} while waiting out one evaluation '
            f'period after re-quiescing, expected still \'OK\'; the fresh breach publish below '
            f'depends on this holding steady'
        )
        time.sleep(5.0)
    _drive_one(estates['subject'], _QUIET_OUT, _THRESHOLD - 5.0, want_out='OK', want_in='ALARM',
               leg='leg 4a (fresh breach after resume)')
    subject_in = _poll_until(
        lambda: _desired_count(
            ecs, estates['subject']['cluster'], estates['subject']['service']),
        lambda c: c != after_out['subject'], timeout_s=_APPLY_S, interval_s=3.0,
        description=f'leg 4a: ECS desiredCount for the subject service '
                    f'{estates["subject"]["service"]!r} moving off {after_out["subject"]} once a '
                    f'FRESH OK->ALARM transition occurs on the resumed target')
    assert subject_in == after_out['subject'] + _IN_ADJ, (
        f'leg 4a: the subject reached desiredCount {subject_in}, expected '
        f'{after_out["subject"] + _IN_ADJ}. A fresh transition on the resumed target must deliver '
        f'the adjustment -- if it does not, the resume call disabled scale-in permanently rather '
        f'than just declining to replay history'
    )

    # 4b: the withheld SCHEDULED action must NOT run, because its instant has passed.
    readings = []
    for _ in range(_FREEZE_READS):
        time.sleep(_FREEZE_INTERVAL_S)
        bounds = _bounds(estates['subject'])
        readings.append((bounds['MinCapacity'], bounds['MaxCapacity']))
    assert set(readings) == {(_MIN_CAPACITY, _MAX_CAPACITY)}, (
        f'leg 4b: the subject\'s bounds read {readings!r} over the '
        f'{_FREEZE_READS * _FREEZE_INTERVAL_S:.0f}s after ScheduledScalingSuspended was lifted. '
        f'The action\'s instant {fire_at.isoformat()} is in the past, and resuming scheduled '
        f'scaling "only evaluates scheduled actions whose execution time has not yet passed", so '
        f'the bounds must stay ({_MIN_CAPACITY}, {_MAX_CAPACITY}). An implementation that replays '
        f'withheld actions on resume answers ({_SCHEDULED_MIN}, {_SCHEDULED_MAX}) -- which in '
        f'production is a fleet resized to last night\'s schedule. Leg 4a proves the resume '
        f'machinery on this target works, so this absence is the scheduled rule and not a dead '
        f'resume'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)


# Async deletes inside the VPC leave ENIs behind for a while, so DeleteSubnet / DeleteSecurityGroup /
# DeleteVpc fail with DependencyViolation; retry within a bounded window, then raise naming the ENIs.
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
