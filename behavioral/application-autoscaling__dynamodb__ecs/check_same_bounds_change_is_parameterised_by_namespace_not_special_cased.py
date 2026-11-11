"""same-bounds-change-is-parameterised-by-namespace-not-special-cased."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "same-bounds-change-is-parameterised-by-namespace-not-special-cased"
GROUP = 'scaling-activities'
SERVICES = ['application-autoscaling', 'dynamodb', 'ecs']

_DDB_NS = 'dynamodb'
_DDB_DIM = 'dynamodb:table:ReadCapacityUnits'
_ECS_NS = 'ecs'
_ECS_DIM = 'ecs:service:DesiredCount'

_START = 1
_MIN_CAPACITY = 1
_MAX_CAPACITY = 20
_FLOOR = 5
_TARGET_VALUE = 70.0

#: DescribeScalingPolicies echoes the literal cooldown that was sent, not the per-namespace default
#: the docs describe (300 for ecs, 0 for dynamodb): an unset cooldown reads back 0 on BOTH.
_ECHOED_COOLDOWN_WHEN_UNSET = 0
_PREDEFINED = {_DDB_NS: 'DynamoDBReadCapacityUtilization',
               _ECS_NS: 'ECSServiceAverageCPUUtilization'}
_SLR_NAME = {_DDB_NS: 'AWSServiceRoleForApplicationAutoScaling_DynamoDBTable',
             _ECS_NS: 'AWSServiceRoleForApplicationAutoScaling_ECSService'}
_SLR_PRINCIPAL = {_DDB_NS: 'dynamodb.application-autoscaling.amazonaws.com',
                  _ECS_NS: 'ecs.application-autoscaling.amazonaws.com'}
_NOUN = {_DDB_NS: 'read capacity units', _ECS_NS: 'desired count'}

#: A bump from 1 to 5 Fargate tasks needs real image-pull-and-start time on top of the deployment
#: settling.
_APPLY_S = 180.0

#: The additive worst case of the six sequential waits; never waited on itself.
_WORST_CASE_BUDGET_S = 120.0 + 90.0 + 180.0 + 180.0 + 180.0 + 180.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=4.0, description='condition'):
    """Bounded retry with a deadline that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _delete_table(ddb, name):
    for _ in range(8):
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException':
                raise RuntimeError(f'table {name!r} not deleted: {code}') from exc
            time.sleep(6)
    raise RuntimeError(f'table {name!r} still ResourceInUseException after retries')


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
    """DeleteCluster fails while a service is draining (ClusterContainsServicesException) or a task
    is stopping (ClusterContainsTasksException); retry both every 2s for up to 120s of the
    cleanup budget, then say so out loud."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ClusterNotFoundException':
                return
            if code not in ('ClusterContainsServicesException', 'ClusterContainsTasksException'):
                raise RuntimeError(f'cluster {cluster!r} not deleted: {code}') from exc
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
    raise RuntimeError(
        f'cluster {cluster!r} still contains a draining service or task after retries'
    )


def _deregister_task_definition(ecs, arn):
    try:
        _retire_task_definition(ecs, arn)
    except ClientError as exc:
        raise RuntimeError(f'task definition {arn!r} not deregistered: '
                           f'{exc.response.get("Error", {}).get("Code")}') from exc


def _delete_execution_role(iam, role_name, policy_arn):
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


def _delete_vpc_network(ec2, vpc_id, subnet_id, igw_id, rt_id):
    """Delete the network bottom-up; _delete_net waits out the ENI a just-stopped Fargate task
    leaves behind. Only a resource that is already gone counts as clean."""
    steps = [
        ('delete_subnet', {'SubnetId': subnet_id}, ('InvalidSubnetID.NotFound',)),
        ('delete_route_table', {'RouteTableId': rt_id}, ('InvalidRouteTableID.NotFound',)),
        ('detach_internet_gateway', {'InternetGatewayId': igw_id, 'VpcId': vpc_id},
         ('InvalidInternetGatewayID.NotFound', 'Gateway.NotAttached')),
        ('delete_internet_gateway', {'InternetGatewayId': igw_id},
         ('InvalidInternetGatewayID.NotFound',)),
        ('delete_vpc', {'VpcId': vpc_id}, ('InvalidVpcID.NotFound',)),
    ]
    for op, ident, gone in steps:
        try:
            _delete_net(ec2, op, **ident)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') not in gone:
                raise


def _deregister(aas, namespace, dimension, resource_id):
    try:
        aas.deregister_scalable_target(ServiceNamespace=namespace, ResourceId=resource_id,
                                       ScalableDimension=dimension)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _delete_policy(aas, namespace, dimension, resource_id, policy):
    try:
        aas.delete_scaling_policy(ServiceNamespace=namespace, ResourceId=resource_id,
                                  ScalableDimension=dimension, PolicyName=policy)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _activities(aas, namespace, dimension, resource_id):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': namespace, 'ResourceId': resource_id,
                  'ScalableDimension': dimension, 'IncludeNotScaledActivities': True}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _terminal(activity):
    return activity['StatusCode'] in ('Successful', 'Failed', 'Overridden', 'Unfulfilled')


@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'cap:c5', 'concern:e2e', 'concern:representation',
      'plane:control')
def run(ctx) -> None:
    """Raising MinCapacity on a DynamoDB table and an ECS service yields one activity each with
    identical engine-level fields (Cause, StatusCode) and per-namespace noun, fulfilling service and
    service-linked role; an unset cooldown echoes 0 on both; both consumers reach the floor.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scaling-activities.html
    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/target-tracking-scaling-policy-overview.html
    """
    aas = ctx.client('application-autoscaling')
    ddb = ctx.client('dynamodb')
    ecs = ctx.client('ecs')
    ec2 = ctx.client('ec2')
    iam = ctx.client('iam')
    identity = ctx.client('sts').get_caller_identity()
    account, partition = identity['Account'], identity['Arn'].split(':')[1]

    table = ctx.unique_name('sim2real-behav-aas-xns-tbl-')
    cluster = ctx.unique_name('sim2real-behav-aas-xns-cl-')
    service = ctx.unique_name('sim2real-behav-aas-xns-svc-')
    family = ctx.unique_name('sim2real-behav-aas-xns-td-')
    role_name = ctx.unique_name('sim2real-behav-aas-xns-role-')
    tag_pairs = [{'Key': 'sim2real', 'Value': CHECK}, {'Key': 'owner', 'Value': 'sim2real-behav-aas'}]
    ecs_pairs = [{'key': 'sim2real', 'value': CHECK},
                 {'key': 'owner', 'value': 'sim2real-behav-aas'}]

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': _START, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK},
              {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))

    # Fargate/awsvpc in a VPC this check owns: on a zero-container-instance EC2 cluster the ECS
    # ScalingActivity stays InProgress forever, because no task is ever placed.
    vpc_id = ec2.create_vpc(
        CidrBlock='10.99.0.0/24',
        TagSpecifications=[{'ResourceType': 'vpc', 'Tags': tag_pairs}],
    )['Vpc']['VpcId']
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock='10.99.0.0/25',
        TagSpecifications=[{'ResourceType': 'subnet', 'Tags': tag_pairs}],
    )['Subnet']['SubnetId']
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{'ResourceType': 'internet-gateway', 'Tags': tag_pairs}],
    )['InternetGateway']['InternetGatewayId']
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[{'ResourceType': 'route-table', 'Tags': tag_pairs}],
    )['RouteTable']['RouteTableId']
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock='0.0.0.0/0', GatewayId=igw_id)
    ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={'Value': True})
    ctx.on_cleanup(lambda: _delete_vpc_network(ec2, vpc_id, subnet_id, igw_id, rt_id))
    # The VPC's auto-created default security group already allows all egress, which is all a
    # Fargate task pulling a public image over the internet gateway above needs; it is deleted
    # implicitly with the VPC, so it carries no cleanup of its own.
    sg_id = ec2.describe_security_groups(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'group-name', 'Values': ['default']}],
    )['SecurityGroups'][0]['GroupId']

    exec_policy_arn = 'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
    trust = {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
         'Action': 'sts:AssumeRole'}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                                Tags=tag_pairs)['Role']['Arn']
    iam.attach_role_policy(RoleName=role_name, PolicyArn=exec_policy_arn)
    ctx.on_cleanup(lambda: _delete_execution_role(iam, role_name, exec_policy_arn))
    # No flat sleep for IAM/STS propagation: ECS's own deployment retries a task that briefly fails
    # to assume a not-yet-propagated role, and the bounded polls below absorb it.

    ecs.create_cluster(clusterName=cluster, tags=ecs_pairs)
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    task_def = ecs.register_task_definition(
        family=family, networkMode='awsvpc', requiresCompatibilities=['FARGATE'],
        cpu='256', memory='512', executionRoleArn=role_arn,
        containerDefinitions=[{
            'name': 'sim2real-idle',
            'image': 'public.ecr.aws/docker/library/busybox:1.36',
            'essential': True, 'command': ['sh', '-c', 'sleep 3600'],
            # `sh -c 'sleep 3600'` runs as the container's PID 1 with no SIGTERM trap, and the
            # kernel does not apply a default disposition to an unhandled signal for PID 1 -- so
            # without this, ECS's stop would sit out the FULL default stopTimeout (30s) before
            # SIGKILL. 2 is Fargate's minimum.
            'stopTimeout': 2,
        }],
        tags=ecs_pairs,
    )['taskDefinition']['taskDefinitionArn']
    ctx.on_cleanup(lambda: _deregister_task_definition(ecs, task_def))
    ecs.create_service(cluster=cluster, serviceName=service, taskDefinition=task_def,
                       desiredCount=_START, launchType='FARGATE',
                       networkConfiguration={'awsvpcConfiguration': {
                           'subnets': [subnet_id], 'securityGroups': [sg_id],
                           'assignPublicIp': 'ENABLED'}},
                       tags=ecs_pairs)
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, service))

    arms = {
        _DDB_NS: {'dim': _DDB_DIM, 'resource_id': f'table/{table}'},
        _ECS_NS: {'dim': _ECS_DIM, 'resource_id': f'service/{cluster}/{service}'},
    }

    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {table!r} becoming ACTIVE')
    assert ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits'] == _START, (
        f'table {table!r} in region {ctx.region} of account {account} did not start at {_START} '
        f'read capacity unit(s)'
    )
    described = _poll_until(
        lambda: ecs.describe_services(cluster=cluster, services=[service])['services'],
        lambda s: len(s) == 1 and s[0]['desiredCount'] == _START, timeout_s=90, interval_s=3.0,
        description=f'ECS reporting desiredCount {_START} for {service!r} in cluster {cluster!r}')
    assert described[0]['desiredCount'] == _START, (
        f'ECS reports desiredCount {described[0]["desiredCount"]} for the freshly created service '
        f'{service!r}, expected {_START}; the two namespaces must start at the same capacity or the '
        f'comparison below is not like for like'
    )

    for namespace, arm in arms.items():
        aas.register_scalable_target(
            ServiceNamespace=namespace, ResourceId=arm['resource_id'],
            ScalableDimension=arm['dim'], MinCapacity=_MIN_CAPACITY, MaxCapacity=_MAX_CAPACITY,
            Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
        )
        ctx.on_cleanup(
            lambda ns=namespace, a=arm: _deregister(aas, ns, a['dim'], a['resource_id']))
        assert _activities(aas, namespace, arm['dim'], arm['resource_id']) == [], (
            f'the freshly registered {namespace} target {arm["resource_id"]!r} already has an '
            f'activity history; the one-activity-each arithmetic below would count activities this '
            f'check did not cause'
        )

        policy = ctx.unique_name(f'sim2real-behav-aas-xns-{namespace[:3]}pol-')
        aas.put_scaling_policy(
            ServiceNamespace=namespace, ResourceId=arm['resource_id'],
            ScalableDimension=arm['dim'], PolicyName=policy,
            PolicyType='TargetTrackingScaling',
            # NO cooldowns sent, deliberately: the per-namespace DEFAULT is the subject of leg 2.
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': _TARGET_VALUE,
                'PredefinedMetricSpecification': {
                    'PredefinedMetricType': _PREDEFINED[namespace],
                },
            },
        )
        ctx.on_cleanup(
            lambda ns=namespace, a=arm, n=policy: _delete_policy(
                aas, ns, a['dim'], a['resource_id'], n))
        arm['policy'] = policy

    # ---- Leg 1: the per-namespace SERVICE-LINKED ROLE selection, read off the target.
    roles = {}
    for namespace, arm in arms.items():
        targets = aas.describe_scalable_targets(
            ServiceNamespace=namespace, ResourceIds=[arm['resource_id']],
            ScalableDimension=arm['dim'])['ScalableTargets']
        assert len(targets) == 1, (
            f'DescribeScalableTargets returned {len(targets)} targets for the {namespace} arm '
            f'{arm["resource_id"]!r}: {targets!r}'
        )
        role_arn = targets[0]['RoleARN']
        roles[namespace] = role_arn
        expected_prefix = (f'arn:{partition}:iam::{account}:role/aws-service-role/'
                           f'{_SLR_PRINCIPAL[namespace]}/')
        assert role_arn == expected_prefix + _SLR_NAME[namespace], (
            f'the {namespace} target reports RoleARN {role_arn!r}, expected exactly '
            f'{expected_prefix + _SLR_NAME[namespace]!r}. The service-linked role is per NAMESPACE, '
            f'not per account: an implementation that formats one role name for every target gets '
            f'this wrong for every namespace but the one it was built from'
        )
    assert roles[_DDB_NS] != roles[_ECS_NS], (
        f'both namespaces report the same RoleARN {roles[_DDB_NS]!r}; dynamodb and ecs targets are '
        f'documented to use different service-linked roles under different service principals'
    )

    # ---- Leg 2: the cooldown ECHO is namespace-INDEPENDENT and literal: a policy created with no
    # cooldown reads back 0 for BOTH namespaces, even though ECS's documented default is 300s.
    cooldowns = {}
    for namespace, arm in arms.items():
        stored = aas.describe_scaling_policies(
            ServiceNamespace=namespace, ResourceId=arm['resource_id'],
            ScalableDimension=arm['dim'], PolicyNames=[arm['policy']])['ScalingPolicies']
        assert len(stored) == 1, (
            f'DescribeScalingPolicies returned {len(stored)} policies named {arm["policy"]!r} on '
            f'the {namespace} arm: {stored!r}'
        )
        config = stored[0]['TargetTrackingScalingPolicyConfiguration']
        assert config['PredefinedMetricSpecification']['PredefinedMetricType'] == (
            _PREDEFINED[namespace]), (
            f'the {namespace} policy tracks '
            f'{config["PredefinedMetricSpecification"].get("PredefinedMetricType")!r}, expected '
            f'{_PREDEFINED[namespace]!r}'
        )
        out_cooldown = config.get('ScaleOutCooldown', 0)
        in_cooldown = config.get('ScaleInCooldown', 0)
        cooldowns[namespace] = (out_cooldown, in_cooldown)
        assert out_cooldown == _ECHOED_COOLDOWN_WHEN_UNSET, (
            f'the {namespace} policy reports an effective ScaleOutCooldown of {out_cooldown} with '
            f'none specified, expected the literal echo {_ECHOED_COOLDOWN_WHEN_UNSET} -- MEASURED '
            f'on real AWS, DescribeScalingPolicies echoes what was SENT, not the namespace default '
            f'AWS documents (300 for ecs, 0 for dynamodb); a target that resolves the documented '
            f'default into this field diverges from real AWS'
        )
        assert in_cooldown == _ECHOED_COOLDOWN_WHEN_UNSET, (
            f'the {namespace} policy reports an effective ScaleInCooldown of {in_cooldown} with '
            f'none specified, expected the literal echo {_ECHOED_COOLDOWN_WHEN_UNSET}'
        )
    assert cooldowns[_DDB_NS] == cooldowns[_ECS_NS] == (
        _ECHOED_COOLDOWN_WHEN_UNSET, _ECHOED_COOLDOWN_WHEN_UNSET), (
        f'the two namespaces report different cooldown echoes with none configured: '
        f'{cooldowns!r}; MEASURED on real AWS both come back '
        f'({_ECHOED_COOLDOWN_WHEN_UNSET}, {_ECHOED_COOLDOWN_WHEN_UNSET}) regardless of the '
        f'documented per-namespace default, so a target that differentiates this field by '
        f'namespace is itself wrong'
    )

    # ---- Leg 3: the SAME cause on both arms, issued before either is polled so the two are as close
    # to simultaneous as this API allows.
    for namespace, arm in arms.items():
        aas.register_scalable_target(
            ServiceNamespace=namespace, ResourceId=arm['resource_id'],
            ScalableDimension=arm['dim'], MinCapacity=_FLOOR, MaxCapacity=_MAX_CAPACITY)

    records = {}
    for namespace, arm in arms.items():
        found = _poll_until(
            lambda ns=namespace, a=arm: _activities(aas, ns, a['dim'], a['resource_id']),
            lambda acts: len(acts) == 1 and _terminal(acts[0]),
            timeout_s=_APPLY_S, interval_s=4.0,
            description=f'the {namespace} arm recording exactly one terminal activity after its '
                        f'floor was raised to {_FLOOR}')
        assert len(found) == 1, (
            f'the {namespace} arm reports {len(found)} activities for one floor raise: '
            f'{[a.get("Description") for a in found]!r}'
        )
        records[namespace] = found[0]

    # Engine-level fields: IDENTICAL across namespaces.
    causes = {ns: r['Cause'] for ns, r in records.items()}
    assert set(causes.values()) == {f'minimum capacity was set to {_FLOOR}'}, (
        f'the two arms attribute the same cause differently: {causes!r}. Raising MinCapacity is an '
        f'engine-level act with no target service in it, so both must read '
        f'"minimum capacity was set to {_FLOOR}"'
    )
    for namespace, record in records.items():
        assert record['StatusCode'] == 'Successful', (
            f'the {namespace} activity finished {record["StatusCode"]!r}, expected "Successful"'
        )
        assert record['EndTime'] > record['StartTime'], (
            f'the {namespace} activity reports EndTime {record["EndTime"].isoformat()}, not after '
            f'its StartTime {record["StartTime"].isoformat()}'
        )
        assert record['ServiceNamespace'] == namespace, (
            f'the {namespace} activity carries ServiceNamespace '
            f'{record["ServiceNamespace"]!r}'
        )
        assert record['ScalableDimension'] == arms[namespace]['dim'], (
            f'the {namespace} activity carries ScalableDimension '
            f'{record["ScalableDimension"]!r}, expected {arms[namespace]["dim"]!r}'
        )
        assert record['ResourceId'] == arms[namespace]['resource_id'], (
            f'the {namespace} activity names resource {record["ResourceId"]!r}, expected '
            f'{arms[namespace]["resource_id"]!r}'
        )

    # Per-namespace fields: DIFFERENT, in exactly the documented way.
    for namespace, record in records.items():
        noun = _NOUN[namespace]
        assert record['Description'] == f'Setting {noun} to {_FLOOR}.', (
            f'the {namespace} activity described itself as {record["Description"]!r}, expected '
            f'"Setting {noun} to {_FLOOR}." -- the capacity noun is per namespace'
        )
        assert record['StatusMessage'] == (
            f'Successfully set {noun} to {_FLOOR}. Change successfully fulfilled by {namespace}.'
        ), (
            f'the {namespace} activity status message was {record["StatusMessage"]!r}, expected '
            f'"Successfully set {noun} to {_FLOOR}. Change successfully fulfilled by '
            f'{namespace}." -- the terminal wording names the service that fulfilled the change'
        )
    assert records[_DDB_NS]['Description'] != records[_ECS_NS]['Description'], (
        f'both arms described themselves as {records[_DDB_NS]["Description"]!r}; an engine with one '
        f'capacity noun writes "read capacity units" about a container count'
    )
    assert records[_DDB_NS]['StatusMessage'] != records[_ECS_NS]['StatusMessage'], (
        f'both arms reported the same StatusMessage {records[_DDB_NS]["StatusMessage"]!r}; the '
        f'fulfilling service name must differ'
    )

    # ---- Terminal reads, at BOTH consumers, through operations this check never used to mutate.
    throughput = _poll_until(
        lambda: ddb.describe_table(TableName=table)['Table']['ProvisionedThroughput'],
        lambda t: t['ReadCapacityUnits'] == _FLOOR, timeout_s=_APPLY_S, interval_s=4.0,
        description=f'DynamoDB reporting {_FLOOR} read capacity units for {table!r}')
    assert throughput['ReadCapacityUnits'] == _FLOOR, (
        f'DynamoDB reports {throughput["ReadCapacityUnits"]} read capacity units for {table!r}, '
        f'expected {_FLOOR}; the activity claims a fulfilled change DynamoDB does not show'
    )
    final = _poll_until(
        lambda: ecs.describe_services(cluster=cluster, services=[service])['services'],
        lambda s: len(s) == 1 and s[0]['desiredCount'] == _FLOOR, timeout_s=_APPLY_S,
        interval_s=4.0,
        description=f'ECS reporting desiredCount {_FLOOR} for {service!r}')
    assert final[0]['desiredCount'] == _FLOOR, (
        f'ECS reports desiredCount {final[0]["desiredCount"]} for {service!r}, expected {_FLOOR}; '
        f'the activity claims a fulfilled change ECS does not show'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)


# Network deletes wait (bounded) for AWS-managed ENIs to leave: a resource in this VPC deletes
# asynchronously, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with
# DependencyViolation. Retry inside the window, then raise naming the ENIs still attached.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
