"""create-ecs-deployment-group-rejects-service-without-codedeploy-controller."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-ecs-deployment-group-rejects-service-without-codedeploy-controller"
GROUP = "ecs-blue-green-cutover"
SERVICES = ["codedeploy", "ec2", "ecs", "elbv2", "iam"]

_CONTAINER_NAME = "web"
_CONTAINER_PORT = 8080
_WRONG_CONTROLLER_ERROR = (
    "InvalidECSServiceException",
    "Deployment group's ECS service must be configured for a CODE_DEPLOY deployment controller.",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeploymentGroup for an ECS BLUE_GREEN application rejects an Amazon ECS service
    that was not created with the CODE_DEPLOY deployment controller, and creates no group; the
    same request naming a service created with that controller succeeds.
    """
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")
    elbv2 = ctx.client("elbv2")
    iam = ctx.client("iam")
    codedeploy = ctx.client("codedeploy")

    vpc_id, subnet_ids, sg_id = _provision_network(ctx, ec2)
    cluster_name = _provision_cluster(ctx, ecs)
    task_def_arn = _register_idle_task_definition(ctx, ecs)
    origin_tg_name, origin_tg_arn, standby_tg_name, standby_tg_arn = _provision_target_groups(
        ctx, elbv2, vpc_id
    )
    listener_arn = _provision_load_balancer(ctx, elbv2, subnet_ids, sg_id, origin_tg_arn)
    role_arn = _provision_codedeploy_role(ctx, iam)

    rolling_service_name = _provision_idle_service(
        ctx, ecs, cluster_name, task_def_arn, subnet_ids, sg_id, origin_tg_arn,
        controller="ECS",
    )
    bad_application = _provision_application(ctx, codedeploy)
    pair = _error_pair(lambda: _create_ecs_deployment_group(
        codedeploy, bad_application, role_arn, ctx.unique_name("sim2real-xsvc-dg-"),
        cluster=cluster_name, service_name=rolling_service_name,
        origin_tg_name=origin_tg_name, standby_tg_name=standby_tg_name, listener_arn=listener_arn,
    ))
    assert pair == _WRONG_CONTROLLER_ERROR, (
        f"creating a BLUE_GREEN deployment group for an ECS service whose deploymentController "
        f"is not CODE_DEPLOY must be rejected with {_WRONG_CONTROLLER_ERROR!r}, got {pair!r}"
    )
    listed = codedeploy.list_deployment_groups(applicationName=bad_application)["deploymentGroups"]
    assert listed == [], f"the rejected deployment group must not exist, got {listed!r}"

    # Positive control: the identical request against a service created with the CODE_DEPLOY
    # deployment controller succeeds.
    codedeploy_service_name = _provision_idle_service(
        ctx, ecs, cluster_name, task_def_arn, subnet_ids, sg_id, origin_tg_arn,
        controller="CODE_DEPLOY",
    )
    good_application = _provision_application(ctx, codedeploy)
    good_group_name = ctx.unique_name("sim2real-xsvc-dg-")
    _create_ecs_deployment_group(
        codedeploy, good_application, role_arn, good_group_name,
        cluster=cluster_name, service_name=codedeploy_service_name,
        origin_tg_name=origin_tg_name, standby_tg_name=standby_tg_name, listener_arn=listener_arn,
    )
    ctx.on_cleanup(lambda: codedeploy.delete_deployment_group(
        applicationName=good_application, deploymentGroupName=good_group_name,
    ))
    info = codedeploy.get_deployment_group(
        applicationName=good_application, deploymentGroupName=good_group_name,
    )["deploymentGroupInfo"]
    assert info["ecsServices"] == [{"serviceName": codedeploy_service_name, "clusterName": cluster_name}], info


# ===== helpers =====

def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *,
                 timeout_s: float = 240.0, interval_s: float = 5.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


def _error_pair(fn):
    """The ``(code, message)`` of the refusal ``fn()`` must raise; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _tagged(ctx, resource_type: str, kind: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-xsvc-{kind}-")}],
    }


def _provision_network(ctx, ec2) -> tuple:
    vpc_id = ec2.create_vpc(
        CidrBlock="10.202.0.0/16", TagSpecifications=[_tagged(ctx, "vpc", "vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_networked(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tagged(ctx, "internet-gateway", "igw")]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_networked(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_networked(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"][:2]
    ]
    assert len(azs) >= 2, f"region {ctx.region!r} offers fewer than 2 available AZs: {azs!r}"

    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.202.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[_tagged(ctx, "subnet", f"subnet{i}")],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        ctx.on_cleanup(lambda sid=sid: _delete_networked(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tagged(ctx, "route-table", "rt")]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_networked(ec2, "delete_route_table", RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for sid in subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(lambda assoc_id=assoc_id: ec2.disassociate_route_table(AssociationId=assoc_id))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-xsvc-sg-"),
        Description="sim2real codedeploy ecs deployment-controller negative test sg",
        VpcId=vpc_id, TagSpecifications=[_tagged(ctx, "security-group", "sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_networked(ec2, "delete_security_group", GroupId=sg_id))
    # Nothing ever serves here (both services stay idle); members of this group only.
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": _CONTAINER_PORT, "ToPort": _CONTAINER_PORT,
            "UserIdGroupPairs": [{"GroupId": sg_id}],
        }],
    )
    return vpc_id, subnet_ids, sg_id


def _provision_cluster(ctx, ecs) -> str:
    name = ctx.unique_name("sim2real-xsvc-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _delete_cluster_once_drained(ecs, name))
    return name


def _delete_cluster_once_drained(ecs, name: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ClusterContainsServicesException", "ClusterContainsTasksException"):
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError(f"delete_cluster({name}): still draining after {timeout_s}s") from exc
            time.sleep(5)


def _register_idle_task_definition(ctx, ecs) -> str:
    family = ctx.unique_name("sim2real-xsvc-td-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[{
            "name": _CONTAINER_NAME,
            "image": "busybox:1.36",
            "essential": True,
            "command": ["sh", "-c", f"httpd -f -p {_CONTAINER_PORT} -h /"],
            "portMappings": [{"containerPort": _CONTAINER_PORT, "protocol": "tcp"}],
        }],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _retire_task_definition(ecs, task_def_arn: str) -> None:
    try:
        described = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=task_def_arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[task_def_arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {task_def_arn} teardown failed: {failures}")


def _provision_target_groups(ctx, elbv2, vpc_id: str) -> tuple:
    def _make(suffix: str) -> tuple:
        name = ctx.unique_name(f"sim2real-xsvc-tg-{suffix}-")[:32].strip("-")
        arn = elbv2.create_target_group(
            Name=name, Protocol="HTTP", Port=_CONTAINER_PORT, VpcId=vpc_id, TargetType="ip",
            HealthCheckProtocol="HTTP", HealthCheckPath="/", HealthCheckIntervalSeconds=10,
            HealthyThresholdCount=2, UnhealthyThresholdCount=2, Matcher={"HttpCode": "200"},
        )["TargetGroups"][0]["TargetGroupArn"]
        ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=arn))
        return name, arn

    origin_name, origin_arn = _make("origin")
    standby_name, standby_arn = _make("standby")
    return origin_name, origin_arn, standby_name, standby_arn


def _provision_load_balancer(ctx, elbv2, subnet_ids: list, sg_id: str, origin_tg_arn: str) -> str:
    name = ctx.unique_name("sim2real-xsvc-alb-")[:32].strip("-")
    lb_arn = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id],
        Type="application", Scheme="internal",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active", timeout_s=240.0, interval_s=5.0,
        description=f"load balancer {lb_arn} becoming active",
    )
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": origin_tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _provision_idle_service(ctx, ecs, cluster: str, task_def_arn: str, subnet_ids: list,
                             sg_id: str, origin_tg_arn: str, *, controller: str) -> str:
    """A CODE_DEPLOY- or ECS-controlled service with desiredCount=0: real enough for
    CreateDeploymentGroup to resolve, cheap enough that no Fargate task ever runs."""
    name = ctx.unique_name("sim2real-xsvc-svc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=0,
        launchType="FARGATE",
        deploymentController={"type": controller},
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED",
        }},
        loadBalancers=[{
            "targetGroupArn": origin_tg_arn, "containerName": _CONTAINER_NAME,
            "containerPort": _CONTAINER_PORT,
        }],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=name, force=True))
    return name


def _provision_codedeploy_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-xsvc-cd-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codedeploy.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust, Path="/sim2real/",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AWSCodeDeployRoleForECS"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _provision_application(ctx, codedeploy) -> str:
    name = ctx.unique_name("sim2real-xsvc-app-")
    codedeploy.create_application(applicationName=name, computePlatform="ECS")
    ctx.on_cleanup(lambda: codedeploy.delete_application(applicationName=name))
    return name


def _create_ecs_deployment_group(codedeploy, application_name: str, role_arn: str, name: str, *,
                                  cluster: str, service_name: str, origin_tg_name: str,
                                  standby_tg_name: str, listener_arn: str) -> str:
    kwargs = dict(
        applicationName=application_name,
        deploymentGroupName=name,
        serviceRoleArn=role_arn,
        deploymentStyle={"deploymentType": "BLUE_GREEN", "deploymentOption": "WITH_TRAFFIC_CONTROL"},
        ecsServices=[{"serviceName": service_name, "clusterName": cluster}],
        loadBalancerInfo={"targetGroupPairInfoList": [{
            "targetGroups": [{"name": origin_tg_name}, {"name": standby_tg_name}],
            "prodTrafficRoute": {"listenerArns": [listener_arn]},
        }]},
        blueGreenDeploymentConfiguration={
            "terminateBlueInstancesOnDeploymentSuccess": {
                "action": "TERMINATE", "terminationWaitTimeInMinutes": 0,
            },
            "deploymentReadyOption": {"actionOnTimeout": "CONTINUE_DEPLOYMENT"},
        },
    )
    # A freshly-minted service role is not immediately assumable: CreateDeploymentGroup can
    # reject an otherwise-valid request with InvalidRoleException until the trust propagates.
    deadline = time.monotonic() + 90
    while True:
        try:
            codedeploy.create_deployment_group(**kwargs)
            return name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidRoleException" or \
                    time.monotonic() >= deadline:
                raise
            time.sleep(3)


_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_TEARDOWN_DEADLINES: dict = {}
_NET_TEARDOWN_S = 630.0


def _delete_networked(client, op: str, **ident) -> None:
    held = _NET_TEARDOWN_DEADLINES.get(id(client))
    if held is None:
        held = _NET_TEARDOWN_DEADLINES[id(client)] = time.monotonic() + _NET_TEARDOWN_S
    deadline = held
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _attached_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(5)
    while True:
        try:
            getattr(client, op)(**ident)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                    f"ENIs still attached: {_attached_enis(client, flt)}"
                ) from exc
            time.sleep(5)


def _attached_enis(client, flt: list) -> list:
    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except ClientError:
        return []
    return [e["NetworkInterfaceId"] for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
