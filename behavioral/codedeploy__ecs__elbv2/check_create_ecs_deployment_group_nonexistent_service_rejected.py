"""create-ecs-deployment-group-nonexistent-service-rejected."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "create-ecs-deployment-group-nonexistent-service-rejected"
GROUP = "validation"
SERVICES = ["codedeploy", "ecs", "elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An ECS CreateDeploymentGroup naming a nonexistent cluster/service is rejected with
    InvalidECSServiceException and creates no group; the same request naming a real idle
    service and target groups succeeds."""
    net = _create_network(ctx)
    alb = _create_alb_two_target_groups(ctx, net["vpc_id"], net["subnet_ids"], net["sg_id"])
    cluster = _create_cluster(ctx)
    role_arn = _create_codedeploy_service_role(ctx)

    bad_app = _create_cd_application(ctx)
    ghost_cluster = ctx.unique_name("sim2real-nonexistent-cluster-")
    code, msg = _error(lambda: _create_ecs_deployment_group(
        ctx, bad_app, role_arn,
        cluster=ghost_cluster,
        service_name="sim2real-nonexistent-service",
        blue_tg_name=alb["blue_tg_name"], green_tg_name=alb["green_tg_name"],
        listener_arn=alb["listener_arn"],
        _register=False,
    ))
    assert code == "InvalidECSServiceException", (
        f"expected a deployment group naming a nonexistent ECS cluster/service to be "
        f"rejected InvalidECSServiceException, got {code!r}"
    )
    # The message quotes ECS's own refusal, including a per-request id; that one field is
    # normalised, every other character is compared exactly.
    expected = (
        f"Could not load ECS service information for cluster: {ghost_cluster}, service: "
        "sim2real-nonexistent-service. Cause: Cluster not found. (Service: AmazonECS; Status Code: 400; "
        "Error Code: ClusterNotFoundException; Request ID: <request-id>; Proxy: null)"
    )
    msg = re.sub(r"Request ID: [0-9a-fA-F-]+;", "Request ID: <request-id>;", msg or "")
    assert msg == expected, f"expected the exact InvalidECSServiceException message {expected!r}, got {msg!r}"
    listed = ctx.client("codedeploy").list_deployment_groups(applicationName=bad_app)["deploymentGroups"]
    assert listed == [], f"rejected deployment group must not exist, got {listed!r}"

    # Positive control: the same request against a real idle ECS service succeeds, so the
    # rejection above is about resolving the named service, not the request shape.
    task_def_arn = _register_idle_task_def(ctx)
    service_name = _create_idle_ecs_service(ctx, cluster, task_def_arn, net["subnet_ids"], net["sg_id"], alb["blue_tg_arn"])
    good_app = _create_cd_application(ctx)
    dg = _create_ecs_deployment_group(
        ctx, good_app, role_arn,
        cluster=cluster, service_name=service_name,
        blue_tg_name=alb["blue_tg_name"], green_tg_name=alb["green_tg_name"],
        listener_arn=alb["listener_arn"],
    )
    info = ctx.client("codedeploy").get_deployment_group(
        applicationName=good_app, deploymentGroupName=dg
    )["deploymentGroupInfo"]
    assert info["deploymentGroupName"] == dg, info
    assert info["ecsServices"] == [{"serviceName": service_name, "clusterName": cluster}], info



# ===== helpers =====

def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *,
                timeout_s: float = 120.0, interval_s: float = 5.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """The (code, message) of the refusal fn() must raise; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _tag_spec(ctx, resource_type: str, kind: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{kind}-")}]}


def _create_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.97.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tag_spec(ctx, "internet-gateway", "igw")]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.97.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", f"subnet{i}")],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tag_spec(ctx, "route-table", "rt")]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for sid in subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(lambda assoc_id=assoc_id: ec2.disassociate_route_table(AssociationId=assoc_id))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-xsvc-sg-"), Description="sim2real codedeploy-ecs-elbv2 negative test sg",
        VpcId=vpc_id, TagSpecifications=[_tag_spec(ctx, "security-group", "sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    # Nothing ever serves here (the service is idle); members of this group only, on the listener port.
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "UserIdGroupPairs": [{"GroupId": sg_id}]}],
    )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-xsvc-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _delete_cluster_when_empty(ecs, name))
    return name


def _delete_cluster_when_empty(ecs, name: str, timeout_s: float = 180.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ClusterContainsServicesException", "ClusterContainsTasksException") or \
                    time.monotonic() >= deadline:
                raise RuntimeError(f"delete_cluster({name}): {code or exc}") from exc
            time.sleep(10)


def _register_idle_task_def(ctx, container_name: str = "app", container_port: int = 80) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-xsvc-td-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[{
            "name": container_name,
            "image": "busybox:1.36",
            "command": ["sh", "-c", f"mkdir -p /www && echo OK > /www/index.html && httpd -f -p {container_port} -h /www"],
            "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
            "essential": True,
        }],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _create_idle_ecs_service(ctx, cluster: str, task_def_arn: str, subnet_ids: list, sg_id: str,
                              blue_tg_arn: str, container_name: str = "app", container_port: int = 80) -> str:
    """A CODE_DEPLOY-controlled service with desiredCount=0: real enough for
    CreateDeploymentGroup to resolve, cheap enough that no Fargate task ever runs."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-xsvc-svc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=0,
        launchType="FARGATE",
        deploymentController={"type": "CODE_DEPLOY"},
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED",
        }},
        loadBalancers=[{
            "targetGroupArn": blue_tg_arn, "containerName": container_name, "containerPort": container_port,
        }],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=name, force=True))
    return name


def _create_alb_two_target_groups(ctx, vpc_id: str, subnet_ids: list, sg_id: str, port: int = 80) -> dict:
    elbv2 = ctx.client("elbv2")
    alb_name = ctx.unique_name("sim2real-xsvc-alb-")[:32].strip("-")
    alb_arn = elbv2.create_load_balancer(
        Name=alb_name, Subnets=subnet_ids, SecurityGroups=[sg_id], Type="application", Scheme="internal",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active", timeout_s=240.0, interval_s=10.0,
        description=f"load balancer {alb_arn} becoming active",
    )

    def _make_tg(suffix: str) -> tuple:
        name = ctx.unique_name(f"sim2real-xsvc-tg-{suffix}-")[:32].strip("-")
        arn = elbv2.create_target_group(
            Name=name, Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType="ip",
            HealthCheckProtocol="HTTP", HealthCheckPath="/", HealthCheckIntervalSeconds=10,
            HealthyThresholdCount=2, UnhealthyThresholdCount=2, Matcher={"HttpCode": "200"},
        )["TargetGroups"][0]["TargetGroupArn"]
        ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=arn))
        return name, arn

    blue_tg_name, blue_tg_arn = _make_tg("blue")
    green_tg_name, green_tg_arn = _make_tg("green")

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": blue_tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    return {
        "alb_arn": alb_arn, "listener_arn": listener_arn,
        "blue_tg_name": blue_tg_name, "blue_tg_arn": blue_tg_arn,
        "green_tg_name": green_tg_name, "green_tg_arn": green_tg_arn,
    }


def _create_codedeploy_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-role-codedeploy-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codedeploy.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"}],
    )

    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # The AWS-managed policy CodeDeploy documents for ECS blue/green (it can describe ECS services).
    policy_arn = "arn:aws:iam::aws:policy/AWSCodeDeployRoleForECS"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return resp["Role"]["Arn"]


def _create_cd_application(ctx, compute_platform="ECS") -> str:
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-xsvc-app-")
    cd.create_application(applicationName=name, computePlatform=compute_platform)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _create_ecs_deployment_group(ctx, app: str, role_arn: str, *, cluster: str, service_name: str,
                                  blue_tg_name: str, green_tg_name: str, listener_arn: str,
                                  _register: bool = True) -> str:
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-xsvc-dg-")
    kwargs = dict(
        applicationName=app,
        deploymentGroupName=name,
        serviceRoleArn=role_arn,
        deploymentStyle={"deploymentType": "BLUE_GREEN", "deploymentOption": "WITH_TRAFFIC_CONTROL"},
        ecsServices=[{"serviceName": service_name, "clusterName": cluster}],
        loadBalancerInfo={"targetGroupPairInfoList": [{
            "targetGroups": [{"name": blue_tg_name}, {"name": green_tg_name}],
            "prodTrafficRoute": {"listenerArns": [listener_arn]},
        }]},
        blueGreenDeploymentConfiguration={
            "terminateBlueInstancesOnDeploymentSuccess": {"action": "TERMINATE", "terminationWaitTimeInMinutes": 0},
            "deploymentReadyOption": {"actionOnTimeout": "CONTINUE_DEPLOYMENT"},
        },
    )
    # A fresh service role takes seconds to become assumable by CodeDeploy; the same bound on every target.
    deadline = time.monotonic() + 75
    while True:
        try:
            cd.create_deployment_group(**kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            msg = (err.get("Message") or "").lower()
            transient_role = code == "InvalidRoleException" or ("assume" in msg or "not authorized" in msg)
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    if _register:
        ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name))
    return name


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
        return []
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
