"""ecs-canary-deployment-shifts-traffic-in-stages."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "ecs-canary-deployment-shifts-traffic-in-stages"
GROUP = "ecs-blue-green-lifecycle"
SERVICES = ["codedeploy", "ecs", "elbv2"]

_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codedeploy.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_POLL_TIMEOUT_S = 1200.0


# timing:real-time — schedule: 300 s https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-configurations.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:e2e",
    "plane:control",
    "timing:real-time",
)
def run(ctx) -> None:
    """CodeDeployDefault.ECSCanary10Percent5Minutes routes only 10% of production traffic
    to the green task set for the configured bake window before cutting over the rest, and
    the deployment reaches SUCCEEDED once the full cutover completes."""
    ecs = ctx.client("ecs")
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    codedeploy = ctx.client("codedeploy")

    vpc_id, subnet_ids, sg_id = _create_network(ctx, ec2)

    cluster = ctx.unique_name("sim2real-xsvc-cl-")
    ecs.create_cluster(clusterName=cluster)
    ctx.on_cleanup(lambda: _delete_cluster_after_drain(ecs, cluster))

    task_def_arn = _register_task_def(ctx, ecs)

    blue_tg_name, blue_tg_arn, green_tg_name, green_tg_arn = _create_target_groups(ctx, elbv2, vpc_id)
    alb_arn, _alb_dns, listener_arn = _create_alb(ctx, elbv2, subnet_ids, sg_id, blue_tg_arn)

    service = ctx.unique_name("sim2real-xsvc-svc-")
    ecs.create_service(
        cluster=cluster, serviceName=service, desiredCount=1, taskDefinition=task_def_arn,
        launchType="FARGATE",
        loadBalancers=[{"targetGroupArn": blue_tg_arn, "containerName": "app", "containerPort": 80}],
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED",
        }},
        healthCheckGracePeriodSeconds=90,
        deploymentController={"type": "CODE_DEPLOY"},
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=service, force=True))

    _wait_running_count(ecs, cluster, service, 1, timeout_s=360.0)
    _wait_target_healthy(elbv2, blue_tg_arn, 1, timeout_s=240.0)

    role_arn = _create_codedeploy_ecs_role(ctx, iam)

    app_name = ctx.unique_name("sim2real-xsvc-app-")
    codedeploy.create_application(applicationName=app_name, computePlatform="ECS")
    ctx.on_cleanup(lambda: codedeploy.delete_application(applicationName=app_name))

    group_name = ctx.unique_name("sim2real-xsvc-dg-")

    def _create_group():
        return codedeploy.create_deployment_group(
            applicationName=app_name,
            deploymentGroupName=group_name,
            deploymentConfigName="CodeDeployDefault.ECSAllAtOnce",
            serviceRoleArn=role_arn,
            deploymentStyle={"deploymentType": "BLUE_GREEN", "deploymentOption": "WITH_TRAFFIC_CONTROL"},
            ecsServices=[{"serviceName": service, "clusterName": cluster}],
            loadBalancerInfo={"targetGroupPairInfoList": [{
                "targetGroups": [{"name": blue_tg_name}, {"name": green_tg_name}],
                "prodTrafficRoute": {"listenerArns": [listener_arn]},
            }]},
            blueGreenDeploymentConfiguration={
                "terminateBlueInstancesOnDeploymentSuccess": {
                    "action": "TERMINATE", "terminationWaitTimeInMinutes": 0,
                },
                "deploymentReadyOption": {"actionOnTimeout": "CONTINUE_DEPLOYMENT"},
            },
        )

    _retry_iam_propagation(_create_group)
    ctx.on_cleanup(lambda: codedeploy.delete_deployment_group(
        applicationName=app_name, deploymentGroupName=group_name,
    ))

    app_spec = json.dumps({
        "version": 0.0,
        "Resources": [{
            "TargetService": {
                "Type": "AWS::ECS::Service",
                "Properties": {
                    "TaskDefinition": task_def_arn,
                    "LoadBalancerInfo": {"ContainerName": "app", "ContainerPort": 80},
                },
            },
        }],
    })
    deployment_id = codedeploy.create_deployment(
        applicationName=app_name,
        deploymentGroupName=group_name,
        deploymentConfigName="CodeDeployDefault.ECSCanary10Percent5Minutes",
        revision={
            "revisionType": "AppSpecContent",
            "appSpecContent": {"content": app_spec},
        },
    )["deploymentId"]
    assert deployment_id.startswith("d-"), f"deploymentId {deployment_id!r} does not start with 'd-'"

    split = _wait_for_canary_split(codedeploy, deployment_id, elbv2, listener_arn,
                                   timeout_s=_POLL_TIMEOUT_S)
    status = _wait_deployment_terminal(codedeploy, deployment_id, timeout_s=_POLL_TIMEOUT_S)
    assert status == "Succeeded", f"deployment {deployment_id!r} reached terminal status {status!r}, not Succeeded"

    info = codedeploy.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
    assert info["deploymentConfigName"] == "CodeDeployDefault.ECSCanary10Percent5Minutes", (
        f"GetDeployment deploymentConfigName was {info['deploymentConfigName']!r}"
    )
    assert split == {blue_tg_arn: 90, green_tg_arn: 10}, (
        f"during the canary bake the listener's forward weights must be 90 blue / 10 green; "
        f"observed {split!r}"
    )

    final_actions = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"][0]["DefaultActions"]
    final_weights = _forward_target_group_weights(final_actions)
    assert final_weights.get(green_tg_arn, 0) > 0, (
        f"after the canary deployment finished, the listener's weights {final_weights!r} give the "
        f"green target group {green_tg_arn!r} no traffic"
    )
    assert final_weights.get(blue_tg_arn, 0) == 0, (
        f"after the canary deployment finished, the listener's weights {final_weights!r} still "
        f"route traffic to the original blue target group {blue_tg_arn!r}"
    )


# ===== helpers =====

def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *,
                 timeout_s: float, interval_s: float = 10.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


def _retry_iam_propagation(fn: Callable[[], Any], *, attempts: int = 8, interval_s: float = 10.0):
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - narrowed by error code below
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code not in ("InvalidRoleException", "AccessDenied", "InvalidInputException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc  # type: ignore[misc]


def _tag_spec(ctx, resource_type: str, kind: str) -> dict:
    return {"ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{kind}-")},
                     {"Key": "sim2real:managed", "Value": "true"}]}


def _create_network(ctx, ec2) -> tuple:
    """A VPC of this check's own: two public subnets (Fargate pulls its image over the internet
    gateway) and a security group admitting tcp/80 from its own members only (ALB to task)."""
    vpc_id = ec2.create_vpc(CidrBlock="10.97.0.0/16",
                            TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tag_spec(ctx, "internet-gateway", "igw")]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.97.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", f"subnet{i}")],
        )["Subnet"]["SubnetId"]
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
        GroupName=ctx.unique_name("sim2real-xsvc-sg-"), Description="sim2real codedeploy-ecs canary",
        VpcId=vpc_id, TagSpecifications=[_tag_spec(ctx, "security-group", "sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "UserIdGroupPairs": [{"GroupId": sg_id}],
    }])
    return vpc_id, subnet_ids, sg_id


_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    """Delete one network resource once the ENIs holding it are released (bounded, shared deadline)."""
    from botocore.exceptions import ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while flt and client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"] \
            and time.monotonic() < deadline:
        time.sleep(10)  # ALB and Fargate ENIs are released asynchronously after their owner is deleted
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") != "DependencyViolation" \
                    or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _register_task_def(ctx, ecs) -> str:
    family = ctx.unique_name("sim2real-xsvc-td-")
    resp = ecs.register_task_definition(
        family=family, networkMode="awsvpc", requiresCompatibilities=["FARGATE"],
        cpu="256", memory="512",
        containerDefinitions=[{
            "name": "app", "image": "busybox:1.36", "essential": True,
            "command": ["sh", "-c", "mkdir -p /www && echo OK > /www/index.html && httpd -f -p 80 -h /www"],
            "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
            "healthCheck": {
                "command": ["CMD-SHELL", "wget -q -O- http://localhost:80/ | grep -q OK || exit 1"],
                "interval": 10, "timeout": 5, "retries": 3, "startPeriod": 10,
            },
        }],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _create_target_groups(ctx, elbv2, vpc_id: str) -> tuple:
    blue_name = ctx.unique_name("sim2real-xsvc-blue-")[:32].strip("-")
    green_name = ctx.unique_name("sim2real-xsvc-green-")[:32].strip("-")
    common = dict(
        Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
        HealthCheckProtocol="HTTP", HealthCheckPath="/", HealthCheckIntervalSeconds=10,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2, Matcher={"HttpCode": "200"},
    )
    blue_arn = elbv2.create_target_group(Name=blue_name, **common)["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=blue_arn))
    green_arn = elbv2.create_target_group(Name=green_name, **common)["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=green_arn))
    return blue_name, blue_arn, green_name, green_arn


def _create_alb(ctx, elbv2, subnet_ids: list, sg_id: str, blue_tg_arn: str) -> tuple:
    alb_name = ctx.unique_name("sim2real-xsvc-alb-")[:32].strip("-")
    alb = elbv2.create_load_balancer(
        Name=alb_name, Subnets=subnet_ids, SecurityGroups=[sg_id], Type="application", Scheme="internal",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["LoadBalancers"][0]
    alb_arn, alb_dns = alb["LoadBalancerArn"], alb["DNSName"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": blue_tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return alb_arn, alb_dns, listener_arn


def _create_codedeploy_ecs_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-xsvc-cdrole-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AWSCodeDeployRoleForECS"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn  # propagation is retried at first use (_retry_iam_propagation)


def _wait_running_count(ecs, cluster: str, service: str, count: int, *, timeout_s: float):
    def probe():
        return ecs.describe_services(cluster=cluster, services=[service])["services"][0]["runningCount"]

    return _poll_until(probe, lambda rc: rc == count, timeout_s=timeout_s,
                        description=f"service {service} runningCount=={count}")


def _wait_target_healthy(elbv2, tg_arn: str, count: int, *, timeout_s: float):
    def probe():
        ths = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        return [t["TargetHealth"]["State"] for t in ths]

    return _poll_until(probe, lambda states: states.count("healthy") == count, timeout_s=timeout_s,
                        description=f"target group {tg_arn} healthy-target-count=={count}")


def _delete_cluster_after_drain(ecs, cluster: str, *, timeout_s: float = 240.0) -> None:
    """DeleteCluster races a service's async drain (ClusterContainsServicesException /
    ClusterContainsTasksException); poll for the drain, then delete."""
    deadline = time.monotonic() + timeout_s

    def active():
        d = ecs.describe_clusters(clusters=[cluster])["clusters"]
        return d[0]["activeServicesCount"] + d[0]["runningTasksCount"] + d[0]["pendingTasksCount"] if d else 0

    while active() > 0 and time.monotonic() < deadline:
        time.sleep(10)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except Exception as exc:  # noqa: BLE001 - bounded retry on the specific drain races
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code not in ("ClusterContainsServicesException", "ClusterContainsTasksException"):
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"delete_cluster({cluster}): still draining after {timeout_s}s"
                ) from exc
            time.sleep(10)


def _wait_deployment_terminal(codedeploy, deployment_id: str, *, timeout_s: float) -> str:
    terminal = {"Succeeded", "Failed", "Stopped"}

    def probe():
        return codedeploy.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["status"]

    return _poll_until(probe, lambda s: s in terminal, timeout_s=timeout_s, interval_s=15.0,
                        description=f"deployment {deployment_id} reaches a terminal status")


def _forward_target_group_weights(default_actions: list) -> dict:
    for action in default_actions:
        if action.get("Type") != "forward":
            continue
        cfg = action.get("ForwardConfig", {})
        return {tg["TargetGroupArn"]: tg.get("Weight", 0) for tg in cfg.get("TargetGroups", [])}
    return {}


def _wait_for_canary_split(codedeploy, deployment_id: str, elbv2, listener_arn: str, *,
                           timeout_s: float) -> dict:
    """The listener's forward weights at the first poll where both target groups carry traffic.

    Polled until the split appears or the deployment ends; a deployment that ends without ever
    splitting raises, so the split is demanded, not hoped for.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        actions = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"][0]["DefaultActions"]
        weights = _forward_target_group_weights(actions)
        if sum(1 for w in weights.values() if w > 0) >= 2:
            return weights
        status = codedeploy.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["status"]
        if status in ("Succeeded", "Failed", "Stopped") or time.monotonic() >= deadline:
            raise AssertionError(
                f"deployment {deployment_id} reached {status!r} without the listener ever splitting "
                f"traffic across both target groups; last weights {weights!r}"
            )
        time.sleep(5)  # the 10% bake lasts five minutes, so a 5 s poll cannot miss it


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
