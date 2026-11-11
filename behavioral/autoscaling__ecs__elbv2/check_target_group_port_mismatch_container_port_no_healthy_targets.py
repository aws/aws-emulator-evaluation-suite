"""target-group-port-mismatch-container-port-no-healthy-targets."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-group-port-mismatch-container-port-no-healthy-targets"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A target group whose HealthCheckPort is a port the container never listens on never reports a
    healthy target, while a traffic-port health check on an identical task does."""
    net = ctx.network()
    vpc_id, subnet_ids = net.vpc_id, net.subnet_ids[:2]

    sg_id = _create_sg(ctx, vpc_id)
    execution_role_arn = _create_execution_role(ctx)
    cluster_arn = _create_cluster(ctx)
    container_name = "web"
    task_def_arn = _register_task_def(ctx, execution_role_arn, container_name, container_port=80)

    # Correct config: health check uses the traffic-port (== container port 80).
    tg_control = _create_target_group(ctx, vpc_id, port=80, health_check_port=None)
    # Broken config: health check explicitly points at a port nothing listens on.
    tg_mismatch = _create_target_group(ctx, vpc_id, port=80, health_check_port=8888)

    alb_arn, _dns = _create_alb(ctx, subnet_ids, sg_id)
    _create_listener(ctx, alb_arn, tg_control, port=80)
    _create_listener(ctx, alb_arn, tg_mismatch, port=8080)

    svc_control = _create_service(ctx, cluster_arn, task_def_arn, tg_control, subnet_ids, sg_id, container_name, 80)
    svc_mismatch = _create_service(ctx, cluster_arn, task_def_arn, tg_mismatch, subnet_ids, sg_id, container_name, 80)
    _wait_service_running(ctx, cluster_arn, svc_control, 1)
    _wait_service_running(ctx, cluster_arn, svc_mismatch, 1)

    control_state, mismatch_state = _poll_pair(ctx, tg_control, tg_mismatch, timeout_s=300, interval_s=10)
    assert control_state == "healthy", f"positive control (traffic-port health check) never became healthy: {control_state!r}"
    assert mismatch_state != "healthy", f"target with a mismatched health-check port must never report healthy: {mismatch_state!r}"


def _poll_pair(ctx, tg_control, tg_mismatch, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    control_state = "unregistered"
    mismatch_state = "unregistered"
    while time.monotonic() < deadline:
        control_targets = _target_health(ctx, tg_control)
        mismatch_targets = _target_health(ctx, tg_mismatch)
        control_state = control_targets[0]["TargetHealth"]["State"] if control_targets else "unregistered"
        mismatch_state = mismatch_targets[0]["TargetHealth"]["State"] if mismatch_targets else "unregistered"
        assert mismatch_state != "healthy", "target with a mismatched health-check port must never report healthy"
        if control_state == "healthy":
            return control_state, mismatch_state
        time.sleep(interval_s)
    return control_state, mismatch_state


#: What a delete answers while a dependent drains: a listener deleted with its ALB still holds the
#: target group, stopping tasks hold the cluster, and their ENIs hold the security group.
_HELD = ("DependencyViolation", "ResourceInUse", "ClusterContainsTasksException",
         "ClusterContainsServicesException")


def _retry_delete(fn, *, timeout_s=300.0):
    """Retry a delete while what holds the resource drains away; a resource already gone is done."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(("NotFound", "NotFoundException")):
                return
            if code not in _HELD or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _create_sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ecs-elb-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real ecs/elbv2 behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))
    # The ALB and the tasks share this group; the self-reference admits the ALB's health checks.
    # Nothing outside the group connects.
    ec2.authorize_security_group_ingress(
        GroupId=sg_id, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": sg_id}]}]
    )
    return sg_id


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecs-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _poll_until(
        lambda: [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]],
        lambda arns: policy_arn in arns,
        timeout_s=60,
        interval_s=5,
        desc="execution role policy attachment to become visible before ECS/Fargate attempts to assume the role",
    )
    return role_arn


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ecs.delete_cluster(cluster=arn)))
    return arn


def _register_task_def(ctx, execution_role_arn, container_name="web", container_port=80):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-taskdef-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": container_name,
                "image": "public.ecr.aws/docker/library/httpd:2.4",
                "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
                "essential": True,
            }
        ],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _create_target_group(ctx, vpc_id, port=80, health_check_port=None, interval=10):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-")
    kwargs: dict[str, Any] = dict(
        Name=name,
        Protocol="HTTP",
        Port=port,
        VpcId=vpc_id,
        TargetType="ip",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=interval,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
    )
    if health_check_port is not None:
        kwargs["HealthCheckPort"] = str(health_check_port)
    tg_arn = elbv2.create_target_group(**kwargs)["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-alb-")
    alb_arn = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme="internet-facing", Type="application"
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=300,
        interval_s=10,
        desc="ALB to become active",
    )
    dns_name = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["DNSName"]
    return alb_arn, dns_name


def _create_listener(ctx, alb_arn, tg_arn, port):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))
    return listener_arn


def _create_service(ctx, cluster_arn, task_def_arn, tg_arn, subnet_ids, sg_id, container_name, container_port, desired_count=1):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}
        },
        loadBalancers=[{"targetGroupArn": tg_arn, "containerName": container_name, "containerPort": container_port}],
    )

    def _cleanup():
        try:
            ecs.update_service(cluster=cluster_arn, service=name, desiredCount=0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "NamespaceNotFoundException",
                "ServiceNotFoundException",
            ):
                raise
        ecs.delete_service(cluster=cluster_arn, service=name, force=True)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_service_running(ctx, cluster_arn, service_name, desired_count, timeout_s=420):
    ecs = ctx.client("ecs")

    def probe():
        d = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
        return d["runningCount"]

    return _poll_until(probe, lambda n: n >= desired_count, timeout_s=timeout_s, interval_s=15, desc="ECS service running count")


def _target_health(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]


def _poll_until(probe, predicate, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {desc}; last observed: {last!r}")


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
