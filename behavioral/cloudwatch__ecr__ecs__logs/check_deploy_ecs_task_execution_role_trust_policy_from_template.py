"""deploy-ecs-task-execution-role-trust-policy-from-template."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecs-task-execution-role-trust-policy-from-template"
GROUP = "deploy-integration"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]

_EXEC_TEST_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The CloudFormation-made task execution role has one Allow sts:AssumeRole trust statement for
    exactly ecs-tasks.amazonaws.com and AmazonECSTaskExecutionRolePolicy attached, and a Fargate task
    using it as executionRoleArn reaches RUNNING."""
    template = _build_template()
    result = _deploy_cfn(ctx, json.dumps(template), timeout_s=180.0)
    role_name = result["outputs"]["RoleName"]
    role_arn = result["outputs"]["RoleArn"]

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["Arn"] == role_arn, f"expected role ARN {role_arn!r}, got {role['Arn']!r}"

    trust_doc = role["AssumeRolePolicyDocument"]
    statements = trust_doc["Statement"]
    assert len(statements) == 1, f"expected exactly 1 trust statement, got {len(statements)}: {statements!r}"
    stmt = statements[0]
    assert stmt["Effect"] == "Allow", f"expected trust statement Effect Allow, got {stmt['Effect']!r}"
    assert stmt["Action"] == "sts:AssumeRole", f"expected trust statement Action sts:AssumeRole, got {stmt['Action']!r}"
    principal = stmt["Principal"]
    assert principal == {"Service": "ecs-tasks.amazonaws.com"}, (
        f"expected trust principal to be exactly ecs-tasks.amazonaws.com, got {principal!r}"
    )

    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    attached_arns = {p["PolicyArn"] for p in attached}
    assert "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy" in attached_arns, (
        f"expected AmazonECSTaskExecutionRolePolicy attached, got {attached_arns!r}"
    )

    # IAM's own GetRole/ListAttachedRolePolicies is a template echo, not proof the role works.
    # The destination is ECS: only a real RunTask using this executionRoleArn shows ECS could
    # assume the role and that the attached policy's awslogs permissions actually function.
    subnet_id, sg_id = _check_networking(ctx)
    cluster_name = _create_cluster(ctx)
    log_group = _create_log_group(ctx)
    task_def_arn = _register_task_def(ctx, role_arn, log_group)
    task_arn = _run_task(ctx, cluster_name, task_def_arn, subnet_id, sg_id)
    task = _wait_task(ctx, cluster_name, task_arn, {"RUNNING", "STOPPED"}, timeout_s=180.0)
    assert task["lastStatus"] == "RUNNING", (
        "ECS could not actually use the CFN-deployed execution role: expected RUNNING, got "
        f"lastStatus={task['lastStatus']!r} stoppedReason={task.get('stoppedReason')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    """ECS's Tag shape uses lowercase key/value, unlike CFN's Key/Value."""
    return [{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=600,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _check_networking(ctx):
    net = _create_network(ctx, n_subnets=1)
    return net["subnet_id"], net["sg_id"]


def _create_network(ctx, n_subnets: int = 1) -> dict:
    """A VPC this check owns: public subnets behind an internet gateway (Fargate pulls the image
    over a public IP) and a security group with only the default allow-all egress rule. One
    cleanup tears the whole network down in dependency order, retrying while ECS still holds
    task ENIs in it."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-net-")

    def tag(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]}]

    net: dict = {"subnet_ids": []}
    net["vpc_id"] = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=tag("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_network(ctx, net))
    ec2.get_waiter("vpc_available").wait(VpcIds=[net["vpc_id"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    net["igw_id"] = ec2.create_internet_gateway(TagSpecifications=tag("internet-gateway"))[
        "InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    net["igw_attached"] = True
    net["rt_id"] = ec2.create_route_table(VpcId=net["vpc_id"], TagSpecifications=tag("route-table"))[
        "RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=net["rt_id"], DestinationCidrBlock="0.0.0.0/0", GatewayId=net["igw_id"])
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"]]
    if len(zones) < n_subnets:
        raise AssertionError(f"need {n_subnets} availability zones, the region offers {zones}")
    for i, zone in enumerate(sorted(zones)[:n_subnets]):
        subnet_id = ec2.create_subnet(
            VpcId=net["vpc_id"], CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=zone, TagSpecifications=tag("subnet")
        )["Subnet"]["SubnetId"]
        net["subnet_ids"].append(subnet_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        ec2.associate_route_table(RouteTableId=net["rt_id"], SubnetId=subnet_id)
    net["subnet_id"] = net["subnet_ids"][0]
    net["sg_id"] = ec2.create_security_group(
        GroupName=name, Description="sim2real check network", VpcId=net["vpc_id"], TagSpecifications=tag("security-group")
    )["GroupId"]
    return net


def _delete_network(ctx, net: dict, timeout_s: float = 900.0) -> None:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s

    def retrying(fn, **kwargs):
        while True:
            try:
                fn(**kwargs)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code.endswith(".NotFound") or code == "Gateway.NotAttached":
                    return
                if code != "DependencyViolation" or time.monotonic() > deadline:
                    raise
            time.sleep(15)

    if net.get("sg_id"):
        retrying(ec2.delete_security_group, GroupId=net["sg_id"])
    for subnet_id in net["subnet_ids"]:
        retrying(ec2.delete_subnet, SubnetId=subnet_id)
    if net.get("rt_id"):
        retrying(ec2.delete_route_table, RouteTableId=net["rt_id"])
    if net.get("igw_attached"):
        retrying(ec2.detach_internet_gateway, InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    if net.get("igw_id"):
        retrying(ec2.delete_internet_gateway, InternetGatewayId=net["igw_id"])
    retrying(ec2.delete_vpc, VpcId=net["vpc_id"])


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = _xname(ctx, "cluster")
    cluster = ecs.create_cluster(clusterName=name, tags=_ecs_tags_kv())["cluster"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    return cluster["clusterName"]


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = f"/{_xname(ctx, 'lg')}"
    logs.create_log_group(logGroupName=name, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name


def _register_task_def(ctx, exec_role_arn: str, log_group: str) -> str:
    ecs = ctx.client("ecs")
    family = _xname(ctx, "taskdef")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": _EXEC_TEST_IMAGE,
                "essential": True,
                "command": ["sh", "-c", "sleep 60"],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": "ecs",
                    },
                },
            }
        ],
        tags=_ecs_tags_kv(),
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_def(ecs, resp["taskDefinitionArn"]))
    return resp["taskDefinitionArn"]


def _retire_task_def(ecs, arn: str) -> None:
    """Deregister, then delete, one task definition revision, so no INACTIVE revision lingers."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
    if failures:
        raise RuntimeError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _run_task(ctx, cluster_name: str, task_def_arn: str, subnet_id: str, sg_id: str, *, timeout_s: float = 60.0, interval_s: float = 5.0) -> str:
    """RunTask synchronously calls sts:AssumeRole on the execution role before it will launch a
    task. A role that was JUST created by the CFN stack is often not yet visible to that
    synchronous check even though GetRole already returns it -- IAM trust/policy propagation
    lags role creation. Retry on that specific error (and on a transient placement failure)
    instead of a blind sleep, bounded by a deadline."""
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    last_err: Any = None
    while time.monotonic() < deadline:
        try:
            resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [subnet_id],
                        "securityGroups": [sg_id],
                        "assignPublicIp": "ENABLED",
                    }
                },
                tags=_ecs_tags_kv(),
            )
        except ClientError as exc:
            if "unable to assume the role" not in str(exc).lower():
                raise
            last_err = exc
            time.sleep(interval_s)
            continue
        failures = resp.get("failures", [])
        if failures:
            last_err = failures[0]
            time.sleep(interval_s)
            continue
        task_arn = resp["tasks"][0]["taskArn"]
        ctx.on_cleanup(lambda t=task_arn: _stop_task_and_wait(ctx, cluster_name, t))
        return task_arn
    raise AssertionError(f"run_task never succeeded within {timeout_s}s (last error: {last_err})")


def _stop_task_and_wait(ctx, cluster_name: str, task_arn: str) -> None:
    ecs = ctx.client("ecs")
    try:
        ecs.stop_task(cluster=cluster_name, task=task_arn, reason="sim2real check cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise
        return

    def _status():
        try:
            tasks = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"]
            return tasks[0]["lastStatus"] if tasks else "GONE"
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return "GONE"

    try:
        _poll_until(_status, lambda s: s in {"STOPPED", "GONE"}, timeout_s=90.0, interval_s=5.0)
    except AssertionError:
        pass


def _wait_task(ctx, cluster_name: str, task_arn: str, target_statuses: set[str], *, timeout_s: float, interval_s: float = 5.0) -> dict[str, Any]:
    ecs = ctx.client("ecs")

    def _describe():
        tasks = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn]).get("tasks", [])
        return tasks[0] if tasks else None

    return _poll_until(
        _describe,
        lambda t: t is not None and t["lastStatus"] in target_statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"task {task_arn} reach {target_statuses}",
    )


def _build_template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
                    ],
                },
            }
        },
        "Outputs": {
            "RoleName": {"Value": {"Ref": "ExecutionRole"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["ExecutionRole", "Arn"]}},
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
