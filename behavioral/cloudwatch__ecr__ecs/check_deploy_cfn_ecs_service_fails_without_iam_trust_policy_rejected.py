"""deploy-cfn-ecs-service-fails-without-iam-trust-policy-rejected."""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-ecs-service-fails-without-iam-trust-policy-rejected"
GROUP = "iac-stack"
SERVICES = ["cloudwatch", "ecr", "ecs"]

_IMAGE = "public.ecr.aws/amazonlinux/amazonlinux:2023"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An execution role trusting ec2.amazonaws.com instead of ecs-tasks.amazonaws.com cannot be
    assumed by ECS: RunTask is rejected with ClientException, so a service on it never stabilizes,
    while a correctly-trusted role in the same stack runs its task."""
    cluster_name = _xname(ctx, "cluster")
    good_family = _xname(ctx, "taskdef-good")
    bad_family = _xname(ctx, "taskdef-bad")
    good_role_name = _xname(ctx, "good-role")
    bad_role_name = _xname(ctx, "bad-role")
    log_group_name = f"/sim2real/{_xname(ctx, 'logs')}"
    good_token = f"sim2real-good-{uuid.uuid4().hex[:12]}"
    bad_token = f"sim2real-bad-{uuid.uuid4().hex[:12]}"
    net = _check_network(ctx)

    def _container(name: str, token: str) -> dict[str, Any]:
        return {
            "Name": name,
            "Image": _IMAGE,
            "Essential": True,
            "Command": ["sh", "-c", f"echo {token}; sleep 300"],
            "LogConfiguration": {
                "LogDriver": "awslogs",
                "Options": {
                    "awslogs-group": {"Ref": "LogGroup"},
                    "awslogs-region": ctx.region,
                    "awslogs-stream-prefix": "ecs",
                },
            },
        }

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
            "SecurityGroupId": {"Type": "AWS::EC2::SecurityGroup::Id"},
        },
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": log_group_name, "RetentionInDays": 1},
            },
            "Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {"ClusterName": cluster_name}},
            "GoodRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": good_role_name,
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
            },
            "BadRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": bad_role_name,
                    # The one thing broken: wrong service principal in the trust policy.
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
                    ],
                },
            },
            "GoodTaskDefinition": {
                "Type": "AWS::ECS::TaskDefinition",
                "DependsOn": ["GoodRole"],
                "Properties": {
                    "Family": good_family,
                    "Cpu": "256",
                    "Memory": "512",
                    "NetworkMode": "awsvpc",
                    "RequiresCompatibilities": ["FARGATE"],
                    "ExecutionRoleArn": {"Fn::GetAtt": ["GoodRole", "Arn"]},
                    "ContainerDefinitions": [_container("app", good_token)],
                },
            },
            "BadTaskDefinition": {
                "Type": "AWS::ECS::TaskDefinition",
                "DependsOn": ["BadRole"],
                "Properties": {
                    "Family": bad_family,
                    "Cpu": "256",
                    "Memory": "512",
                    "NetworkMode": "awsvpc",
                    "RequiresCompatibilities": ["FARGATE"],
                    "ExecutionRoleArn": {"Fn::GetAtt": ["BadRole", "Arn"]},
                    "ContainerDefinitions": [_container("app", bad_token)],
                },
            },
        },
    }

    _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={
            "SubnetIds": ",".join(net["subnet_ids"]),
            "SecurityGroupId": net["security_group_id"],
        },
        timeout_s=180.0,
    )

    ecs = ctx.client("ecs")
    logs = ctx.client("logs")
    net_config = {
        "awsvpcConfiguration": {
            "subnets": net["subnet_ids"],
            "securityGroups": [net["security_group_id"]],
            "assignPublicIp": "ENABLED",
        }
    }

    def _launch_and_wait_running(family: str) -> str:
        resp = ecs.run_task(
            cluster=cluster_name, taskDefinition=family, launchType="FARGATE",
            networkConfiguration=net_config, count=1,
        )
        assert not resp["failures"], f"RunTask({family}) reported failures: {resp['failures']}"
        task_arn = resp["tasks"][0]["taskArn"]
        ctx.on_cleanup(lambda: _stop_task_and_wait(ctx, cluster_name, task_arn))

        def _status() -> str:
            tasks = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"]
            return tasks[0]["lastStatus"] if tasks else "MISSING"

        return _poll_until(
            _status, lambda s: s in {"RUNNING", "STOPPED"}, timeout_s=120.0, interval_s=5.0,
            description=f"task from {family} reaching a terminal launch status",
        )

    # --- Negative: RunTask synchronously refuses a role ECS can never assume.
    try:
        ecs.run_task(
            cluster=cluster_name, taskDefinition=bad_family, launchType="FARGATE",
            networkConfiguration=net_config, count=1,
        )
    except ClientError as exc:
        error = exc.response["Error"]
        assert error["Code"] == "ClientException", (
            f"expected ClientException rejecting the unassumable role, got "
            f"{error['Code']}: {error.get('Message')}"
        )
        bad_role_arn = ctx.client("iam").get_role(RoleName=bad_role_name)["Role"]["Arn"]
        expected = (
            f"ECS was unable to assume the role '{bad_role_arn}' that was provided for this task. "
            "Please verify that the role being passed has the proper trust relationship and "
            "permissions and that your IAM user has permissions to pass this role."
        )
        assert error.get("Message") == expected, (
            f"unexpected role-assumption refusal message: {error.get('Message')!r}"
        )
    else:
        raise AssertionError(
            "RunTask succeeded with a role trusting ec2.amazonaws.com (not ecs-tasks.amazonaws.com) "
            "-- ECS should never have been able to assume it"
        )
    # Effect absent: the bad container's log line was never delivered (it never ran).
    stream_prefix = f"ecs/app/"
    all_streams = logs.describe_log_streams(
        logGroupName=log_group_name, logStreamNamePrefix=stream_prefix
    )["logStreams"]
    for stream in all_streams:
        events = logs.get_log_events(
            logGroupName=log_group_name, logStreamName=stream["logStreamName"], startFromHead=True
        )["events"]
        assert not any(bad_token in e["message"] for e in events), (
            "bad-trust-role task's log line was delivered -- it must never have started"
        )

    # --- Positive control: the correctly-trusted role's task DOES reach RUNNING and logs.
    good_status = _launch_and_wait_running(good_family)
    assert good_status == "RUNNING", f"control task with a correctly-trusted role failed (status={good_status})"

    def _fetch_good_messages() -> list[str]:
        streams = logs.describe_log_streams(
            logGroupName=log_group_name, logStreamNamePrefix=stream_prefix
        )["logStreams"]
        out: list[str] = []
        for stream in streams:
            events = logs.get_log_events(
                logGroupName=log_group_name, logStreamName=stream["logStreamName"], startFromHead=True
            )["events"]
            out.extend(e["message"] for e in events)
        return out

    messages = _poll_until(
        _fetch_good_messages,
        lambda msgs: any(good_token in m for m in msgs),
        timeout_s=90.0,
        interval_s=5.0,
        description="control task's log token appearing",
    )
    assert any(good_token in m for m in messages), "control task with correct trust never logged"


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (exc.response["Error"]["Code"] == "ValidationError"
                    and "does not exist" in exc.response["Error"].get("Message", "")):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    _record_stack_id = _task_definition_teardown(ctx, name)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    ctx.on_cleanup(_record_stack_id)
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _check_network(ctx):
    net = _create_network(ctx, n_subnets=2)
    return {**net, "security_group_id": net["sg_id"]}


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


def _stop_task_and_wait(ctx, cluster: str, task_arn: str) -> None:
    ecs = ctx.client("ecs")
    try:
        ecs.stop_task(cluster=cluster, task=task_arn, reason="sim2real check cleanup")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClusterNotFoundException"
                or (err["Code"] == "InvalidParameterException" and "not found" in err.get("Message", ""))):
            raise
        return

    def _status() -> str:
        try:
            tasks = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return "GONE"
        return tasks[0]["lastStatus"] if tasks else "GONE"

    _poll_until(_status, lambda s: s in {"STOPPED", "GONE"}, timeout_s=90.0, interval_s=2.0)


def _task_definition_teardown(ctx, stack_name: str):
    """Register the deletion of every ECS task definition revision the stack (and its nested
    stacks) registers, run once the stack is deleted: CloudFormation only deregisters them,
    which leaves INACTIVE revisions. Returns the cleanup that records the stack id; register it
    after the stack's own deletion so it runs before it."""
    state: dict = {}
    ctx.on_cleanup(lambda: _delete_stack_task_definitions(ctx, state.get("stack_id")))

    def _record_stack_id() -> None:
        try:
            state["stack_id"] = ctx.client("cloudformation").describe_stacks(
                StackName=stack_name)["Stacks"][0]["StackId"]
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise

    return _record_stack_id


def _delete_stack_task_definitions(ctx, stack_id) -> None:
    """Wait for the stack's deletion, then delete each task definition revision it registered."""
    if stack_id is None:
        return
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    # Bounded with the stack's own 120 s deletion wait inside the suite's 900 s cleanup budget.
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    arns, pending, seen = set(), [stack_id], set()
    while pending:
        sid = pending.pop()
        if sid in seen:
            continue
        seen.add(sid)
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=sid):
            for event in page["StackEvents"]:
                physical = event.get("PhysicalResourceId") or ""
                if not physical.startswith("arn:") or event["ResourceStatus"] not in (
                        "CREATE_COMPLETE", "UPDATE_COMPLETE"):
                    continue
                if event["ResourceType"] == "AWS::ECS::TaskDefinition":
                    arns.add(physical)
                elif event["ResourceType"] == "AWS::CloudFormation::Stack" and physical != sid:
                    pending.append(physical)
    for arn in sorted(arns):
        try:
            status = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
        except ClientError as exc:
            if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
                continue
            raise
        if status == "DELETE_IN_PROGRESS":
            continue
        if status == "ACTIVE":
            ecs.deregister_task_definition(taskDefinition=arn)
        failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
        if failures:
            raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
