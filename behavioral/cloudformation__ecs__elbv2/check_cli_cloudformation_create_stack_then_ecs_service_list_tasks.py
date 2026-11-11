"""cli-cloudformation-create-stack-then-ecs-service-list-tasks."""
from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-cloudformation-create-stack-then-ecs-service-list-tasks"
GROUP = "deployment-order"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """`aws cloudformation create-stack` of an ECS cluster, a Fargate service DependsOn the listener
    and an ALB target group reaches CREATE_COMPLETE; `aws ecs list-tasks` lists exactly one task, the
    target group holds one healthy target, and an HTTP request through the ALB returns 200."""
    require_tools("aws")

    ecs = ctx.client("ecs")
    cfn = ctx.client("cloudformation")

    net = ctx.network()
    vpc_id, subnet_ids = net.vpc_id, net.subnet_ids[:2]

    cluster_name = ctx.unique_name("sim2real-cfncl-")
    service_name = ctx.unique_name("sim2real-cfnsvc-")
    family = ctx.unique_name("sim2real-cfntd-")
    role_name = ctx.unique_name("sim2real-cfnrole-")
    alb_name = _short_name(ctx, "sim2real-cfnalb-")
    tg_name = _short_name(ctx, "sim2real-cfntg-")

    template = _build_template(
        cluster_name, service_name, family, role_name, alb_name, tg_name, ctx.ingress_cidrs()
    )
    stack_name = ctx.unique_name("sim2real-cfnstack-")

    parameters_json = json.dumps(
        [
            {"ParameterKey": "VpcId", "ParameterValue": vpc_id},
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)},
        ]
    )
    _run_aws(
        ctx,
        "cloudformation",
        "create-stack",
        "--stack-name",
        stack_name,
        "--template-body",
        json.dumps(template),
        "--parameters",
        parameters_json,
        "--capabilities",
        "CAPABILITY_NAMED_IAM",
        timeout_s=60,
    )
    _record_stack_id = _task_definition_teardown(ctx, stack_name)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    ctx.on_cleanup(_record_stack_id)

    _wait_stack_status(ctx, stack_name, "CREATE_COMPLETE", timeout_s=600, interval_s=15)

    tasks = _run_aws(ctx, "ecs", "list-tasks", "--cluster", cluster_name, "--service-name", service_name)
    task_arns = tasks.get("taskArns", [])
    assert len(task_arns) == 1, f"expected 1 task for the CFN-provisioned service, got {task_arns}"

    def _running_count():
        described = ecs.describe_tasks(cluster=cluster_name, tasks=task_arns)["tasks"]
        return sum(1 for t in described if t["lastStatus"] == "RUNNING")

    _poll_until(_running_count, lambda v: v == 1, timeout_s=240, interval_s=15)

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    tg_arn = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "TargetGroupArn")
    alb_dns = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "LoadBalancerDnsName")

    healthy = _poll_until(
        lambda: [tid for tid, s in _target_states(ctx, tg_arn) if s == "healthy"],
        lambda v: len(v) == 1,
        timeout_s=300,
        interval_s=15,
    )
    assert len(healthy) == 1

    status = _poll_until(
        lambda: _http_get_status(ctx, f"http://{alb_dns}/"),
        lambda v: v == 200,
        timeout_s=120,
        interval_s=10,
    )
    assert status == 200, f"expected the ALB-fronted task to serve HTTP 200, got {status}"


def _build_template(cluster_name, service_name, family, role_name, alb_name, tg_name, ingress):
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "VpcId": {"Type": "AWS::EC2::VPC::Id"},
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
        },
        "Resources": {
            "ExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
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
            "Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {"ClusterName": cluster_name}},
            "TaskDefinition": {
                "Type": "AWS::ECS::TaskDefinition",
                "Properties": {
                    "Family": family,
                    "Cpu": "256",
                    "Memory": "512",
                    "NetworkMode": "awsvpc",
                    "RequiresCompatibilities": ["FARGATE"],
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "ContainerDefinitions": [
                        {
                            "Name": "app",
                            "Image": "public.ecr.aws/nginx/nginx:1.27",
                            "PortMappings": [{"ContainerPort": 80, "Protocol": "tcp"}],
                            "Essential": True,
                        }
                    ],
                },
            },
            "AlbSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "alb sg",
                    "VpcId": {"Ref": "VpcId"},
                    "SecurityGroupIngress": [
                        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIp": c} for c in ingress
                    ],
                },
            },
            "TaskSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "task sg",
                    "VpcId": {"Ref": "VpcId"},
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "SourceSecurityGroupId": {"Ref": "AlbSecurityGroup"},
                        }
                    ],
                },
            },
            "LoadBalancer": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Name": alb_name,
                    "Subnets": {"Ref": "SubnetIds"},
                    "SecurityGroups": [{"Ref": "AlbSecurityGroup"}],
                    "Scheme": "internet-facing",
                    "Type": "application",
                },
            },
            "TargetGroup": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {
                    "Name": tg_name,
                    "VpcId": {"Ref": "VpcId"},
                    "Port": 80,
                    "Protocol": "HTTP",
                    "TargetType": "ip",
                    "HealthCheckPath": "/",
                    "HealthCheckIntervalSeconds": 10,
                    "HealthyThresholdCount": 2,
                    "UnhealthyThresholdCount": 2,
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "LoadBalancer"},
                    "Port": 80,
                    "Protocol": "HTTP",
                    "DefaultActions": [{"Type": "forward", "TargetGroupArn": {"Ref": "TargetGroup"}}],
                },
            },
            "Service": {
                "Type": "AWS::ECS::Service",
                "DependsOn": "Listener",
                "Properties": {
                    "ServiceName": service_name,
                    "Cluster": {"Ref": "Cluster"},
                    "TaskDefinition": {"Ref": "TaskDefinition"},
                    "DesiredCount": 1,
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "AwsvpcConfiguration": {
                            "Subnets": {"Ref": "SubnetIds"},
                            "SecurityGroups": [{"Ref": "TaskSecurityGroup"}],
                            "AssignPublicIp": "ENABLED",
                        }
                    },
                    "LoadBalancers": [
                        {"ContainerName": "app", "ContainerPort": 80, "TargetGroupArn": {"Ref": "TargetGroup"}}
                    ],
                },
            },
        },
        "Outputs": {
            "TargetGroupArn": {"Value": {"Ref": "TargetGroup"}},
            "LoadBalancerDnsName": {"Value": {"Fn::GetAtt": ["LoadBalancer", "DNSName"]}},
        },
    }


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["AWS_PAGER"] = ""
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _short_name(ctx, prefix, max_len=32):
    name = ctx.unique_name(prefix)
    if len(name) <= max_len:
        return name
    return name[-max_len:].lstrip("-")


def _http_get_status(ctx, url, timeout_s=5.0):
    try:
        _url, _route = ctx.endpoint_route(url)
        with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=timeout_s) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError):
        return None


def _target_states(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    return [(d["Target"]["Id"], d["TargetHealth"]["State"]) for d in descs]


def _wait_stack_status(ctx, stack_name, target_status, timeout_s=900, interval_s=15):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        last = stacks[0]["StackStatus"]
        if last == target_status:
            return last
        if last.endswith("ROLLBACK_COMPLETE") or last.endswith("FAILED"):
            raise AssertionError(f"stack {stack_name} entered unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {target_status}, last status={last}")


def _delete_stack_and_wait(ctx, stack_name, timeout_s=900, interval_s=15):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


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
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
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
