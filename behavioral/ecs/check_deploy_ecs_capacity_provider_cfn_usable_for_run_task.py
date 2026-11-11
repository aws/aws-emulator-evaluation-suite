"""deploy-ecs-capacity-provider-cfn-usable-for-run-task."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-ecs-capacity-provider-cfn-usable-for-run-task"
GROUP = "deploy"
SERVICES = ["ecs"]

_SIM2REAL_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack with an ASG-backed ECS::CapacityProvider and ClusterCapacityProviderAssociations
    is usable: RunTask with that capacityProviderStrategy places a task on an instance from the ASG.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    subnet_id, sg_id = _default_subnet_and_sg(ec2, ctx=ctx)
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"
    )["Parameter"]["Value"]

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cp_name = ctx.unique_name("sim2real-behav-cp-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    params = [
        {"ParameterKey": "ClusterName", "ParameterValue": cluster_name},
        {"ParameterKey": "CapacityProviderName", "ParameterValue": cp_name},
        {"ParameterKey": "SubnetId", "ParameterValue": subnet_id},
        {"ParameterKey": "SecurityGroupId", "ParameterValue": sg_id},
        {"ParameterKey": "ImageId", "ParameterValue": ami_id},
    ]
    _deploy_cfn(ctx, stack_name, _CAPACITY_PROVIDER_TEMPLATE, params)

    ecs = ctx.client("ecs")
    container_instance_arn = _wait_container_instance_active(
        ecs, cluster_name, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    assert container_instance_arn, "no ACTIVE container instance arn returned for the ASG-backed capacity provider"

    family = ctx.unique_name("sim2real-behav-td-")
    ecs.register_task_definition(
        family=family,
        networkMode="bridge",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "command": ["sh", "-c", "sleep 300"],
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": t["Key"], "value": t["Value"]} for t in _SIM2REAL_TAGS],
    )
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, f"{family}:1"))

    run_resp = ecs.run_task(
        cluster=cluster_name,
        taskDefinition=family,
        count=1,
        capacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
        tags=[{"key": t["Key"], "value": t["Value"]} for t in _SIM2REAL_TAGS],
    )
    assert not run_resp.get("failures"), f"RunTask reported failures: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]

    def _stop_task() -> None:
        ecs.stop_task(cluster=cluster_name, task=task_arn)
        _wait_task_stopped(ecs, cluster_name, task_arn, timeout_s=120.0)

    ctx.on_cleanup(_stop_task)

    task = _wait_task_placed(ecs, cluster_name, task_arn, timeout_s=_budget_s(ctx, 180.0), ctx=ctx)
    if task["lastStatus"] == "STOPPED":
        raise AssertionError(
            f"task exited before reaching RUNNING; stoppedReason={task.get('stoppedReason')}"
        )
    assert task["launchType"] == "EC2", f"expected launchType EC2, got {task['launchType']!r}"
    assert task["containerInstanceArn"] == container_instance_arn, (
        f"task placed on containerInstanceArn={task['containerInstanceArn']!r}, "
        f"expected the ASG-registered instance {container_instance_arn!r}"
    )
    assert task["lastStatus"] == "RUNNING", f"expected RUNNING, got {task['lastStatus']!r}"



_CAPACITY_PROVIDER_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ClusterName": {"Type": "String"},
            "CapacityProviderName": {"Type": "String"},
            "SubnetId": {"Type": "String"},
            "SecurityGroupId": {"Type": "String"},
            "ImageId": {"Type": "String"},
        },
        "Resources": {
            "Cluster": {
                "Type": "AWS::ECS::Cluster",
                "Properties": {"ClusterName": {"Ref": "ClusterName"}},
            },
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
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
                        "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
                    ],
                },
            },
            "InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "InstanceRole"}]},
            },
            "LaunchTemplate": {
                "Type": "AWS::EC2::LaunchTemplate",
                "Properties": {
                    "LaunchTemplateData": {
                        "ImageId": {"Ref": "ImageId"},
                        "InstanceType": "t3.micro",
                        "IamInstanceProfile": {"Arn": {"Fn::GetAtt": ["InstanceProfile", "Arn"]}},
                        "SecurityGroupIds": [{"Ref": "SecurityGroupId"}],
                        "UserData": {
                            "Fn::Base64": {
                                "Fn::Sub": "#!/bin/bash\necho ECS_CLUSTER=${ClusterName} >> /etc/ecs/ecs.config\n"
                            }
                        },
                    }
                },
            },
            "Asg": {
                "Type": "AWS::AutoScaling::AutoScalingGroup",
                "DependsOn": ["InstanceProfile"],
                "Properties": {
                    "LaunchTemplate": {
                        "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                        "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                    },
                    "MinSize": "1",
                    "MaxSize": "1",
                    "DesiredCapacity": "1",
                    "VPCZoneIdentifier": [{"Ref": "SubnetId"}],
                    "NewInstancesProtectedFromScaleIn": False,
                },
            },
            "CapacityProvider": {
                "Type": "AWS::ECS::CapacityProvider",
                "Properties": {
                    "Name": {"Ref": "CapacityProviderName"},
                    "AutoScalingGroupProvider": {
                        "AutoScalingGroupArn": {"Ref": "Asg"},
                        "ManagedScaling": {"Status": "ENABLED", "TargetCapacity": 100},
                        "ManagedTerminationProtection": "DISABLED",
                    },
                },
            },
            "ClusterCPAssoc": {
                "Type": "AWS::ECS::ClusterCapacityProviderAssociations",
                "Properties": {
                    "Cluster": {"Ref": "Cluster"},
                    "CapacityProviders": [{"Ref": "CapacityProvider"}],
                    "DefaultCapacityProviderStrategy": [
                        {"CapacityProvider": {"Ref": "CapacityProvider"}, "Weight": 1}
                    ],
                },
            },
        },
    }
)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0

def _default_subnet_and_sg(ec2: Any, *, ctx) -> tuple[str, str]:

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account/region has no shared network VPC to launch the ASG instance into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    public = [s for s in subnets if s.get("MapPublicIpOnLaunch")]
    subnet_id = (public or subnets)[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _deploy_cfn(ctx: Any, stack_name: str, template_body: str, parameters: list) -> None:
    cfn = ctx.client("cloudformation")

    def _cleanup() -> None:
        ecs = ctx.client("ecs")
        cluster_name = next(p["ParameterValue"] for p in parameters if p["ParameterKey"] == "ClusterName")
        # The ClusterCapacityProviderAssociations delete handler does not reliably clear the
        # association, leaving the CapacityProvider undeletable (DELETE_FAILED). Disassociate first.
        try:
            ecs.put_cluster_capacity_providers(
                cluster=cluster_name, capacityProviders=[], defaultCapacityProviderStrategy=[]
            )
            for arn in ecs.list_container_instances(cluster=cluster_name).get("containerInstanceArns", []):
                ecs.deregister_container_instance(cluster=cluster_name, containerInstance=arn, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        # A first delete can fail while the ASG's instance is still terminating under the
        # capacity provider; the reasons are kept, and one more delete runs once it has settled.
        reasons = []
        for _ in range(2):
            cfn.delete_stack(StackName=stack_name)
            status = _wait_stack_deleted(cfn, stack_name, timeout_s=400.0)
            if status == "DELETE_COMPLETE":
                return
            reasons = [
                f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason')}"
                for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
                if e["ResourceStatus"] == "DELETE_FAILED"
            ][:5]
        raise AssertionError(f"stack {stack_name} did not delete ({status}): {reasons}")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters,
        Capabilities=["CAPABILITY_IAM"],
        OnFailure="DELETE",
        Tags=_SIM2REAL_TAGS,
    )
    ctx.on_cleanup(_cleanup)
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name,
            WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 900.0) // 2))},
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(
                f"stack {stack_name} reaching CREATE_COMPLETE: the run budget ended first; not graded"
            ) from exc
        raise


def _wait_stack_deleted(cfn: Any, stack_name: str, timeout_s: float) -> str:
    """Poll a deleting stack until it is gone or DELETE_FAILED; returns the final status."""
    deadline = time.monotonic() + timeout_s
    status = "DELETE_IN_PROGRESS"
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in exc.response["Error"].get("Message", ""):
                return "DELETE_COMPLETE"
            raise
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            return status
        time.sleep(2.0)
    return status


def _wait_container_instance_active(ecs: Any, cluster: str, timeout_s: float, ctx=None) -> str | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        arns = ecs.list_container_instances(cluster=cluster, status="ACTIVE").get(
            "containerInstanceArns", []
        )
        if arns:
            details = ecs.describe_container_instances(
                cluster=cluster, containerInstances=arns
            )["containerInstances"]
            active = [d for d in details if d["status"] == "ACTIVE" and d["agentConnected"]]
            if active:
                return active[0]["containerInstanceArn"]
        time.sleep(2.0)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(
            f"an ACTIVE, agent-connected container instance in {cluster}: the run budget ended first; "
            f"not graded")
    raise AssertionError(
        f"no ACTIVE, agent-connected container instance registered to {cluster} within {timeout_s}s"
    )


def _wait_task_placed(ecs: Any, cluster: str, task_arn: str, timeout_s: float, ctx=None) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if tasks and tasks[0]["lastStatus"] in ("RUNNING", "STOPPED"):
            return tasks[0]
        time.sleep(1.0)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"task {task_arn} leaving PENDING: the run budget ended first; not graded")
    raise AssertionError(f"task {task_arn} never left PENDING within {timeout_s}s")


def _wait_task_stopped(ecs: Any, cluster: str, task_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if not tasks or tasks[0]["lastStatus"] == "STOPPED":
            return
        time.sleep(2.0)


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
