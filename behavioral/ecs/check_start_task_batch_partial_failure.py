"""start-task-batch-partial-failure."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-task-batch-partial-failure"
GROUP = 'task-execution'
SERVICES = ['ecs']

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "cpu": 64,
        "memory": 128,
        "essential": True,
    }
]


def _default_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _default_subnets(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnets available in this account/region")
    return [s["SubnetId"] for s in subnets]


def _default_sg(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available in this account/region")
    return sgs[0]["GroupId"]


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _launch_real_container_instance(ctx, ecs, cluster, *, timeout_s=200):
    """Launch a minimal EC2 instance that self-registers as an ECS container instance; the
    instance-identity document RegisterContainerInstance validates cannot be synthesized."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    subnets = _default_subnets(ec2, ctx=ctx)
    sg = _default_sg(ec2, ctx=ctx)
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]

    role_name = ctx.unique_name("ecsInstanceRole-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    )
    profile_arn = iam.get_instance_profile(InstanceProfileName=role_name)["InstanceProfile"]["Arn"]

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n"
    encoded_user_data = base64.b64encode(user_data.encode()).decode()

    # A fresh instance profile is refused as an invalid iamInstanceProfile until IAM propagates it.
    deadline = time.monotonic() + 40.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while True:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Arn": profile_arn},
                SubnetId=subnets[0],
                SecurityGroupIds=[sg],
                UserData=encoded_user_data,
                TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": role_name}]}],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] != "InvalidParameterValue" or "iamInstanceProfile" not in err.get("Message", "")
                    or time.monotonic() >= deadline):
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    def _find():
        arns = ecs.list_container_instances(cluster=cluster).get("containerInstanceArns", [])
        if not arns:
            return None
        described = ecs.describe_container_instances(cluster=cluster, containerInstances=arns)[
            "containerInstances"
        ]
        for ci in described:
            if ci.get("ec2InstanceId") == instance_id:
                return ci
        return None

    ci = _poll_until(
        _find,
        lambda x: x is not None,
        timeout_s=timeout_s,
        interval_s=10,
        description="EC2 instance registers as an ECS container instance",
    )
    ctx.on_cleanup(
        lambda: ecs.deregister_container_instance(
            cluster=cluster, containerInstance=ci["containerInstanceArn"], force=True
        )
    )
    return ci


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartTask over one real ACTIVE container instance and one nonexistent instance ARN
    partially succeeds: the real instance gets a task and the bogus ARN is reported in failures[]."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    ci = _launch_real_container_instance(ctx, ecs, name)
    ci_arn = ci["containerInstanceArn"]
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=DEFAULT_CONTAINER_DEFS,
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))

    account_id = ci_arn.split(":")[4]
    bogus_ci_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/{name}/"
        "00000000-0000-0000-0000-000000000000"
    )

    resp = ecs.start_task(
        cluster=name,
        containerInstances=[ci_arn, bogus_ci_arn],
        taskDefinition=td["taskDefinitionArn"],
    )
    assert len(resp.get("tasks", [])) == 1, (
        f"expected exactly one successfully-placed task (the real instance), got {resp.get('tasks')}"
    )
    placed_task = resp["tasks"][0]
    assert placed_task["containerInstanceArn"] == ci_arn
    task_arn = placed_task["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=name, task=task_arn, reason="behavioral-cleanup"))

    failures = resp.get("failures", [])
    assert len(failures) == 1, f"expected exactly one failures[] entry for the bogus instance, got {failures}"
    failure_arn = failures[0].get("arn", "")
    assert failure_arn.rsplit("/", 1)[-1] == bogus_ci_arn.rsplit("/", 1)[-1] or failure_arn == bogus_ci_arn, (
        f"expected the failures[] entry to reference the bogus instance, got {failures[0]}"
    )
    assert failures[0].get("reason") == "MISSING", (
        f"expected reason MISSING for a never-registered container instance, got {failures[0]}"
    )

    # Independent ListTasks read: exactly the one placed task exists, none for the bogus entry.
    task_arns = ecs.list_tasks(cluster=name).get("taskArns", [])
    assert task_arns == [task_arn], (
        f"expected exactly the placed task {task_arn!r} to be visible in the cluster, got {task_arns}"
    )
    described = ecs.describe_tasks(cluster=name, tasks=[task_arn]).get("tasks", [])
    assert len(described) == 1, f"expected the placed task to be independently readable via DescribeTasks, got {described}"
    assert described[0]["containerInstanceArn"] == ci_arn, (
        f"expected DescribeTasks to confirm placement on the real instance, got {described[0]}"
    )
    assert described[0]["lastStatus"] != "STOPPED", (
        f"expected the placed task to still be alive shortly after StartTask, got {described[0]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
