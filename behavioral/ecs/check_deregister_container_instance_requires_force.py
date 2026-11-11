"""deregister-container-instance-requires-force."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deregister-container-instance-requires-force"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not be reported as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _launch_real_container_instance(ctx, ecs, cluster, *, timeout_s=200):
    """Launch a real (minimal) EC2 instance that self-registers as an ECS
    container instance via the genuine ECS agent.
    """
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

    last_exc = None
    instance_id = None
    left = ctx.time_left()
    deadline = time.monotonic() + (40.0 if left is None else min(40.0, left))
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
                UserData=user_data,
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except Exception as exc:  # noqa: BLE001 — IAM propagation lag surfaces as a ClientError
            last_exc = exc
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
    if instance_id is None:
        raise last_exc or RuntimeError("failed to launch container-instance EC2 host")
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterContainerInstance without force on an instance that still has a task placed on it
    fails rather than deregistering it out from under a live task; once the task is stopped, the
    same call without force succeeds."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    ci = _launch_real_container_instance(ctx, ecs, name)
    ci_arn = ci["containerInstanceArn"]
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "memory": 128,
                "command": ["sleep", "300"],
            }
        ],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))

    started = ecs.start_task(
        cluster=name, containerInstances=[ci_arn], taskDefinition=td["taskDefinitionArn"]
    )
    assert not started.get("failures"), f"unexpected StartTask failures: {started.get('failures')}"
    task_arn = started["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=name, task=task_arn, reason="behavioral-cleanup"))

    def _placed_task():
        # DescribeTasks is eventually consistent right after StartTask — the
        # task ARN can be briefly absent, so tolerate an empty list instead of
        # indexing [0] and let the poll retry until it appears.
        tasks = ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"]
        return tasks[0] if tasks else None

    _poll_until(
        _placed_task,
        lambda t: t is not None and t["lastStatus"] in ("RUNNING", "PENDING", "ACTIVATING"),
        timeout_s=90,
        interval_s=5,
        description="the placed task is at least PENDING before we attempt to deregister its host",
    )

    # overly-permissive boundary: can't deregister a busy instance without force.
    code, message = _error(
        lambda: ecs.deregister_container_instance(cluster=name, containerInstance=ci_arn)
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException deregistering an instance with a live task and no "
        f"force flag, got {code}"
    )
    assert message == "Found running tasks on the instance.", f"unexpected message: {message!r}"
    still_there = ecs.describe_container_instances(cluster=name, containerInstances=[ci_arn])[
        "containerInstances"
    ][0]
    assert still_there["status"] == "ACTIVE", (
        f"a rejected deregister attempt must not have changed the instance's status, "
        f"got {still_there['status']}"
    )

    ecs.stop_task(cluster=name, task=task_arn, reason="clearing instance for deregister")
    _poll_until(
        lambda: ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=120,
        interval_s=5,
        description="the task reaches STOPPED before retrying deregister",
    )

    ecs.deregister_container_instance(cluster=name, containerInstance=ci_arn)

    listed_after = ecs.list_container_instances(cluster=name)["containerInstanceArns"]
    assert ci_arn not in listed_after, (
        "the identical deregister call must succeed once the task is stopped and remove the "
        f"instance from ListContainerInstances, but it is still listed: {listed_after}"
    )
    described_after = ecs.describe_container_instances(cluster=name, containerInstances=[ci_arn])[
        "containerInstances"
    ]
    assert described_after and described_after[0]["status"] == "INACTIVE", (
        "the restored deregister call must transition the instance to INACTIVE, got "
        f"{described_after[0]['status'] if described_after else 'missing from DescribeContainerInstances'}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
