"""deregister-container-instance-with-running-tasks-requires-force."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deregister-container-instance-with-running-tasks-requires-force"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterContainerInstance without force on an instance with a placed task is rejected
    (InvalidParameterException) and the instance stays ACTIVE; with force=true it is removed."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-dcinst-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: ecs.delete_cluster(cluster=cluster_arn)))

    # RegisterContainerInstance requires an AWS-signed instance identity document, so a real
    # ECS-optimized instance is launched and its agent self-registers.
    container_instance_arn = _registered_ec2_instance(ctx, cluster_name)

    family = ctx.unique_name("sim2real-dcinst-td")
    td_arn = ecs.register_task_definition(
        family=family,
        networkMode="bridge",
        requiresCompatibilities=["EC2"],
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 128,
                "memory": 128,
                "essential": True,
                "command": ["sleep", "300"],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    start = ecs.start_task(
        cluster=cluster_arn, containerInstances=[container_instance_arn], taskDefinition=td_arn
    )
    assert start["failures"] == [], f"unexpected StartTask failures: {start['failures']}"
    task_arn = start["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn)))

    # wait until the container instance's own counters reflect the placed task
    active_count = _poll_until(
        lambda: _pending_plus_running(ecs, cluster_arn, container_instance_arn),
        lambda n: n >= 1,
        timeout_s=30.0,
        interval_s=1.5,
    )
    assert active_count >= 1, "container instance never reflected the placed task"

    # --- Negative: deregister without force must be refused ---
    code, msg = _error_code(
        lambda: ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=container_instance_arn)
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException deregistering an instance with active tasks, got {code}: {msg}"
    )
    assert msg == "Found running tasks on the instance.", f"unexpected message: {msg!r}"

    # the forbidden effect did not happen: instance is still registered and ACTIVE
    still = ecs.describe_container_instances(
        cluster=cluster_arn, containerInstances=[container_instance_arn]
    )["containerInstances"][0]
    assert still["status"] == "ACTIVE", f"instance status changed despite the refused call: {still['status']}"

    # --- Positive control: force=true on the SAME instance succeeds ---
    forced = ecs.deregister_container_instance(
        cluster=cluster_arn, containerInstance=container_instance_arn, force=True
    )["containerInstance"]
    assert forced["status"] != "ACTIVE", f"force deregistration did not change status: {forced['status']}"

    remaining = ecs.list_container_instances(cluster=cluster_arn)["containerInstanceArns"]
    assert container_instance_arn not in remaining, "instance still listed as active after forced deregistration"



_MISSING_CODES = {"ClusterNotFoundException", "NoSuchEntity", "InvalidInstanceID.NotFound"}
_IN_USE_CODES = {"ClusterContainsTasksException", "ClusterContainsContainerInstancesException", "DeleteConflict"}


def _teardown(fn, timeout_s: float = 120.0) -> None:
    """Run a teardown step: return once it succeeds or its target is already gone, retry while a
    dependency is still being released, raise anything else."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _MISSING_CODES:
                return
            if code not in _IN_USE_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _pending_plus_running(ecs, cluster_arn: str, container_instance_arn: str) -> int:
    ci = ecs.describe_container_instances(
        cluster=cluster_arn, containerInstances=[container_instance_arn]
    )["containerInstances"][0]
    return int(ci["pendingTasksCount"]) + int(ci["runningTasksCount"])


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    return result


def _default_vpc_subnet_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    sg_id = sgs[0]["GroupId"]
    return subnet_id, sg_id


def _registered_ec2_instance(ctx, cluster_name: str) -> str:
    """Launch a real ECS-optimized EC2 instance whose agent self-registers into the
    given (already-created) cluster, and return its container instance ARN once
    ACTIVE and agent-connected."""
    from botocore.exceptions import ClientError

    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    subnet_id, sg_id = _default_vpc_subnet_and_sg(ctx)

    ami_id = json.loads(
        ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended")["Parameter"]["Value"]
    )["image_id"]

    role_name = ctx.unique_name("sim2real-dcinst-instrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=role_name)))

    profile_name = ctx.unique_name("sim2real-dcinst-instprof-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)

    def _cleanup_profile():
        _teardown(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
        _teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _teardown(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    ctx.on_cleanup(_cleanup_profile)

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n"

    instance_id = None
    last_err = None
    left = ctx.time_left()
    launch_deadline = time.monotonic() + (100.0 if left is None else min(100.0, left))
    while True:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                IamInstanceProfile={"Name": profile_name},
                UserData=user_data,
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dcinst-ec2-")}],
                    }
                ],
            )
            instance_id = run_resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] not in ("InvalidParameterValue", "Client.InvalidParameterValue"):
                raise
            if time.monotonic() >= launch_deadline:
                break
            time.sleep(2)
    if instance_id is None:
        raise AssertionError(f"could not launch the ECS-optimized instance: {last_err}")

    def _terminate():
        ec2.terminate_instances(InstanceIds=[instance_id])
        waiter = ec2.get_waiter("instance_terminated")
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    ctx.on_cleanup(lambda: _teardown(_terminate))

    ci_arn = None
    deadline = time.monotonic() + 480
    while time.monotonic() < deadline:
        arns = ecs.list_container_instances(cluster=cluster_name).get("containerInstanceArns", [])
        if arns:
            described = ecs.describe_container_instances(cluster=cluster_name, containerInstances=arns)[
                "containerInstances"
            ]
            active = [c for c in described if c["status"] == "ACTIVE" and c["agentConnected"]]
            if active:
                ci_arn = active[0]["containerInstanceArn"]
                break
        time.sleep(2)

    if ci_arn is None:
        raise AssertionError("EC2 container instance never registered with a connected agent within the poll budget")

    def _deregister_if_registered():
        described = ecs.describe_container_instances(cluster=cluster_name, containerInstances=[ci_arn])
        if any(c["status"] != "INACTIVE" for c in described["containerInstances"]):
            ecs.deregister_container_instance(cluster=cluster_name, containerInstance=ci_arn, force=True)

    ctx.on_cleanup(lambda: _teardown(_deregister_if_registered))

    return ci_arn


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
