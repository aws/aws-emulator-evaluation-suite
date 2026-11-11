"""submit-task-state-change-updates-task-record."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "submit-task-state-change-updates-task-record"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitTaskStateChange from the caller sets an EC2-launch task's lastStatus and stoppedReason,
    visible at once through DescribeTasks (AWS accepts it for Fargate tasks only from the
    Fargate agent, so an EC2 container instance hosts the task).
    """
    ecs = ctx.client("ecs")
    setup = _ec2_task_setup(ctx)
    cluster, task_arn = setup["cluster"], setup["task_arn"]

    before = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
    assert before["lastStatus"] != "STOPPED", before["lastStatus"]

    ecs.submit_task_state_change(
        cluster=cluster,
        task=task_arn,
        status="STOPPED",
        reason="sim2real-manual-agent-report",
    )

    after = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
    assert after["lastStatus"] == "STOPPED", after["lastStatus"]
    assert after.get("stoppedReason") == "sim2real-manual-agent-report", after.get("stoppedReason")


# ===== helpers =====

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
    sg_id = sgs[0]["GroupId"]
    return subnet_id, sg_id


def _registered_ec2_instance(ctx):
    

    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    subnet_id, sg_id = _default_vpc_subnet_and_sg(ctx)

    ami_id = json.loads(
        ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended")["Parameter"]["Value"]
    )["image_id"]

    role_name = ctx.unique_name("sim2real-ecsx-instrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    profile_name = ctx.unique_name("sim2real-ecsx-instprof-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)

    def _cleanup_profile():
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_instance_profile(InstanceProfileName=profile_name)

    ctx.on_cleanup(_cleanup_profile)

    cluster_name = ctx.unique_name("sim2real-ecsx-cluster-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n"

    instance_id = None
    last_err = None
    # A fresh instance profile is refused as InvalidParameterValue until IAM propagates it.
    deadline = time.monotonic() + 100.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
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
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ecsx-ec2-")}],
                    }
                ],
            )
            instance_id = run_resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] in ("InvalidParameterValue", "Client.InvalidParameterValue"):
                if time.monotonic() >= deadline:
                    break
                time.sleep(2)
                continue
            raise
    if instance_id is None:
        raise AssertionError(f"could not launch the ECS-optimized instance: {last_err}")

    def _terminate():
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return
            raise
        waiter = ec2.get_waiter("instance_terminated")
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    ctx.on_cleanup(_terminate)

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

    ctx.on_cleanup(
        lambda: ecs.deregister_container_instance(cluster=cluster_name, containerInstance=ci_arn, force=True)
    )

    return {"cluster": cluster_name, "container_instance_arn": ci_arn}


def _ec2_task_setup(ctx):
    ecs = ctx.client("ecs")
    instance_setup = _registered_ec2_instance(ctx)
    cluster_name = instance_setup["cluster"]

    family = ctx.unique_name("sim2real-ecsx-taskdef-")
    container_name = "app"
    reg = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["EC2"],
        networkMode="bridge",
        containerDefinitions=[
            {
                "name": container_name,
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                "essential": True,
                "cpu": 128,
                "memory": 128,
                "command": ["sleep", "300"],
            }
        ],
    )
    task_def_arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    tasks = []
    last_failures = None
    deadline = time.monotonic() + 200.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while True:
        resp = ecs.run_task(
            cluster=cluster_name,
            taskDefinition=task_def_arn,
            launchType="EC2",
            count=1,
        )
        tasks = resp.get("tasks", [])
        if tasks:
            break
        last_failures = resp.get("failures")
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if not tasks:
        raise AssertionError(f"RunTask never placed a task on the registered EC2 instance: failures={last_failures}")
    task_arn = tasks[0]["taskArn"]

    deadline = time.monotonic() + 180
    last_status = None
    while time.monotonic() < deadline:
        d = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn]).get("tasks", [])
        if d:
            last_status = d[0]["lastStatus"]
            if last_status in ("RUNNING", "STOPPED"):
                break
        time.sleep(5)
    if last_status != "RUNNING":
        raise AssertionError(
            f"task never reached RUNNING on the registered EC2 instance: {last_status}",
        )

    def _stop_and_wait():
        try:
            ecs.stop_task(cluster=cluster_name, task=task_arn, reason="sim2real-cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            d = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn]).get("tasks", [])
            if not d or d[0]["lastStatus"] == "STOPPED":
                return
            time.sleep(3)

    ctx.on_cleanup(_stop_and_wait)

    return {
        "cluster": cluster_name,
        "task_arn": task_arn,
        "container_name": container_name,
    }


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                    "ServiceNotActiveException",
                ):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
