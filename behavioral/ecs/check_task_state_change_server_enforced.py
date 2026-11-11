"""task-state-change-server-enforced."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "task-state-change-server-enforced"
GROUP = 'task-lifecycle'
SERVICES = ['ecs']

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
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


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _run_fargate_task(ctx, ecs, cluster, task_definition_arn, **kwargs):
    ec2 = ctx.client("ec2")
    subnets = _default_subnets(ec2, ctx=ctx)
    sg = _default_sg(ec2, ctx=ctx)
    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=task_definition_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
        **kwargs,
    )
    for t in resp.get("tasks", []):
        ctx.on_cleanup(lambda a=t["taskArn"]: ecs.stop_task(cluster=cluster, task=a, reason="behavioral-cleanup"))
    return resp


def _launch_real_container_instance(ctx, ecs, cluster, *, timeout_s=200):
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

    last_exc = None
    instance_id = None
    left = ctx.time_left()
    launch_deadline = time.monotonic() + (40.0 if left is None else min(40.0, left))
    while instance_id is None and time.monotonic() < launch_deadline:
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
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ecs-ci-")}],
                    }
                ],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except Exception as exc:  # noqa: BLE001 — IAM propagation lag surfaces as a ClientError
            last_exc = exc
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """State changes are validated server-side: an unknown container name and a Fargate-task report
    are refused, an out-of-enum attachment status is refused, and an idempotent RUNNING report on a
    task placed on a registered EC2 container instance is accepted as a no-op.
    """
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    cluster = ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])["cluster"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    account_id = cluster["clusterArn"].split(":")[4]

    # overly-permissive boundary: a Fargate task has no container-instance
    # identity to verify — SubmitTaskStateChange against one must be denied.
    fg_family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    fargate_task_def = ecs.register_task_definition(
        family=fg_family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[fargate_task_def["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=fargate_task_def["taskDefinitionArn"]))
    fargate_run = _run_fargate_task(ctx, ecs, name, fargate_task_def["taskDefinitionArn"])
    assert not fargate_run.get("failures"), fargate_run.get("failures")
    fargate_task = fargate_run["tasks"][0]
    fargate_task_arn = fargate_task["taskArn"]

    # RunTask returns the freshly created ENI attachment inline (typically PRECREATED);
    # use its REAL id so the enum-status negative below isolates exactly one broken
    # variable (the status value) instead of also being rejectable for naming an
    # attachment that does not exist.
    eni_attachments = [
        a for a in fargate_task.get("attachments", []) if a.get("type") == "ElasticNetworkInterface"
    ]
    assert eni_attachments, (
        f"expected RunTask to return an ElasticNetworkInterface attachment for the Fargate task, "
        f"got {fargate_task.get('attachments')}"
    )
    real_attachment_arn = f"arn:aws:ecs:{ctx.region}:{account_id}:attachment/{eni_attachments[0]['id']}"

    error = _error(
        lambda: ecs.submit_task_state_change(cluster=name, task=fargate_task_arn, status="RUNNING")
    )
    expected = ("AccessDeniedException", "Fargate task state changes from the agent must have the instance verified")
    assert error == expected, (
        f"expected {expected!r} submitting an agent-facing task state change for a "
        f"Fargate task (no verifiable container-instance identity), got {error!r}"
    )

    # overly-permissive boundary: an out-of-enum attachment status must be rejected,
    # against a REAL attachment ARN so the only broken thing is the status value.
    bad_status = _error(
        lambda: ecs.submit_attachment_state_changes(
            cluster=name,
            attachments=[{"attachmentArn": real_attachment_arn, "status": "NOT_A_REAL_STATUS"}],
        )
    )
    expected = ("InvalidParameterException", "attachmentStatus should be one of [ATTACHED]")
    assert bad_status == expected, (
        f"expected {expected!r} for an out-of-enum attachment status on a real attachment, got {bad_status!r}"
    )

    # A REAL, genuinely-registered container instance DOES have a verifiable identity.
    ci = _launch_real_container_instance(ctx, ecs, name)
    ci_arn = ci["containerInstanceArn"]
    ec2_family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    ec2_task_def = ecs.register_task_definition(
        family=ec2_family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 64,
                "memory": 128,
                "essential": True,
                "command": ["sleep", "600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[ec2_task_def["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=ec2_task_def["taskDefinitionArn"]))
    started = ecs.start_task(
        cluster=name, containerInstances=[ci_arn], taskDefinition=ec2_task_def["taskDefinitionArn"]
    )
    assert not started.get("failures"), f"unexpected StartTask failures: {started.get('failures')}"
    task_arn = started["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=name, task=task_arn, reason="behavioral-cleanup"))

    def _task():
        # DescribeTasks is eventually consistent right after StartTask; the task can be briefly
        # absent, so return None instead of indexing an
        # empty list.
        tasks = ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"]
        return tasks[0] if tasks else None

    def _container():
        return next(c for c in _task().get("containers", []) if c.get("name") == "app")

    running_task = _poll_until(
        _task,
        lambda t: t is not None and t["lastStatus"] == "RUNNING",
        timeout_s=180,
        interval_s=5,
        description="the EC2-backed task reaches RUNNING via the real agent",
    )
    assert running_task["lastStatus"] == "RUNNING", (
        f"expected the EC2-backed task to reach RUNNING, got {running_task['lastStatus']!r}"
    )
    original_container_count = len(running_task.get("containers", []))

    # Positive control for the Fargate boundary above: the SAME API
    # (SubmitTaskStateChange), submitted against a task on a REAL,
    # genuinely-registered container instance, must succeed — unlike the
    # Fargate case, this task has a verifiable container-instance identity.
    ecs.submit_task_state_change(cluster=name, task=task_arn, status="RUNNING", reason="probe-positive-control")
    after_task_positive_control = _task()
    assert after_task_positive_control["lastStatus"] == "RUNNING", (
        f"expected an idempotent RUNNING task-state report on a real container instance to remain a "
        f"no-op, got {after_task_positive_control}"
    )

    # Legitimate, idempotent report of the task's own already-true status.
    ecs.submit_container_state_change(
        cluster=name, task=task_arn, containerName="app", status="RUNNING", reason="probe-idempotent-report"
    )
    after_idempotent = _container()
    assert after_idempotent.get("lastStatus") == "RUNNING", (
        f"expected an idempotent RUNNING report to remain a no-op, got {after_idempotent}"
    )

    # Server-side validation against the authoritative task definition: a
    # container name never part of this task must be rejected outright.
    bad_container = _error(
        lambda: ecs.submit_task_state_change(
            cluster=name,
            task=task_arn,
            containers=[{"containerName": "not-a-real-container-on-this-task", "status": "RUNNING"}],
            reason="probe-unknown-container",
        )
    )
    expected = (
        "InvalidParameterException",
        f"Unable to find container not-a-real-container-on-this-task for task {task_arn.rsplit('/', 1)[-1]}",
    )
    assert bad_container == expected, (
        f"expected {expected!r} naming an unknown container in a state-change payload, "
        f"got {bad_container!r}"
    )
    after_bogus_container = _task()
    assert len(after_bogus_container.get("containers", [])) == original_container_count, (
        "a rejected state-change payload naming an unknown container must not fabricate a new "
        f"container record: {after_bogus_container.get('containers')}"
    )
    assert not any(
        c.get("name") == "not-a-real-container-on-this-task"
        for c in after_bogus_container.get("containers", [])
    ), after_bogus_container.get("containers")



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
                if exc.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
