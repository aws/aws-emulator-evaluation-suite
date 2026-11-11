"""task-state-change-ordering-enforced."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-state-change-ordering-enforced"
GROUP = "ordering"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stale SubmitTaskStateChange reporting RUNNING for a task ECS already recorded as STOPPED
    is rejected or ignored: lastStatus never regresses. It runs on an EC2 container instance (Fargate
    denies the call to all callers), after a positive control drives the task to STOPPED.
    """
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real-check", "value": CHECK}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, cluster_arn))

    ci_arn = _launch_real_container_instance(ctx, ecs, cluster_arn)

    family = ctx.unique_name("sim2real-behav-td-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "c",
                "image": "public.ecr.aws/docker/library/alpine:3.20",
                "essential": True,
                "memory": 128,
                "command": ["sleep", "600"],
            }
        ],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    started = ecs.start_task(
        cluster=cluster_arn, containerInstances=[ci_arn], taskDefinition=task_def_arn
    )
    if started.get("failures"):
        raise AssertionError(f"StartTask produced failures: {started['failures']}")
    task_arn = started["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: _safe(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="behavioral-cleanup"))
    )

    def _describe() -> dict[str, Any]:
        tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
        return tasks[0] if tasks else None

    running_task = _poll_until(
        _describe, lambda t: t is not None and t["lastStatus"] == "RUNNING", timeout_s=180.0, interval_s=5.0
    )
    assert running_task["lastStatus"] == "RUNNING"

    # Positive control: a legitimate SubmitTaskStateChange from this principal, on this
    # exact wiring, must actually take effect -- proving the negative below tests ordering
    # enforcement specifically, not a blanket denial of every caller-submitted report.
    ecs.submit_task_state_change(
        cluster=cluster_arn, task=task_arn, status="STOPPED", reason="legit-terminal-report"
    )
    stopped_task = _poll_until(
        _describe, lambda t: t is not None and t["lastStatus"] == "STOPPED", timeout_s=60.0, interval_s=3.0
    )
    assert stopped_task["lastStatus"] == "STOPPED"
    assert stopped_task["desiredStatus"] == "STOPPED"

    # Inject a stale, out-of-order state report: the (fictitious) agent claims the task
    # is RUNNING again, after ECS already recorded it as STOPPED via the legitimate
    # report above.
    call_error_code = None
    try:
        ecs.submit_task_state_change(cluster=cluster_arn, task=task_arn, status="RUNNING", reason="stale-report")
    except ClientError as exc:
        call_error_code = exc.response.get("Error", {}).get("Code")

    # Whether the stale call was rejected outright or silently accepted-but-ignored, the
    # task's recorded status must never regress backward from the terminal state that the
    # positive control above already proved this same call can legitimately reach.
    final_task = _describe()
    assert final_task["lastStatus"] == "STOPPED", (
        f"task lastStatus regressed after stale out-of-order state change: {final_task['lastStatus']} "
        f"(submit_task_state_change error={call_error_code!r})"
    )
    assert final_task["desiredStatus"] == "STOPPED"


# ===== helpers =====
def _default_vpc_id(ec2, *, ctx) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _default_subnets(ec2, *, ctx) -> list[str]:
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnets available in this account/region")
    return [s["SubnetId"] for s in subnets]


def _default_sg(ec2, *, ctx) -> str:
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available in this account/region")
    return sgs[0]["GroupId"]


def _launch_real_container_instance(ctx, ecs, cluster_arn: str, *, timeout_s: float = 200.0) -> str:
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    subnets = _default_subnets(ec2, ctx=ctx)
    sg = _default_sg(ec2, ctx=ctx)
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]

    role_name = ctx.unique_name("sim2real-ecsInstRole-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name))
    )
    profile_arn = iam.get_instance_profile(InstanceProfileName=role_name)["InstanceProfile"]["Arn"]

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_arn} >> /etc/ecs/ecs.config\n"

    last_exc: Exception | None = None
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
                UserData=user_data,
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
                ],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:  # IAM role/instance-profile propagation lag
            last_exc = exc
            time.sleep(2)
    if instance_id is None:
        raise AssertionError(f"failed to launch container-instance EC2 host: {last_exc}")
    ctx.on_cleanup(lambda: _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _find():
        arns = ecs.list_container_instances(cluster=cluster_arn).get("containerInstanceArns", [])
        if not arns:
            return None
        described = ecs.describe_container_instances(cluster=cluster_arn, containerInstances=arns)[
            "containerInstances"
        ]
        for ci in described:
            if ci.get("ec2InstanceId") == instance_id:
                return ci
        return None

    ci = _poll_until(
        _find, lambda x: x is not None, timeout_s=timeout_s, interval_s=10.0
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ecs.deregister_container_instance(
                cluster=cluster_arn, containerInstance=ci["containerInstanceArn"], force=True
            )
        )
    )
    return ci["containerInstanceArn"]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "InvalidInstanceID.NotFound",
            "NoSuchEntity",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _safe_delete_cluster(ecs, cluster_arn: str) -> None:
    # DeleteCluster is refused until the container instance and tasks are gone; retry only that.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in (
                "ClusterContainsServicesException", "ClusterContainsTasksException",
                "ClusterContainsContainerInstancesException", "UpdateInProgressException",
            ) or time.monotonic() >= deadline:
                raise
            time.sleep(2)


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
