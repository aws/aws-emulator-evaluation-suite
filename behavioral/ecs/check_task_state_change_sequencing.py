"""task-state-change-sequencing."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "task-state-change-sequencing"
GROUP = 'task-lifecycle'
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
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
    """Once a short-lived task on an EC2 container instance is STOPPED, a stale
    SubmitTaskStateChange(status=RUNNING) does not regress DescribeTasks' lastStatus, and the
    call against an unknown cluster fails with ClientException.
    """
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))

    # overly-permissive boundary: an unusable/unknown cluster identifier must
    # be rejected outright (empirically ClientException for this agent-facing
    # API, rather than the ClusterNotFoundException used by client-facing ops).
    bogus_cluster = ctx.unique_name("no-such-cluster-")
    error = _error(
        lambda: ecs.submit_task_state_change(cluster=bogus_cluster, task="0" * 32, status="RUNNING")
    )
    expected = ("ClientException", "Cluster not found.")
    assert error == expected, f"expected {expected!r}, got {error!r}"

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
                "command": ["sh", "-c", "sleep 2"],
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

    def _task():
        # DescribeTasks is eventually consistent right after StartTask — the
        # just-started task ARN can be briefly absent, so tolerate an empty list
        # instead of indexing [0] and let the poll retry until it appears.
        tasks = ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"]
        return tasks[0] if tasks else None

    terminal = _poll_until(
        _task,
        lambda t: t is not None and t["lastStatus"] == "STOPPED",
        timeout_s=180,
        interval_s=5,
        description="short-lived task naturally reaches STOPPED",
    )
    assert terminal["lastStatus"] == "STOPPED", (
        f"expected the short-lived task to reach STOPPED naturally, got {terminal['lastStatus']!r}"
    )

    # Out-of-order/stale signal: try to resurrect the terminal task.
    ecs.submit_task_state_change(cluster=name, task=task_arn, status="RUNNING", reason="stale-replay")

    still_terminal = ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"][0]
    assert still_terminal["lastStatus"] == "STOPPED", (
        f"a stale out-of-order SubmitTaskStateChange(RUNNING) must not regress a STOPPED task, "
        f"got {still_terminal['lastStatus']}"
    )

    # Duplicate terminal signal must also be a safe no-op.
    ecs.submit_task_state_change(cluster=name, task=task_arn, status="STOPPED", reason="duplicate-replay")
    still_terminal2 = ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"][0]
    assert still_terminal2["lastStatus"] == "STOPPED", (
        f"a duplicate SubmitTaskStateChange(STOPPED) must remain a no-op, got {still_terminal2['lastStatus']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
