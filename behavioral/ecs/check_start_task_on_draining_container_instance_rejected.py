"""start-task-on-draining-container-instance-rejected."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-task-on-draining-container-instance-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartTask targeting a container instance that has been placed in
    DRAINING status is rejected as a placement failure -- the exact same
    instance accepts a task while ACTIVE and refuses one once DRAINING."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    subnet_id, sg_id, vpc_id = _default_network(ctx)
    ami_id = _latest_ecs_optimized_ami(ctx)
    profile_name, profile_arn = _create_ecs_instance_profile(ctx)

    cluster_name = ctx.unique_name("sim2real-draining-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    user_data = base64.b64encode(f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n".encode()).decode()
    instance_id = _launch_instance_with_retry(ec2, ami_id, subnet_id, sg_id, profile_name, user_data, ctx)
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    container_instance_arn = _poll_until(
        lambda: _find_container_instance(ecs, cluster_arn, instance_id),
        lambda arn: arn is not None,
        timeout_s=420,
        interval_s=15,
        description="EC2 instance to register as an ECS container instance",
    )
    ctx.on_cleanup(
        lambda: ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=container_instance_arn, force=True)
    )

    family = ctx.unique_name("sim2real-draining-td-")
    taskdef = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "memory": 64,
                "command": ["sleep", "120"],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=taskdef))
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[taskdef]))

    # Positive control: the container instance is ACTIVE and accepts a task.
    resp = ecs.start_task(
        cluster=cluster_arn, containerInstances=[container_instance_arn], taskDefinition=taskdef
    )
    assert resp["failures"] == [], f"StartTask failed on an ACTIVE container instance: {resp['failures']}"
    assert len(resp["tasks"]) == 1, f"expected exactly one task placed on the ACTIVE instance, got: {resp['tasks']}"
    control_task_arn = resp["tasks"][0]["taskArn"]
    ecs.stop_task(cluster=cluster_arn, task=control_task_arn)

    # Drain the instance.
    ecs.update_container_instances_state(
        cluster=cluster_arn, containerInstances=[container_instance_arn], status="DRAINING"
    )
    _poll_until(
        lambda: ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[container_instance_arn])[
            "containerInstances"
        ][0]["status"],
        lambda status: status == "DRAINING",
        timeout_s=60,
        interval_s=3,
        description="container instance to reach DRAINING",
    )

    # Negative: StartTask against the same, now-DRAINING instance is rejected
    # as a per-instance placement failure, not a raised exception.
    resp = ecs.start_task(
        cluster=cluster_arn, containerInstances=[container_instance_arn], taskDefinition=taskdef
    )
    assert resp["tasks"] == [], f"a task was placed on a DRAINING container instance: {resp['tasks']}"
    assert len(resp["failures"]) == 1, f"expected exactly one placement failure, got: {resp['failures']}"
    failure = resp["failures"][0]
    # StartTask's own failure record names the container instance in the short ARN
    # form (no cluster-name segment), unlike DescribeContainerInstances -- compare
    # the instance id, not the full ARN string.
    assert failure["arn"].rsplit("/", 1)[-1] == container_instance_arn.rsplit("/", 1)[-1], (
        f"placement failure named the wrong instance: expected {container_instance_arn}, got {failure['arn']}"
    )
    assert failure.get("reason"), "placement failure carried no reason"

    # Effect-absent, via an independent read: the DRAINING instance itself must show
    # no running or pending task, not just an empty StartTask response.
    described = ecs.describe_container_instances(
        cluster=cluster_arn, containerInstances=[container_instance_arn]
    )["containerInstances"][0]
    assert described["runningTasksCount"] == 0, (
        f"expected 0 running tasks on the DRAINING instance, got {described['runningTasksCount']}"
    )
    assert described["pendingTasksCount"] == 0, (
        f"expected 0 pending tasks on the DRAINING instance, got {described['pendingTasksCount']}"
    )

    # Restore: DRAINING is a reversible state, so undrain the same instance and prove
    # the identical StartTask call now succeeds -- this is what tells "rejects DRAINING"
    # apart from "rejects this instance for any other reason".
    ecs.update_container_instances_state(
        cluster=cluster_arn, containerInstances=[container_instance_arn], status="ACTIVE"
    )
    _poll_until(
        lambda: ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[container_instance_arn])[
            "containerInstances"
        ][0]["status"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=3,
        description="container instance to reach ACTIVE after undraining",
    )
    resp = ecs.start_task(
        cluster=cluster_arn, containerInstances=[container_instance_arn], taskDefinition=taskdef
    )
    assert resp["failures"] == [], f"StartTask failed after restoring ACTIVE: {resp['failures']}"
    assert len(resp["tasks"]) == 1, f"expected exactly one task placed after restore, got: {resp['tasks']}"
    ecs.stop_task(cluster=cluster_arn, task=resp["tasks"][0]["taskArn"])


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {description} (last value: {result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


def _find_container_instance(ecs, cluster_arn, instance_id):
    arns = ecs.list_container_instances(cluster=cluster_arn)["containerInstanceArns"]
    if not arns:
        return None
    described = ecs.describe_container_instances(cluster=cluster_arn, containerInstances=arns)["containerInstances"]
    for ci in described:
        if ci.get("ec2InstanceId") == instance_id and ci["agentConnected"] and ci["status"] == "ACTIVE":
            return ci["containerInstanceArn"]
    return None


def _latest_ecs_optimized_ami(ctx):
    ssm = ctx.client("ssm")
    value = ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended")["Parameter"]["Value"]
    return json.loads(value)["image_id"]


def _create_ecs_instance_profile(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsinst-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    profile_name = ctx.unique_name("sim2real-ecsinst-prof-")
    profile_arn = iam.create_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
    return profile_name, profile_arn


def _launch_instance_with_retry(ec2, ami_id, subnet_id, sg_id, profile_name, user_data, ctx, attempts=8, delay_s=10):
    last_err = None
    for _ in range(attempts):
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                UserData=user_data,
                NetworkInterfaces=[
                    {
                        "DeviceIndex": 0,
                        "SubnetId": subnet_id,
                        "Groups": [sg_id],
                        "AssociatePublicIpAddress": True,
                    }
                ],
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ecsinst-")}]}
                ],
            )
            return resp["Instances"][0]["InstanceId"]
        except ClientError as err:
            last_err = err
            time.sleep(delay_s)
    raise AssertionError(f"RunInstances never succeeded (likely IAM instance-profile propagation delay): {last_err}")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a container instance")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to launch a container instance")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available to launch a container instance")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"], vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
