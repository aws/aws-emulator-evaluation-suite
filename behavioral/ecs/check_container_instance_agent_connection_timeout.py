"""container-instance-agent-connection-timeout."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "container-instance-agent-connection-timeout"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


def _error(fn):
    """Call fn() and return its error code and message; raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Stopping a container instance's EC2 host flips agentConnected to False only after a timeout
    window, not synchronously with StopInstances; UpdateContainerAgent with an invalid
    container instance id fails with InvalidParameterException and an exact message."""
    ecs = ctx.client("ecs")

    bogus_cluster = ctx.unique_name("no-such-cluster-")
    code, message = _error(
        lambda: ecs.update_container_agent(cluster=bogus_cluster, containerInstance="x")
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "ContainerInstanceId must match ^[a-f0-9-]{1,36}$"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    ec2 = ctx.client("ec2")
    setup = _registered_ec2_instance(ctx)
    cluster, ci_arn, instance_id = setup["cluster"], setup["container_instance_arn"], setup["instance_id"]

    before = ecs.describe_container_instances(cluster=cluster, containerInstances=[ci_arn])[
        "containerInstances"
    ][0]
    assert before["agentConnected"] is True, "prerequisite: agent must be connected before the host is stopped"

    interval_s = 2.0
    stop_started = time.monotonic()
    ec2.stop_instances(InstanceIds=[instance_id])

    samples = []  # [(elapsed_s, agentConnected)], each from an independent ECS read

    def _sample():
        ci = ecs.describe_container_instances(cluster=cluster, containerInstances=[ci_arn])[
            "containerInstances"
        ][0]
        elapsed = time.monotonic() - stop_started
        samples.append((elapsed, ci["agentConnected"]))
        return ci["agentConnected"]

    assert _sample() is True, (
        "agentConnected flipped to False synchronously with the StopInstances call -- expected a "
        f"real connection-timeout window, not an instant flip; samples={samples!r}"
    )

    # The flip normally lands within ~15s of the stop; 180s bounds a slow agent disconnect.
    poll_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + poll_s
    disconnected = False
    while time.monotonic() < deadline:
        time.sleep(interval_s)
        if _sample() is False:
            disconnected = True
            break

    if not disconnected:
        if _budget_spent(ctx):
            raise TimeoutError("agentConnected turning False: the run budget ended first; not graded")
        raise AssertionError(
            f"agentConnected never transitioned to False within the {poll_s:.0f}s poll budget after "
            f"stopping the host; samples={samples!r}"
        )

    ec2_state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0][
        "State"
    ]["Name"]
    assert ec2_state in ("stopping", "stopped"), (
        f"expected the underlying host to be stopping/stopped by the time the agent disconnected, "
        f"got {ec2_state!r}"
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

    role_name = ctx.unique_name("sim2real-ecsct-instrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    profile_name = ctx.unique_name("sim2real-ecsct-instprof-")
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

    cluster_name = ctx.unique_name("sim2real-ecsct-cluster-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n"

    instance_id = None
    last_err = None
    for _ in range(10):
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
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ecsct-ec2-")}],
                    }
                ],
            )
            instance_id = run_resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] in ("InvalidParameterValue", "Client.InvalidParameterValue"):
                time.sleep(2)
                continue
            raise
    if instance_id is None:
        raise AssertionError(f"could not launch the ECS-optimized instance: {last_err}")

    def _terminate():
        ec2.terminate_instances(InstanceIds=[instance_id])
        waiter = ec2.get_waiter("instance_terminated")
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    ctx.on_cleanup(_terminate)

    ci_arn = None
    deadline = time.monotonic() + _budget_s(ctx, 480.0)
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
        if _budget_spent(ctx):
            raise TimeoutError(
                "a container instance registering with a connected agent: the run budget ended "
                "first; not graded")
        raise AssertionError("EC2 container instance never registered with a connected agent within the poll budget")

    ctx.on_cleanup(
        lambda: ecs.deregister_container_instance(cluster=cluster_name, containerInstance=ci_arn, force=True)
    )

    return {"cluster": cluster_name, "container_instance_arn": ci_arn, "instance_id": instance_id}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
