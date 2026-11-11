"""update-container-agent-transitions-agent-update-status."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "update-container-agent-transitions-agent-update-status"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateContainerAgent on a registered ECS-optimized container instance either starts an
    agentUpdateStatus transition that converges to UPDATED, or is refused (NoUpdateAvailableException
    or MissingVersionException) with the instance state unchanged."""
    ecs = ctx.client("ecs")
    setup = _registered_ec2_instance(ctx)
    cluster, ci_arn = setup["cluster"], setup["container_instance_arn"]

    before = ecs.describe_container_instances(cluster=cluster, containerInstances=[ci_arn])["containerInstances"][0]
    assert before["agentConnected"] is True, f"expected the registered instance's agent to be connected, got {before['agentConnected']!r}"
    assert before.get("agentUpdateStatus") in (None, "UPDATED"), (
        f"expected no update already in flight before the call, got {before.get('agentUpdateStatus')!r}"
    )

    code = None
    resp = None
    try:
        resp = ecs.update_container_agent(cluster=cluster, containerInstance=ci_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]

    if code == "NoUpdateAvailableException":
        # Refusal: the agent is already current, and no update pipeline started.
        after = ecs.describe_container_instances(cluster=cluster, containerInstances=[ci_arn])["containerInstances"][
            0
        ]
        assert after.get("agentUpdateStatus") in (None, "UPDATED"), (
            f"expected no update transition on a refused call, got {after.get('agentUpdateStatus')!r}"
        )
        return

    if code == "MissingVersionException":
        # The instance never reported agent version info -- a genuinely
        # distinct, real refusal branch.
        after = ecs.describe_container_instances(cluster=cluster, containerInstances=[ci_arn])["containerInstances"][
            0
        ]
        assert not after.get("versionInfo", {}).get("agentVersion"), (
            f"expected no reported agent version after MissingVersionException, got {after.get('versionInfo')!r}"
        )
        return

    if code is not None:
        raise AssertionError(f"unexpected error from UpdateContainerAgent: {code}")

    # Positive branch: an update was actually available and accepted.
    initial_status = resp["containerInstance"]["agentUpdateStatus"]
    assert initial_status in ("PENDING", "STAGING", "STAGED", "UPDATING"), initial_status

    terminal = {"UPDATED", "FAILED"}
    observed = {initial_status}
    deadline = time.monotonic() + _budget_s(ctx, 180)
    while time.monotonic() < deadline:
        current = ecs.describe_container_instances(cluster=cluster, containerInstances=[ci_arn])[
            "containerInstances"
        ][0]
        status = current.get("agentUpdateStatus")
        observed.add(status)
        if status in terminal:
            break
        time.sleep(2)
    else:
        if _budget_spent(ctx):
            raise TimeoutError(
                "the agent update reaching a terminal state: the run budget ended first; not graded")
        raise AssertionError(
            "agent update never reached a terminal state within the poll budget"
        )

    # An update the API accepted is expected to converge rather than land in FAILED.
    assert status == "UPDATED", f"accepted agent update did not converge to UPDATED, got {status!r} (observed={sorted(observed)})"



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
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n"

    instance_id = None
    last_err = None
    launch_deadline = time.monotonic() + _budget_s(ctx, 100)
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
                if time.monotonic() >= launch_deadline:
                    break
                time.sleep(2)
                continue
            raise
    if instance_id is None:
        if _budget_spent(ctx):
            raise TimeoutError(
                f"the ECS-optimized instance launching: the run budget ended first; not graded "
                f"({last_err})")
        raise AssertionError(f"could not launch the ECS-optimized instance: {last_err}")

    def _terminate():
        ec2.terminate_instances(InstanceIds=[instance_id])
        waiter = ec2.get_waiter("instance_terminated")
        try:
            waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        except WaiterError as last:
            raise RuntimeError(f"instance {instance_id} was not deleted: {last!r}") from last

    ctx.on_cleanup(_terminate)

    ci_arn = None
    deadline = time.monotonic() + _budget_s(ctx, 480)
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

    return {"cluster": cluster_name, "container_instance_arn": ci_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
