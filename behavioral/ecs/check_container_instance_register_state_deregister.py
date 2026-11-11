"""container-instance-register-state-deregister."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "container-instance-register-state-deregister"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An EC2 instance running the ECS agent registers ACTIVE and listed,
    UpdateContainerInstancesState makes it DRAINING as described, and after
    DeregisterContainerInstance it is unlisted but still described as INACTIVE."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    cluster_name = ctx.unique_name("sim2real-ecs-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    ci = _launch_real_container_instance(ctx, ecs, ec2, iam, ssm, cluster_name)
    ci_arn = ci["containerInstanceArn"]
    assert ci["status"] == "ACTIVE", f"expected a freshly joined container instance to be ACTIVE, got {ci['status']!r}"

    described = ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[ci_arn])["containerInstances"]
    assert len(described) == 1 and described[0]["containerInstanceArn"] == ci_arn, (
        f"expected exactly [{ci_arn}], got {described}"
    )
    assert described[0]["status"] == "ACTIVE", f"expected ACTIVE, got {described[0]['status']!r}"

    listed = ecs.list_container_instances(cluster=cluster_arn)["containerInstanceArns"]
    assert ci_arn in listed, f"expected {ci_arn} in {listed}"

    state_change = ecs.update_container_instances_state(
        cluster=cluster_arn, containerInstances=[ci_arn], status="DRAINING"
    )
    assert state_change["failures"] == [], f"expected no failures, got {state_change['failures']}"
    assert state_change["containerInstances"][0]["status"] == "DRAINING", (
        f"expected DRAINING in the mutating call's own response, got "
        f"{state_change['containerInstances'][0]['status']!r}"
    )

    # UpdateContainerInstancesState's own response reports DRAINING immediately, but an
    # independent DescribeContainerInstances lags behind it, so poll (bounded) rather than assert
    # on the very next read.
    described_after_drain = _poll_until(
        lambda: ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[ci_arn])[
            "containerInstances"
        ][0],
        lambda ci: ci["status"] == "DRAINING",
        timeout_s=30.0,
        interval_s=2.0,
        description="an independent describe converges to DRAINING",
    )
    assert described_after_drain["status"] == "DRAINING", (
        f"expected an independent describe to show DRAINING, got {described_after_drain['status']!r}"
    )

    ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=ci_arn, force=True)

    listed_after = _poll_until(
        lambda: set(ecs.list_container_instances(cluster=cluster_arn)["containerInstanceArns"]),
        lambda s: ci_arn not in s,
        timeout_s=60.0,
        interval_s=3.0,
        description="deregistered instance disappears from ListContainerInstances",
    )
    assert ci_arn not in listed_after, "deregistered instance must be absent from ListContainerInstances"

    described_after = ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[ci_arn])
    assert described_after["containerInstances"], "expected the deregistered instance to still be describable"
    assert described_after["containerInstances"][0]["status"] == "INACTIVE", (
        f"expected INACTIVE after deregister, got {described_after['containerInstances'][0]['status']!r}"
    )
    assert described_after["failures"] == [], f"expected no failures, got {described_after['failures']}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _default_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _default_subnet(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no default-for-az subnets")
    return subnets[0]["SubnetId"]


def _default_sg(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available in the shared network")
    return sgs[0]["GroupId"]


def _launch_real_container_instance(ctx, ecs, ec2, iam, ssm, cluster_name, timeout_s=240):
    """Launch a real EC2 instance running the genuine ECS agent, pointed at `cluster_name` via
    user data, and wait for the agent to register it. Returns the described containerInstance
    dict once it appears. Registers cleanup for every resource it creates."""
    subnet_id = _default_subnet(ec2, ctx=ctx)
    sg_id = _default_sg(ec2, ctx=ctx)
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]

    role_name = ctx.unique_name("sim2real-ecsInstanceRole-")[:64]
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    try:
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    except ClientError as exc:
        raise AssertionError(f"cannot create the ECS-instance IAM role: {exc}")
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
        )
    )
    profile_arn = iam.get_instance_profile(InstanceProfileName=role_name)["InstanceProfile"]["Arn"]

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n"
    encoded_user_data = base64.b64encode(user_data.encode()).decode()

    instance_name = ctx.unique_name("sim2real-ecs-ci-")
    instance_id = None
    last_exc = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Arn": profile_arn},
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                UserData=encoded_user_data,
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": instance_name}]}
                ],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:  # a freshly-created instance profile lags IAM propagation
            last_exc = exc
            time.sleep(2)
    if instance_id is None:
        raise AssertionError(f"RunInstances never succeeded after IAM propagation retries: {last_exc}")
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _find():
        arns = ecs.list_container_instances(cluster=cluster_name).get("containerInstanceArns", [])
        if not arns:
            return None
        described = ecs.describe_container_instances(cluster=cluster_name, containerInstances=arns)[
            "containerInstances"
        ]
        for candidate in described:
            if candidate.get("ec2InstanceId") == instance_id:
                return candidate
        return None

    ci = _poll_until(
        _find,
        lambda x: x is not None,
        timeout_s=timeout_s,
        interval_s=10.0,
        description="the EC2 instance registers as an ECS container instance",
    )
    ci_arn = ci["containerInstanceArn"]
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.deregister_container_instance(cluster=cluster_name, containerInstance=ci_arn, force=True)
        )
    )
    return ci


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "InvalidInstanceID.NotFound",
            "NoSuchEntity",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
