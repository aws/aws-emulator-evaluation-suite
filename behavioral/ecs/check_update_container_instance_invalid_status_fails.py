"""update-container-instance-invalid-status-fails."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-container-instance-invalid-status-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateContainerInstancesState accepts DRAINING but rejects REGISTERING, a status the field
    reports but never accepts as a target, and the instance's status stays DRAINING."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name,
        tags=[{"key": "sim2real", "value": "true"}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    ci_arn = _launch_real_container_instance(ctx, ecs, cluster_name)

    # Positive control: a real, valid transition on this instance is accepted.
    control = ecs.update_container_instances_state(
        cluster=cluster_arn, containerInstances=[ci_arn], status="DRAINING"
    )
    assert control["failures"] == [], f"positive control DRAINING transition failed: {control['failures']}"
    assert control["containerInstances"][0]["status"] == "DRAINING", (
        f"positive control did not report DRAINING: {control['containerInstances']}"
    )

    # Break exactly one thing: REGISTERING is a status the field can report on a
    # freshly-joining instance, but it is never a settable target status.
    try:
        ecs.update_container_instances_state(
            cluster=cluster_arn, containerInstances=[ci_arn], status="REGISTERING"
        )
        raise AssertionError("UpdateContainerInstancesState accepted status=REGISTERING")
    except ClientError as exc:
        error = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    expected = ("InvalidParameterException", "Container instances status should be one of [ACTIVE,DRAINING]")
    assert error == expected, f"expected {expected!r} for status=REGISTERING, got {error!r}"

    # Effect absent, via an independent read at a different operation than either
    # mutating call above: the instance is still DRAINING, never REGISTERING.
    described = ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[ci_arn])[
        "containerInstances"
    ][0]
    assert described["status"] == "DRAINING", f"expected status unchanged at DRAINING, got {described['status']!r}"


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

    instance_name = ctx.unique_name("sim2real-ecsinst-")
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
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": instance_name}]}
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
    ci_arn = ci["containerInstanceArn"]
    ctx.on_cleanup(lambda: ecs.deregister_container_instance(cluster=cluster, containerInstance=ci_arn, force=True))
    return ci_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
