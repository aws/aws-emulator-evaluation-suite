"""discover-poll-endpoint-for-registered-instance."""
from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "discover-poll-endpoint-for-registered-instance"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DiscoverPollEndpoint returns stable http(s) poll and telemetry endpoints for a container
    instance an ECS-optimized EC2 instance's agent just registered: the mechanism the agent uses
    to find where to long-poll for work."""
    ecs = ctx.client("ecs")
    setup = _registered_ec2_instance(ctx)
    cluster_name, ci_arn = setup["cluster"], setup["container_instance_arn"]

    resp = ecs.discover_poll_endpoint(cluster=cluster_name, containerInstance=ci_arn)

    endpoint = resp.get("endpoint")
    telemetry_endpoint = resp.get("telemetryEndpoint")
    parsed = urllib.parse.urlsplit(endpoint or "")
    assert parsed.scheme in ("https", "http") and parsed.hostname, (
        f"expected an http(s) poll endpoint with a host, got {endpoint!r}"
    )
    parsed = urllib.parse.urlsplit(telemetry_endpoint or "")
    assert parsed.scheme in ("https", "http") and parsed.hostname, (
        f"expected an http(s) telemetry endpoint with a host, got {telemetry_endpoint!r}"
    )

    # A second call for the same container instance is idempotent and returns
    # the same managed endpoint and telemetry endpoint -- server-side assignment,
    # not a one-shot token.
    resp2 = ecs.discover_poll_endpoint(cluster=cluster_name, containerInstance=ci_arn)
    assert resp2["endpoint"] == resp["endpoint"], (
        f"endpoint changed across repeated DiscoverPollEndpoint calls: {resp['endpoint']!r} -> {resp2['endpoint']!r}"
    )
    assert resp2["telemetryEndpoint"] == resp["telemetryEndpoint"], (
        f"telemetryEndpoint changed across repeated DiscoverPollEndpoint calls: "
        f"{resp['telemetryEndpoint']!r} -> {resp2['telemetryEndpoint']!r}"
    )


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
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n"

    instance_id = None
    last_err = None
    # A just-created instance profile is not yet usable by RunInstances (InvalidParameterValue).
    left = ctx.time_left()
    deadline = time.monotonic() + (100.0 if left is None else min(100.0, max(1.0, left - 5.0)))
    while time.monotonic() < deadline:
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
    left = ctx.time_left()
    deadline = time.monotonic() + (480.0 if left is None else min(480.0, max(1.0, left - 5.0)))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
