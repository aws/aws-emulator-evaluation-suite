"""update-container-instances-state-unknown."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-container-instances-state-unknown"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateContainerInstancesState must not claim to drain a container instance that
    was never registered in the cluster, and must not disturb a real instance's state
    while doing so."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx, ecs)

    # Positive control: the identical call, on the same cluster, against a real
    # registered instance, must succeed. Without this, "rejects the unknown id" is
    # indistinguishable from "rejects every UpdateContainerInstancesState call".
    # RegisterContainerInstance verifies a signed EC2 identity document, so the only
    # real way to get a genuine instance is to launch one and let the ECS agent
    # register it -- there is no cheap synthetic substitute on real AWS.
    real_arn = _launch_real_container_instance(ctx, ecs, cluster["clusterArn"], cluster["clusterName"])
    control = ecs.update_container_instances_state(
        cluster=cluster["clusterArn"], containerInstances=[real_arn], status="DRAINING"
    )
    assert not control.get("failures"), f"positive control unexpectedly failed: {control.get('failures')}"
    assert control["containerInstances"][0]["status"] == "DRAINING", (
        f"expected the positive control to reach DRAINING, got {control['containerInstances']}"
    )

    account = ctx.client("sts").get_caller_identity()["Account"]
    unknown_id = "00000000-0000-0000-0000-000000000000"
    unknown_arn = (
        f"arn:aws:ecs:{ctx.region}:{account}:container-instance/"
        f"{cluster['clusterName']}/{unknown_id}"
    )

    # Real AWS answers an unregistered id in the batch's failures[] rather than raising, and
    # echoes the arn normalized (the cluster-name path segment dropped).
    resp = ecs.update_container_instances_state(
        cluster=cluster["clusterArn"],
        containerInstances=[unknown_arn],
        status="DRAINING",
    )
    assert resp["containerInstances"] == [], (
        f"expected no containerInstances reported drained for an unregistered id, "
        f"got {resp['containerInstances']}"
    )
    expected_failures = [
        {"arn": f"arn:aws:ecs:{ctx.region}:{account}:container-instance/{unknown_id}", "reason": "MISSING"}
    ]
    assert resp["failures"] == expected_failures, (
        f"expected failures {expected_failures!r} for the unregistered instance, got {resp['failures']!r}"
    )

    # Independent read at the destination, through DescribeContainerInstances (not the
    # mutating call's own response): the unknown id is not describable, and the real
    # instance's state was not disturbed by the call targeting the unknown id.
    described_unknown = ecs.describe_container_instances(
        cluster=cluster["clusterArn"], containerInstances=[unknown_arn]
    )
    assert not described_unknown["containerInstances"], described_unknown["containerInstances"]
    assert described_unknown["failures"] and described_unknown["failures"][0].get("reason") == "MISSING", (
        f"expected DescribeContainerInstances to also report MISSING, got {described_unknown}"
    )

    described_real = ecs.describe_container_instances(
        cluster=cluster["clusterArn"], containerInstances=[real_arn]
    )["containerInstances"][0]
    assert described_real["status"] == "DRAINING", (
        f"the unknown-id call must not have disturbed the real instance's state, "
        f"got {described_real['status']}"
    )


# ===== helpers =====

# Codes that mean "the control plane is busy", never "your request was wrong".
_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "RequestLimitExceeded",
    "TooManyRequestsException",
)


def _retry_throttled(fn, attempts: int = 7, base_delay: float = 2.0):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(min(base_delay * (2**i), 20.0))
    raise last


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "InvalidInstanceID.NotFound",
            "NoSuchEntity",
        ):
            raise


def _create_cluster(ctx, ecs, name=None, **kwargs) -> dict:
    name = name or ctx.unique_name("sim2real-behav-ecs-cluster-")
    resp = _retry_throttled(lambda: ecs.create_cluster(clusterName=name, **kwargs))
    arn = resp["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.delete_cluster(cluster=arn)))
    return resp["cluster"]


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


def _launch_real_container_instance(ctx, ecs, cluster_arn: str, cluster_name: str, *, timeout_s=200) -> str:
    """Launch a real EC2 host so the ECS agent registers a genuine container instance --
    RegisterContainerInstance verifies a signed identity document, so there is no
    cheaper synthetic substitute on real AWS."""
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
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    )
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
        )
    )
    profile_arn = iam.get_instance_profile(InstanceProfileName=role_name)["InstanceProfile"]["Arn"]

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n"
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
        except Exception as exc:  # noqa: BLE001 - IAM propagation lag surfaces as a ClientError
            last_exc = exc
            time.sleep(2)
    if instance_id is None:
        raise last_exc or RuntimeError("failed to launch container-instance EC2 host")
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

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
        _find,
        lambda x: x is not None,
        timeout_s=timeout_s,
        interval_s=10,
        description="EC2 instance registers as an ECS container instance",
    )
    ci_arn = ci["containerInstanceArn"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=ci_arn, force=True)
        )
    )
    return ci_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
