"""capability-configuration-blob-round-trip."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capability-configuration-blob-round-trip"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Base64 of the bytes 0x00..0xff, split over two KRO capability tag values (each under the
    256-character tag-value limit), comes back byte-identical from DescribeCapability."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    role_arn = _create_capability_role(ctx)

    raw_bytes = bytes(range(256))  # 0x00..0xff, exercises the full byte range
    half = len(raw_bytes) // 2
    chunks_b64 = [
        base64.b64encode(raw_bytes[:half]).decode("ascii"),
        base64.b64encode(raw_bytes[half:]).decode("ascii"),
    ]
    capability_name = ctx.unique_name("sim2real-cap-")

    _retry_while_role_propagates(
        ctx,
        lambda: eks.create_capability(
            clusterName=cluster,
            capabilityName=capability_name,
            type="KRO",
            roleArn=role_arn,
            deletePropagationPolicy="RETAIN",
            tags={"blob0": chunks_b64[0], "blob1": chunks_b64[1]},
        ),
        "create_capability",
    )
    ctx.on_cleanup(lambda: _delete_capability_if_present(eks, cluster, capability_name))

    described = eks.describe_capability(clusterName=cluster, capabilityName=capability_name)[
        "capability"
    ]
    got_b64 = [described["tags"]["blob0"], described["tags"]["blob1"]]
    assert got_b64 == chunks_b64, (
        f"tag blob mutated in storage: expected {chunks_b64!r}, got {got_b64!r}"
    )
    decoded = base64.b64decode(got_b64[0]) + base64.b64decode(got_b64[1])
    assert decoded == raw_bytes, (
        f"base64 round trip corrupted the payload: expected {len(raw_bytes)} bytes "
        f"0x00..0xff, got {len(decoded)} bytes starting {decoded[:8]!r}"
    )

    eks.delete_capability(clusterName=cluster, capabilityName=capability_name)
    _wait_capability_deleted(eks, cluster, capability_name)


# ===== helpers =====


def _retry_while_role_propagates(ctx, call, what, total_s=80.0):
    """Retry call every 2 s while EKS rejects a brand-new IAM role (InvalidParameterException) that
    has not propagated yet, up to total_s, capped by the run's remaining time."""
    deadline = time.monotonic() + total_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what} never succeeded after IAM propagation retries: {exc}") from exc
        time.sleep(2)


def _delete_capability_if_present(eks, cluster, capability_name):
    try:
        eks.delete_capability(clusterName=cluster, capabilityName=capability_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_capability_deleted(eks, cluster, capability_name, timeout_s=600.0, interval_s=15.0):
    """Deletion is asynchronous on real AWS: describe_capability keeps returning the
    capability (typically status DELETING) for a while after delete_capability returns."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_capability(clusterName=cluster, capabilityName=capability_name)
        except ClientError as exc:
            err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            assert err == ("ResourceNotFoundException", "The requested resource does not exist."), (
                f"expected ResourceNotFoundException while polling for capability "
                f"deletion, got {err}"
            )
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"capability {capability_name!r} still present {timeout_s}s after delete_capability"
    )


def _pick_subnets(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            "account/region lacks a shared network VPC with subnets in >=2 AZs; cannot "
            "provision a real EKS cluster for this check"
        )
    return list(by_az.values())[:3]


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    subnet_ids = _pick_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    cluster_name = ctx.unique_name("sim2real-ekscl-")

    _retry_while_role_propagates(
        ctx,
        lambda: eks.create_cluster(
            name=cluster_name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids},
            accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
        ),
        "create_cluster",
    )

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, cluster_name))
    eks.get_waiter("cluster_active").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )
    return cluster_name


def _create_capability_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-caprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "capabilities.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
