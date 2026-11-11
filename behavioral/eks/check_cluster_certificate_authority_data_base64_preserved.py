"""cluster-certificate-authority-data-base64-preserved."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-certificate-authority-data-base64-preserved"
GROUP = "data-plane"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The cluster's base64-encoded CA certificate data returned by DescribeCluster is
    stable byte-for-byte across repeated calls (it is not regenerated or re-encoded
    per request) and decodes to a well-formed PEM certificate."""
    eks = ctx.client("eks")
    cluster_name, _version = _create_active_cluster(ctx)

    readings = []
    for _ in range(3):
        cluster = eks.describe_cluster(name=cluster_name)["cluster"]
        ca_data = cluster["certificateAuthority"]["data"]
        readings.append(ca_data)
        time.sleep(1.0)

    assert all(r == readings[0] for r in readings), "CA data must be identical across repeated DescribeCluster calls"
    assert readings[0], "CA data must not be empty on an ACTIVE cluster"

    decoded = base64.b64decode(readings[0], validate=True)
    assert decoded.startswith(b"-----BEGIN CERTIFICATE-----"), "decoded CA data must be a PEM certificate"
    assert decoded.rstrip().endswith(b"-----END CERTIFICATE-----"), "decoded CA data must be a well-formed PEM block"

    # round-trip: re-encoding the decoded bytes must reproduce the exact same base64 string
    reencoded = base64.b64encode(decoded).decode("ascii")
    assert reencoded == readings[0], "base64 encoding of the decoded CA bytes must match the original string exactly"


# ===== helpers =====


def _iam_trust_policy(service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-clusterrole-")
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_iam_trust_policy("eks.amazonaws.com")
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _default_vpc_subnets(ctx) -> list[str]:
    """Prefer the run's shared network; only create a dedicated one as a fallback -- a freshly
    provisioned account may not have the shared network at all."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())
        if len(subnet_ids) >= 2:
            return subnet_ids[:3]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.44.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.44.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-subnet-{i}-")}]}
            ],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: ec2.delete_subnet(SubnetId=sid))
    if len(subnet_ids) < 2:
        raise AssertionError("could not create a dedicated VPC with subnets in >=2 AZs to host an EKS control plane")
    return subnet_ids


def _create_cluster_with_retry(ctx, name: str, role_arn: str, subnet_ids: list[str], version: str | None = None):
    eks = ctx.client("eks")
    kwargs: dict[str, Any] = dict(
        name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}, tags={"sim2real": "1"}
    )
    if version:
        kwargs["version"] = version
    # A brand-new IAM role is rejected until it propagates: retry those codes every 2 s.
    deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            return eks.create_cluster(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidParameterException", "ClientException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"create_cluster kept failing (likely IAM propagation lag): {exc}") from exc
        time.sleep(2)


def _wait_cluster_active(ctx, name: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> str:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        status = cluster["status"]
        if status == "ACTIVE":
            return cluster["version"]
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not become ACTIVE within {timeout_s}s")


def _create_active_cluster(ctx) -> tuple[str, str]:
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _default_vpc_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")
    _create_cluster_with_retry(ctx, name, role_arn, subnet_ids)

    def _delete() -> None:
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            time.sleep(15)

    ctx.on_cleanup(_delete)
    version = _wait_cluster_active(ctx, name)
    return name, version


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
