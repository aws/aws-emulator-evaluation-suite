"""concurrent-certificate-authority-activate-idempotent."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-certificate-authority-activate-idempotent"
GROUP = "concurrency"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent ActivateCertificateAuthority calls on one successor CA leave that CA IN_USE and
    COMPLETE and exactly one other CA NOT_USED, with identical non-empty certificate data on two reads.
    """
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    successor_id = eks.create_certificate_authority(clusterName=cluster)["certificateAuthority"]["id"]
    _poll_until(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster, certificateAuthorityId=successor_id
        )["certificateAuthority"],
        lambda ca: ca["distributionStatus"] == "COMPLETE",
        timeout_s=1800,
        interval_s=15,
    )

    def _activate():
        try:
            eks.activate_certificate_authority(
                clusterName=cluster, certificateAuthorityId=successor_id
            )
            return "ok"
        except ClientError as exc:
            return exc.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut1 = pool.submit(_activate)
        fut2 = pool.submit(_activate)
        outcome1 = fut1.result()
        outcome2 = fut2.result()

    # At least one racer must have been accepted -- the activation is not lost.
    assert "ok" in (outcome1, outcome2), f"neither concurrent activation succeeded: {outcome1}, {outcome2}"

    final = _poll_until(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster, certificateAuthorityId=successor_id
        )["certificateAuthority"],
        lambda ca: ca["signingStatus"] == "IN_USE",
        timeout_s=900,
        interval_s=10,
    )
    assert final["signingStatus"] == "IN_USE"
    assert final["distributionStatus"] == "COMPLETE"

    all_cas = eks.list_certificate_authorities(clusterName=cluster)["certificateAuthorities"]
    in_use = [ca for ca in all_cas if ca["signingStatus"] == "IN_USE"]
    not_used = [ca for ca in all_cas if ca["signingStatus"] == "NOT_USED"]
    assert len(in_use) == 1 and in_use[0]["id"] == successor_id, (
        f"expected exactly one IN_USE CA (the successor), got {in_use}"
    )
    assert len(not_used) == 1, f"expected exactly one retired CA, got {not_used}"

    # Certificate material is stable (byte-identical) across two independent reads.
    read_a = eks.describe_certificate_authority(
        clusterName=cluster, certificateAuthorityId=successor_id
    )["certificateAuthority"]
    read_b = eks.describe_certificate_authority(
        clusterName=cluster, certificateAuthorityId=successor_id
    )["certificateAuthority"]
    assert read_a.get("data") == read_b.get("data")
    assert read_a.get("data")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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

    # A fresh role is refused with InvalidParameterException until IAM propagates it.
    left = ctx.time_left()
    deadline = time.monotonic() + (80.0 if left is None else min(80.0, left))
    while True:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real-check": CHECK},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, cluster_name))
    eks.get_waiter("cluster_active").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )
    return cluster_name


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
