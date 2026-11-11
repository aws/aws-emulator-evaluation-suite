"""certificate-authority-validity-period-precision-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-authority-validity-period-precision-preserved"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The successor CA's service-computed validity.notBefore, validity.notAfter and createdAt
    are identical across two DescribeCertificateAuthority reads (not rounded or jittered), and
    notAfter exceeds notBefore by a plausible validity window."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    ca_id = eks.create_certificate_authority(clusterName=cluster)["certificateAuthority"]["id"]

    # A new CA carries no validity window until EKS has generated it, so the first read is the
    # one that first reports it.
    read_a = _wait_ca_validity(eks, cluster, ca_id)
    read_b = eks.describe_certificate_authority(clusterName=cluster, certificateAuthorityId=ca_id)[
        "certificateAuthority"
    ]

    assert read_a["createdAt"] == read_b["createdAt"], "createdAt drifted between reads"
    assert read_a["validity"]["notBefore"] == read_b["validity"]["notBefore"]
    assert read_a["validity"]["notAfter"] == read_b["validity"]["notAfter"]

    not_before = read_a["validity"]["notBefore"]
    not_after = read_a["validity"]["notAfter"]
    assert not_after > not_before, "validity.notAfter must be strictly after notBefore"

    # A CA's validity window is measured in years, not seconds/minutes -- a
    # faithful emulator must not truncate/round this to a trivial window.
    delta = not_after - not_before
    seconds_valid = delta.total_seconds()
    one_year_seconds = 365 * 24 * 3600
    assert seconds_valid >= one_year_seconds, (
        f"expected a multi-year CA validity window, got {seconds_valid} seconds"
    )


# ===== helpers =====


_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _pick_subnets(ctx):
    """Two subnets in two distinct, EKS-supported AZs of the run's shared network."""
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az = {}
    for s in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if s["AvailabilityZoneId"] not in _BAD_AZS:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            f"need shared-network subnets in >=2 EKS-supported AZs, found {sorted(by_az)}"
        )
    return [by_az[az] for az in sorted(by_az)][:2]


def _wait_ca_validity(eks, cluster, ca_id, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    ca = None
    while time.monotonic() < deadline:
        ca = eks.describe_certificate_authority(
            clusterName=cluster, certificateAuthorityId=ca_id
        )["certificateAuthority"]
        if ca.get("distributionStatus") == "FAILED":
            raise AssertionError(f"CA {ca_id} distribution FAILED: {ca}")
        if "validity" in ca:
            return ca
        time.sleep(interval_s)
    raise AssertionError(f"CA {ca_id} reported no validity window within {timeout_s}s: {ca}")


def _iam_delete(op, **kwargs):
    """An IAM delete that tolerates only the entity already being gone."""
    try:
        op(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


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

    ctx.on_cleanup(lambda: _iam_delete(iam.delete_role, RoleName=role_name))
    ctx.on_cleanup(lambda: _iam_delete(
        iam.detach_role_policy,
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    ))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    subnet_ids = _pick_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    cluster_name = ctx.unique_name("sim2real-ekscl-")

    # A brand-new IAM role is rejected with InvalidParameterException until it propagates.
    deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"create_cluster never succeeded after IAM propagation retries: {exc}") from exc
        time.sleep(2)

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, cluster_name))
    eks.get_waiter("cluster_active").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )
    return cluster_name


def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the network.

    DeleteCluster is refused while an update (here the CA's own) still runs; that
    ResourceInUseException is retried until the deadline.
    """
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
