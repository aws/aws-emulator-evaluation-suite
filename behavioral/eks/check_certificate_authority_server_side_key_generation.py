"""certificate-authority-server-side-key-generation."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-authority-server-side-key-generation"
GROUP = "server-side"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCertificateAuthority takes no key material, yet once the CUSTOMER-created successor distributes
    (COMPLETE), DescribeCertificateAuthority returns PEM or DER certificate data over 200 bytes.
    """
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    created = eks.create_certificate_authority(clusterName=cluster["name"])["certificateAuthority"]
    ca_id = created["id"]
    assert created["createdBy"] == "CUSTOMER", f"expected CUSTOMER-triggered CA, got {created['createdBy']!r}"

    distributed = _poll_until(
        lambda: eks.describe_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=ca_id)[
            "certificateAuthority"
        ],
        lambda ca: ca["distributionStatus"] in ("COMPLETE", "FAILED"),
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert distributed["distributionStatus"] == "COMPLETE", distributed

    cert_b64 = distributed.get("data")
    assert cert_b64, "expected server-generated public certificate data, got none"
    der_or_pem = base64.b64decode(cert_b64)
    assert len(der_or_pem) > 200, f"certificate material implausibly short: {len(der_or_pem)} bytes"
    is_pem = der_or_pem.lstrip().startswith(b"-----BEGIN CERTIFICATE-----")
    is_der = der_or_pem[0:1] == b"\x30"  # ASN.1 SEQUENCE tag, the start of a DER certificate
    assert is_pem or is_der, "decoded certificate data does not look like PEM or DER"

    # Cleanup: this successor CA never gets activated, so it stays NOT_USED and is
    # freely deletable.
    ctx.on_cleanup(lambda: _delete_certificate_authority_when_idle(eks, cluster["name"], ca_id))


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last}")


def _get_or_create_subnets(ctx, min_azs=2):
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [default_vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        ids = list(by_az.values())
        if len(ids) >= min_azs:
            return ids[:min_azs]

    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
            "AvailabilityZones"
        ]
    ][:min_azs]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.91.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(
            Resources=[subnet_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-subnet-")}]
        )
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_active_cluster(ctx, extra_kwargs=None):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnet_ids = _get_or_create_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        tags={"sim2real": "1"},
    )
    if extra_kwargs:
        kwargs.update(extra_kwargs)

    # A fresh role is refused with InvalidParameterException until IAM propagates it.
    left = ctx.time_left()
    deadline = time.monotonic() + (80.0 if left is None else min(80.0, left))
    while True:
        try:
            eks.create_cluster(**kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster did not reach ACTIVE: {cluster['status']}")
    return {"name": name, "arn": cluster["arn"], "role_arn": role_arn, "subnet_ids": subnet_ids}


def _delete_certificate_authority_when_idle(eks, cluster_name, ca_id, timeout_s=900.0, interval_s=20.0):
    """DeleteCertificateAuthority, retried while an earlier CA update on the cluster still runs."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the network.

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
