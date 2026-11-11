"""server-side-pod-identity-role-scoping-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-pod-identity-role-scoping-enforced"
GROUP = "server-side"
SERVICES = ["eks"]

_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two pod identity associations on one cluster, for different namespace/serviceAccount pairs and roles,
    each describe with their own role, namespace and serviceAccount only, and ListPodIdentityAssociations
    filtered by namespace (and serviceAccount) returns exactly the matching one."""
    eks = ctx.client("eks")
    cluster = _create_active_eks_cluster(ctx)

    role_a = _create_pod_identity_role(ctx, "a")
    role_b = _create_pod_identity_role(ctx, "b")

    namespace_a = ctx.unique_name("sim2real-ns-a-")
    namespace_b = ctx.unique_name("sim2real-ns-b-")
    sa_a = ctx.unique_name("sim2real-sa-a-")
    sa_b = ctx.unique_name("sim2real-sa-b-")

    assoc_a = _create_pod_identity_association_with_retry(
        eks, clusterName=cluster, namespace=namespace_a, serviceAccount=sa_a, roleArn=role_a,
    )["association"]
    assoc_b = _create_pod_identity_association_with_retry(
        eks, clusterName=cluster, namespace=namespace_b, serviceAccount=sa_b, roleArn=role_b,
    )["association"]
    assert assoc_a["associationId"] != assoc_b["associationId"]

    # each association's own record must resolve to its own role only
    described_a = eks.describe_pod_identity_association(
        clusterName=cluster, associationId=assoc_a["associationId"]
    )["association"]
    described_b = eks.describe_pod_identity_association(
        clusterName=cluster, associationId=assoc_b["associationId"]
    )["association"]

    assert described_a["roleArn"] == role_a, described_a
    assert described_a["roleArn"] != role_b
    assert described_a["namespace"] == namespace_a
    assert described_a["serviceAccount"] == sa_a

    assert described_b["roleArn"] == role_b, described_b
    assert described_b["roleArn"] != role_a
    assert described_b["namespace"] == namespace_b
    assert described_b["serviceAccount"] == sa_b

    # server-side filtering by namespace must return exactly the matching association,
    # never the sibling association's record
    listed_a = eks.list_pod_identity_associations(clusterName=cluster, namespace=namespace_a)["associations"]
    listed_a_ids = {a["associationId"] for a in listed_a}
    assert listed_a_ids == {assoc_a["associationId"]}, (
        f"filtering by namespace {namespace_a} returned {listed_a_ids}, expected only "
        f"{assoc_a['associationId']}"
    )

    listed_b = eks.list_pod_identity_associations(clusterName=cluster, namespace=namespace_b)["associations"]
    listed_b_ids = {a["associationId"] for a in listed_b}
    assert listed_b_ids == {assoc_b["associationId"]}, (
        f"filtering by namespace {namespace_b} returned {listed_b_ids}, expected only "
        f"{assoc_b['associationId']}"
    )

    # filtering by service account is likewise exact, not a superset/union of both
    listed_by_sa_a = eks.list_pod_identity_associations(
        clusterName=cluster, namespace=namespace_a, serviceAccount=sa_a
    )["associations"]
    assert {a["associationId"] for a in listed_by_sa_a} == {assoc_a["associationId"]}


def _create_pod_identity_role(ctx, suffix):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-podid-{suffix}-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "pods.eks.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_pod_identity_association_with_retry(eks, timeout_s=60.0, **kwargs):
    """CreatePodIdentityAssociation can reject a just-created role's trust policy
    until IAM propagation catches up; retry on that specific, transient condition
    rather than a bare sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return eks.create_pod_identity_association(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"create_pod_identity_association never succeeded within {timeout_s}s: {last_exc}")


def _ec2_tags(name):
    return [{"Key": "Name", "Value": name}, {"Key": "sim2real-managed", "Value": "true"}]


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_eks_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.86.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags(ctx.unique_name("sim2real-eks-vpc-"))}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.86.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags(ctx.unique_name(f"sim2real-eks-sn{i}-"))}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: ec2.delete_subnet(SubnetId=sid))
    return subnet_ids


def _wait_cluster_status(eks, name, target, timeout_s=1200, interval_s=20):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == target:
            return
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {target}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s")


def _wait_cluster_gone(eks, name, timeout_s=1200, interval_s=20):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not removed within {timeout_s}s")


def _create_cluster_with_retry(eks, timeout_s=60.0, **kwargs):
    """CreateCluster can reject a just-created IAM role until propagation catches
    up; retry on that specific, transient condition rather than a bare sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return eks.create_cluster(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"create_cluster never succeeded within {timeout_s}s: {last_exc}")


def _create_active_eks_cluster(ctx):
    eks = ctx.client("eks")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _create_eks_vpc_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-clu-")
    _create_cluster_with_retry(eks, name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})

    def _cleanup():
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _wait_cluster_gone(eks, name)

    ctx.on_cleanup(_cleanup)
    _wait_cluster_status(eks, name, "ACTIVE")
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
