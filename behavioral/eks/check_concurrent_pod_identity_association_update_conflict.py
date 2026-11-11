"""concurrent-pod-identity-association-update-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-pod-identity-association-update-conflict"
GROUP = "concurrency"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdatePodIdentityAssociation calls on the same association converge to
    exactly one of the two racing roleArn values (deterministic last-write-wins), never a
    corrupted/partial mix of the two updates."""
    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _default_subnets(ctx)
    _create_cluster_with_retry(ctx, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_name))
    cluster = _wait_cluster_status(ctx, cluster_name, {"ACTIVE", "FAILED"})
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster['status']}")

    pod_role_initial_arn = _create_pod_identity_role(ctx, "a")
    pod_role_b_arn = _create_pod_identity_role(ctx, "b")
    pod_role_c_arn = _create_pod_identity_role(ctx, "c")

    assoc = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace="default",
        serviceAccount=ctx.unique_name("sim2real-sa-"),
        roleArn=pod_role_initial_arn,
        tags={"sim2real": "1"},
    )["association"]
    association_id = assoc["associationId"]
    ctx.on_cleanup(
        lambda: eks.delete_pod_identity_association(
            clusterName=cluster_name, associationId=association_id
        )
    )

    barrier = threading.Barrier(2)

    def _update(new_role_arn):
        barrier.wait(timeout=10)
        return eks.update_pod_identity_association(
            clusterName=cluster_name,
            associationId=association_id,
            roleArn=new_role_arn,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_update, pod_role_b_arn),
            pool.submit(_update, pod_role_c_arn),
        ]
        results = [f.result() for f in futures]

    for r in results:
        assert r["association"]["roleArn"] in (pod_role_b_arn, pod_role_c_arn), (
            f"racer response roleArn {r['association']['roleArn']!r} matches neither racer"
        )

    final = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert final["roleArn"] in (pod_role_b_arn, pod_role_c_arn), (
        f"final roleArn {final['roleArn']!r} is neither racer's value - corrupted state"
    )


# ===== helpers =====
from botocore.exceptions import ClientError  # noqa: E402


def _default_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets][:3]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network lacks enough subnets to provision an EKS cluster")
    return subnet_ids


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_pod_identity_role(ctx, suffix):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-podid-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _create_cluster_with_retry(ctx, name, role_arn, subnet_ids, **kwargs):
    eks = ctx.client("eks")
    # A brand-new IAM role is "not authorized" until it propagates: retry that every 2 s.
    deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            return eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                **kwargs,
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code != "ClientException" or "not authorized" not in message or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_cluster_status(ctx, name, statuses, timeout_s=1200.0, interval_s=20.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    cluster = None
    while True:
        cluster = eks.describe_cluster(name=name)["cluster"]
        if cluster["status"] in statuses:
            return cluster
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"cluster {name} did not reach {statuses} within {timeout_s}s "
                f"(last={cluster['status']})"
            )
        time.sleep(interval_s)


def _delete_cluster(ctx, name):
    _delete_eks_cluster_and_wait(ctx.client("eks"), name)



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
