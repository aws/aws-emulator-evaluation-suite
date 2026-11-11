"""e2e-cluster-nodegroup-pod-identity-teardown."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-cluster-nodegroup-pod-identity-teardown"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With a nodegroup attached DeleteCluster fails with ResourceInUseException ("Cluster has nodegroups
    attached") and the cluster stays ACTIVE; a deleted pod identity association leaves the listing and
    answers ResourceNotFoundException, then the nodegroup and the cluster delete in that order."""
    eks = ctx.client("eks")
    subnet_ids = _pick_two_az_subnets(ctx)
    cluster_role_arn = _create_role(ctx, "eks.amazonaws.com", ["AmazonEKSClusterPolicy"])
    node_role_arn = _create_role(
        ctx,
        "ec2.amazonaws.com",
        ["AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy", "AmazonEC2ContainerRegistryReadOnly"],
    )
    pod_role_arn = _create_pod_identity_role(ctx)

    cluster_name = ctx.unique_name("sim2real-eks-cnp-")
    _create_cluster_with_retry(eks, cluster_name, cluster_role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, eks, cluster_name))
    _wait_cluster_status(ctx, eks, cluster_name, "ACTIVE", timeout_s=1500)

    nodegroup_name = ctx.unique_name("sim2real-ng-")
    eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        subnets=subnet_ids,
        nodeRole=node_role_arn,
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
    )
    ctx.on_cleanup(lambda: _safe_delete_nodegroup(ctx, eks, cluster_name, nodegroup_name))
    _wait_nodegroup_status(ctx, eks, cluster_name, nodegroup_name, "ACTIVE", timeout_s=900)

    association_id = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace="sim2real-ns",
        serviceAccount="sim2real-sa",
        roleArn=pod_role_arn,
    )["association"]["associationId"]
    ctx.on_cleanup(lambda: _safe_delete_pod_identity(ctx, eks, cluster_name, association_id))

    listed = eks.list_pod_identity_associations(clusterName=cluster_name)["associations"]
    assert any(a["associationId"] == association_id for a in listed), (
        "newly created pod identity association was not returned by ListPodIdentityAssociations"
    )

    # Break exactly one thing: DeleteCluster must be rejected while the nodegroup is
    # still attached — this is the "delete order matters" claim, actually exercised.
    blocked_code, blocked_msg = _error(lambda: eks.delete_cluster(name=cluster_name))
    assert blocked_code == "ResourceInUseException", (
        f"expected ResourceInUseException deleting a cluster with an active nodegroup, got {blocked_code!r}"
    )
    assert blocked_msg == "Cluster has nodegroups attached", f"unexpected DeleteCluster message {blocked_msg!r}"
    status_after_block = eks.describe_cluster(name=cluster_name)["cluster"]["status"]
    assert status_after_block == "ACTIVE", (
        f"cluster should remain ACTIVE after the blocked delete, got {status_after_block!r}"
    )

    # Tear down dependents in order and observe each removal take effect.
    eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    listed_after = eks.list_pod_identity_associations(clusterName=cluster_name)["associations"]
    assert all(a["associationId"] != association_id for a in listed_after), (
        f"deleted pod identity association {association_id} still appears in ListPodIdentityAssociations"
    )
    gone_code, gone_msg = _error(
        lambda: eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    )
    assert gone_code == "ResourceNotFoundException", "deleted pod identity association is still describable by id"
    assert gone_msg == f"No service account role association found for ID: {association_id}", gone_msg

    eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    _wait_nodegroup_gone(ctx, eks, cluster_name, nodegroup_name, timeout_s=900)

    # Only now that both dependents are gone does cluster deletion succeed.
    eks.delete_cluster(name=cluster_name)
    _wait_cluster_gone(ctx, eks, cluster_name, timeout_s=900)


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _gone(fn) -> bool:
    """Whether fn raises ResourceNotFoundException; a success means not yet gone, other errors raise."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _pick_two_az_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision an EKS test cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 availability zones")
    return list(by_az.values())[:2]


def _create_role(ctx, service_principal: str, managed_policy_names: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}],
    }
    import json

    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name, managed_policy_names))
    for policy_name in managed_policy_names:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
    return role_arn


def _create_pod_identity_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-podrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    import json

    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name, []))
    return role_arn


def _safe_delete_role(ctx, role_name: str, managed_policy_names: list[str]) -> None:
    iam = ctx.client("iam")
    for policy_name in managed_policy_names:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_cluster_with_retry(eks, name: str, role_arn: str, subnet_ids: list[str], timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ClientException":
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"CreateCluster kept failing with {last_code} after {timeout_s}s (IAM role propagation?)")


def _wait_cluster_status(ctx, eks, name: str, want: str, timeout_s: float, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last == want:
            return
        if last == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {want} within {timeout_s}s (last={last})")


def _wait_cluster_gone(ctx, eks, name: str, timeout_s: float, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _gone(lambda: eks.describe_cluster(name=name)):
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _wait_nodegroup_status(ctx, eks, cluster_name: str, nodegroup_name: str, want: str, timeout_s: float, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]["status"]
        if last == want:
            return
        if last in ("CREATE_FAILED", "DELETE_FAILED"):
            raise AssertionError(f"nodegroup {nodegroup_name} entered {last} while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} did not reach {want} within {timeout_s}s (last={last})")


def _wait_nodegroup_gone(ctx, eks, cluster_name: str, nodegroup_name: str, timeout_s: float, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _gone(lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)):
            return
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} was not deleted within {timeout_s}s")


def _safe_delete_cluster(ctx, eks, name: str) -> None:
    _delete_eks_cluster_retrying(eks, name)
    _wait_cluster_gone(ctx, eks, name, timeout_s=900)


def _safe_delete_nodegroup(ctx, eks, cluster_name: str, nodegroup_name: str) -> None:
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    try:
        _wait_nodegroup_gone(ctx, eks, cluster_name, nodegroup_name, timeout_s=900)
    except AssertionError:
        pass


def _safe_delete_pod_identity(ctx, eks, cluster_name: str, association_id: str) -> None:
    try:
        eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
