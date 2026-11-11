"""e2e-cluster-delete-blocked-by-active-nodegroup-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-cluster-delete-blocked-by-active-nodegroup-rejected"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster is rejected while a managed nodegroup still exists (cluster stays
    ACTIVE, untouched); removing the nodegroup first is a positive control showing the
    very same DeleteCluster call then succeeds."""
    eks = ctx.client("eks")
    subnet_ids = _pick_two_az_subnets(ctx)
    cluster_role_arn = _create_role(ctx, "eks.amazonaws.com", ["AmazonEKSClusterPolicy"])
    node_role_arn = _create_role(
        ctx,
        "ec2.amazonaws.com",
        ["AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy", "AmazonEC2ContainerRegistryReadOnly"],
    )

    cluster_name = ctx.unique_name("sim2real-eks-block-")
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
        tags={"sim2real": "1"},
    )
    ctx.on_cleanup(lambda: _safe_delete_nodegroup(ctx, eks, cluster_name, nodegroup_name))
    _wait_nodegroup_status(ctx, eks, cluster_name, nodegroup_name, "ACTIVE", timeout_s=900)

    # Break exactly one thing: try to delete the cluster while its nodegroup is still attached.
    code, message = _expect_rejection(lambda: eks.delete_cluster(name=cluster_name))
    assert code == "ResourceInUseException", f"expected ResourceInUseException while nodegroup {nodegroup_name} is active, got {code!r}"
    assert message == "Cluster has nodegroups attached", f"unexpected DeleteCluster message {message!r}"

    # Effect absent: the cluster is untouched, still ACTIVE, not transitioning to DELETING.
    status_after = eks.describe_cluster(name=cluster_name)["cluster"]["status"]
    assert status_after == "ACTIVE", f"expected cluster {cluster_name} to remain ACTIVE after the rejected delete, got {status_after!r}"
    ng_status_after = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"][
        "status"
    ]
    assert ng_status_after == "ACTIVE", f"expected nodegroup {nodegroup_name} to remain ACTIVE after the rejected delete, got {ng_status_after!r}"

    # Positive control: remove the dependent, then the exact same DeleteCluster call succeeds.
    eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    _wait_nodegroup_gone(ctx, eks, cluster_name, nodegroup_name, timeout_s=900)

    eks.delete_cluster(name=cluster_name)
    _wait_cluster_gone(ctx, eks, cluster_name, timeout_s=900)


def _gone(fn) -> bool:
    """Whether fn raises ResourceNotFoundException; a success means not yet gone, other errors raise."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _expect_rejection(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises immediately."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected with ResourceInUseException, but it SUCCEEDED and returned {result!r}")


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name, managed_policy_names))
    for policy_name in managed_policy_names:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
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
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real": "1"},
            )
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ClientException":
                time.sleep(2.0)
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
