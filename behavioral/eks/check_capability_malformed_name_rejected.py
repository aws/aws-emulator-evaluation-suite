"""capability-malformed-name-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "capability-malformed-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapability with a malformed capabilityName is rejected with
    InvalidParameterException, and the capability is never created on the cluster -- while a
    syntactically valid capability request with the same role and cluster succeeds."""
    eks = ctx.client("eks")
    if "CreateCapability" not in eks.meta.service_model.operation_names:
        raise AssertionError("installed botocore does not implement the EKS capabilities API")

    cluster_name = _create_active_cluster(ctx)
    role_arn = _create_capability_role(ctx)
    cluster_key = _cluster_param(eks, "CreateCapability")

    # Positive control first: prove the role is usable at all (past any IAM
    # propagation delay) with a syntactically valid name.
    valid_name = ctx.unique_name("sim2real-kro-").replace("_", "-")
    resp = _create_capability_with_retry(
        ctx,
        eks,
        **{cluster_key: cluster_name},
        capabilityName=valid_name,
        type="KRO",
        roleArn=role_arn,
        deletePropagationPolicy="RETAIN",
        tags={"sim2real": "1"},
    )
    assert resp["capability"]["capabilityName"] == valid_name, resp

    ctx.on_cleanup(lambda: _delete_capability_and_wait(eks, cluster_name, valid_name))

    # Now the role is proven usable -- a malformed capabilityName is rejected purely on
    # its own merits, with InvalidParameterException.
    malformed_name = "bad capability name!!"
    err = _error(
        lambda: eks.create_capability(
            **{cluster_key: cluster_name},
            capabilityName=malformed_name,
            type="KRO",
            roleArn=role_arn,
            deletePropagationPolicy="RETAIN",
        )
    )
    assert err == (
        "InvalidParameterException",
        "Capability name must start with a letter or number and contain only letters, numbers, hyphens, and underscores",
    ), err

    # Effect absent: no capability with the malformed name exists on the cluster.
    list_key = _cluster_param(eks, "ListCapabilities")
    listed = eks.list_capabilities(**{list_key: cluster_name}).get("capabilities", [])
    assert all(c.get("capabilityName") != malformed_name for c in listed), listed
    # And the earlier, valid capability is still there, unaffected.
    assert any(c.get("capabilityName") == valid_name for c in listed), listed


# ===== helpers =====

def _error(fn):
    """Call fn, require it raises ClientError, return its (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


def _cluster_param(client, op_name: str) -> str:
    shape = client.meta.service_model.operation_model(op_name).input_shape
    members = shape.members if shape else {}
    for candidate in ("clusterName", "name"):
        if candidate in members:
            return candidate
    raise AssertionError(f"no cluster-name member found for operation {op_name}")


def _default_vpc_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account/region has no shared network VPC to provision a test EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = list(by_az.values())[:3]
    if len(ids) < 2:
        raise AssertionError("shared network lacks subnets in >=2 availability zones")
    return ids


def _create_cluster_role(ctx) -> str:
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
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
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
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_capability_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-cap-role-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_capability_with_retry(ctx, eks, **kwargs) -> dict:
    """CreateCapability can reject a just-created role's trust policy as "invalid" for a
    short window while IAM propagates it; retry on that specific transient signature."""
    deadline = time.monotonic() + 60
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return eks.create_capability(**kwargs)
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] == "InvalidParameterException" and "trust policy" in str(exc):
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"create_capability never accepted the role's trust policy: {last_exc}")


def _create_active_cluster(ctx, timeout_s: float = 20 * 60) -> str:
    eks = ctx.client("eks")
    subnet_ids = _default_vpc_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    # The just-created role is rejected until IAM propagates it: retry every 2 s up to 72 s,
    # capped by the run's remaining time.
    retry_deadline = time.monotonic() + 72.0
    left = ctx.time_left()
    if left is not None:
        retry_deadline = min(retry_deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                accessConfig={"authenticationMode": "API"},
                tags={"sim2real": "1"},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidParameterException", "ClientException"):
                raise
            if time.monotonic() >= retry_deadline:
                raise AssertionError(f"create_cluster never succeeded (IAM role propagation?): {exc}") from exc
        time.sleep(2)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == "ACTIVE":
            return name
        if status == "FAILED":
            raise AssertionError(f"cluster {name} reached FAILED status while provisioning")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not become ACTIVE within {timeout_s}s")


def _delete_capability_and_wait(eks, cluster_name: str, capability_name: str, timeout_s: float = 900.0) -> None:
    """Teardown: DeleteCapability is asynchronous, and DeleteCluster refuses a cluster that still
    has capabilities attached, so wait until the capability reads not-found."""
    try:
        eks.delete_capability(clusterName=cluster_name, capabilityName=capability_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_capability(clusterName=cluster_name, capabilityName=capability_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"capability {capability_name} still present {timeout_s}s after DeleteCapability")



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
