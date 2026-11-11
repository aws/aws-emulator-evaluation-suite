"""describe-identity-provider-config-unknown-name-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-identity-provider-config-unknown-name-not-found"
GROUP = "error-semantics"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeIdentityProviderConfig for an unknown config name, on an existing or an unknown
    cluster, returns ResourceNotFoundException with the generic "The requested resource does not
    exist." message; listing configs on the existing cluster succeeds."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    describe_key = _cluster_param(eks, "DescribeIdentityProviderConfig")
    missing_name = ctx.unique_name("sim2real-no-such-oidc-")

    on_real_cluster = _error_detail(
        lambda: eks.describe_identity_provider_config(
            **{describe_key: cluster_name},
            identityProviderConfig={"name": missing_name, "type": "oidc"},
        )
    )
    assert on_real_cluster["Code"] == "ResourceNotFoundException", on_real_cluster
    expected_real = "The requested resource does not exist."
    assert on_real_cluster.get("Message") == expected_real, (expected_real, on_real_cluster)

    # Same call, but against a cluster that was never created: AWS answers with the same
    # code AND the same generic message, so both are graded exactly.
    unknown_cluster = ctx.unique_name("sim2real-no-such-cluster-")
    on_unknown_cluster = _error_detail(
        lambda: eks.describe_identity_provider_config(
            **{describe_key: unknown_cluster},
            identityProviderConfig={"name": missing_name, "type": "oidc"},
        )
    )
    assert on_unknown_cluster["Code"] == "ResourceNotFoundException", on_unknown_cluster
    expected_unknown = "The requested resource does not exist."
    assert on_unknown_cluster.get("Message") == expected_unknown, (expected_unknown, on_unknown_cluster)

    # Positive control: the API surface for this cluster is otherwise fully functional --
    # listing identity provider configs on the same, real cluster succeeds.
    list_key = _cluster_param(eks, "ListIdentityProviderConfigs")
    listed = eks.list_identity_provider_configs(**{list_key: cluster_name})["identityProviderConfigs"]
    assert all(cfg["name"] != missing_name for cfg in listed), f"{missing_name!r} unexpectedly listed in {listed!r}"


def _error_detail(fn) -> dict:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("expected the call to fail, but it succeeded")


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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _create_active_cluster(ctx, timeout_s: float = 20 * 60) -> str:
    eks = ctx.client("eks")
    subnet_ids = _default_vpc_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    left = ctx.time_left()
    create_deadline = time.monotonic() + (72.0 if left is None else min(72.0, left))
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real": "1"},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidParameterException", "ClientException"):
                raise
            if time.monotonic() >= create_deadline:
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



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.
    DeleteCluster is refused while an update, node group or add-on operation runs; that is retried.
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
