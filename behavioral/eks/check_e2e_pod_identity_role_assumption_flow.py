"""e2e-pod-identity-role-assumption-flow."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pod-identity-role-assumption-flow"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pod identity association describes and lists with its role, namespace and service account, the role
    assumes to the expected STS identity, and after deletion it fails Describe with ResourceNotFoundException
    and its exact message and is absent from the list.
    """
    eks = ctx.client("eks")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    cluster = _create_minimal_cluster(ctx)
    namespace = "default"
    service_account = ctx.unique_name("sim2real-sa-")[:63]

    caller_arn = sts.get_caller_identity()["Arn"]
    pod_role_name = ctx.unique_name("sim2real-eks-podrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": caller_arn},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    pod_role_arn = iam.create_role(
        RoleName=pod_role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=pod_role_name))

    assoc = _create_association_with_retry(
        eks, cluster["name"], namespace, service_account, pod_role_arn
    )
    association_id = assoc["associationId"]

    # Role resolution: the association binds the exact role for the exact service account.
    described = eks.describe_pod_identity_association(
        clusterName=cluster["name"], associationId=association_id
    )["association"]
    assert described["roleArn"] == pod_role_arn
    assert described["namespace"] == namespace
    assert described["serviceAccount"] == service_account

    listed = eks.list_pod_identity_associations(
        clusterName=cluster["name"], namespace=namespace, serviceAccount=service_account
    )["associations"]
    assert any(a["associationId"] == association_id for a in listed), (
        "role resolution binding not enumerable by namespace/serviceAccount"
    )

    # Role assumption: the bound role is a real, live, assumable IAM role, not just
    # recorded metadata — assuming it must yield a caller identity that resolves through it.
    session_name = "sim2real-podid-session"
    creds = _assume_role_with_retry(sts, pod_role_arn, session_name)
    assumed_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    identity = assumed_sts.get_caller_identity()
    assert identity["Arn"].endswith(f"assumed-role/{pod_role_name}/{session_name}"), identity["Arn"]

    eks.delete_pod_identity_association(clusterName=cluster["name"], associationId=association_id)

    # Deleted binding must no longer resolve.
    code, msg = _error_code(
        lambda: eks.describe_pod_identity_association(
            clusterName=cluster["name"], associationId=association_id
        )
    )
    assert code == "ResourceNotFoundException", f"unexpected code after delete: {code}"
    expected = f"No service account role association found for ID: {association_id}"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    listed_after = eks.list_pod_identity_associations(
        clusterName=cluster["name"], namespace=namespace, serviceAccount=service_account
    )["associations"]
    assert not any(a["associationId"] == association_id for a in listed_after), (
        "deleted association still resolves via ListPodIdentityAssociations"
    )


def _error_code(fn):
    """Call fn(); return the (Code, Message) of the error it raises, and raise on success."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _create_association_with_retry(
    eks: Any, cluster_name: str, namespace: str, service_account: str, role_arn: str,
    timeout_s: float = 60.0, interval_s: float = 5.0,
) -> dict[str, Any]:
    """A freshly created role's trust policy can take a few seconds to propagate;
    retry the transient rejection within a bounded window rather than failing on
    the very first attempt."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return eks.create_pod_identity_association(
                clusterName=cluster_name,
                namespace=namespace,
                serviceAccount=service_account,
                roleArn=role_arn,
            )["association"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidParameterException", "AccessDeniedException", "AccessDenied"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"create_pod_identity_association still failing after {timeout_s}s (IAM propagation): {last_exc}"
    )


def _assume_role_with_retry(
    sts_client: Any, role_arn: str, session_name: str, timeout_s: float = 90.0, interval_s: float = 5.0,
) -> dict[str, Any]:
    """A freshly created role's trust policy can take a few seconds to propagate through
    IAM; retry AccessDenied on assume-role within a bounded window rather than failing
    on the very first attempt."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDenied":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"assume_role on {role_arn} still denied after {timeout_s}s (IAM propagation): {last_exc}")


def _create_cluster_with_retry(
    eks: Any, timeout_s: float = 90.0, interval_s: float = 10.0, **kwargs: Any
) -> None:
    """EKS rejects CreateCluster with a freshly created cluster role until IAM
    propagates it; retry the transient rejection within a bounded window."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidParameterException", "ClientException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"create_cluster still failing after {timeout_s}s (IAM role propagation): {last_exc}")


def _create_minimal_cluster(ctx, authentication_mode: str | None = None) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")

    vpc_id = ec2.create_vpc(CidrBlock="10.70.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.70.{i}.0/24", AvailabilityZone=az
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))

    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
        )
    )

    cluster_name = ctx.unique_name("sim2real-eks-")
    kwargs: dict[str, Any] = dict(
        name=cluster_name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}
    )
    if authentication_mode:
        kwargs["accessConfig"] = {"authenticationMode": authentication_mode}
    _create_cluster_with_retry(eks, **kwargs)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, cluster_name))
    _wait_for_cluster_status(eks, cluster_name, "ACTIVE", timeout_s=1200.0)
    return {"name": cluster_name, "role_arn": role_arn, "subnet_ids": subnet_ids, "vpc_id": vpc_id}


def _wait_for_cluster_status(eks: Any, name: str, want: str, timeout_s: float = 1200.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last == want:
            return
        if last == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {want} in {timeout_s}s (last={last})")


def _delete_cluster_and_wait(eks: Any, name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    try:
        eks.delete_cluster(name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise AssertionError(f"unexpected delete_cluster error: {err}") from err
        if err.response["Error"].get("Message", "").rstrip(".") != f"No cluster found for name: {name}":
            raise AssertionError(f"unexpected delete_cluster message: {err}") from err
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not delete within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
