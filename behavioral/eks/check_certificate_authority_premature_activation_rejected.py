"""certificate-authority-premature-activation-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-authority-premature-activation-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ActivateCertificateAuthority on a successor CA whose CreateCertificateAuthority append
    update is still in flight is rejected with ResourceInUseException, leaves the CA NOT_USED,
    and the same activation succeeds once distribution completes (positive control)."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    create_resp = eks.create_certificate_authority(clusterName=cluster_name)
    created = create_resp["certificateAuthority"]
    successor_id = created["id"]
    assert created["signingStatus"] == "NOT_USED", created

    # Try to activate immediately -- the append update this CreateCertificateAuthority call
    # just started is still in flight, so this must be rejected.
    code, message = _error(
        lambda: eks.activate_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=successor_id
        )
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code!r}"
    expected = (
        f"Cannot CertificateAuthorityUpdate because cluster {cluster_name} currently has "
        f"update {create_resp['update']['id']} in progress"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unaffected = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=successor_id
    )["certificateAuthority"]
    assert unaffected["signingStatus"] == "NOT_USED", "rejected premature activation must not promote the CA"

    distributed = _poll_until(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=successor_id
        )["certificateAuthority"],
        lambda ca: ca["distributionStatus"] in ("COMPLETE", "FAILED"),
        timeout_s=1800.0,
        interval_s=20.0,
    )
    assert distributed["distributionStatus"] == "COMPLETE", distributed

    # positive control: the identical activation call now succeeds
    eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    activated = _poll_until(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=successor_id
        )["certificateAuthority"],
        lambda ca: ca["signingStatus"] == "IN_USE",
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert activated["signingStatus"] == "IN_USE", activated


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


def _default_vpc_subnets(ctx, min_subnets: int = 2) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host a test EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < min_subnets:
        raise AssertionError("shared network lacks subnets in enough distinct AZs for an EKS cluster")
    return subnet_ids[:3]


def _create_eks_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup() -> None:
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


def _create_cluster_with_role_propagation_retry(
    eks, timeout_s: float = 90.0, interval_s: float = 10.0, **kwargs: Any
) -> None:
    deadline = time.monotonic() + timeout_s
    last_code: str | None = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ClientException":
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"CreateCluster kept failing with {last_code} after {timeout_s}s (IAM role propagation?)")


def _create_active_cluster(ctx, version: str | None = None) -> str:
    eks = ctx.client("eks")
    subnet_ids = _default_vpc_subnets(ctx)
    role_arn = _create_eks_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs: dict[str, Any] = {"name": name, "roleArn": role_arn, "resourcesVpcConfig": {"subnetIds": subnet_ids}}
    if version:
        kwargs["version"] = version
    _create_cluster_with_role_propagation_retry(eks, **kwargs)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster}")
    return name



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
