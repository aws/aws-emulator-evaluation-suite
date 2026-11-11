"""e2e-certificate-authority-issue-activate-disable-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-certificate-authority-issue-activate-disable-delete"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A successor CA is listed NOT_USED at once and cannot be activated until distribution is
    COMPLETE; if that happens in a bounded window the signer swaps. An IN_USE CA cannot be deleted,
    and removed CAs leave the listing."""
    eks = ctx.client("eks")
    subnet_ids = _pick_two_az_subnets(ctx)
    cluster_role_arn = _create_role(ctx, "eks.amazonaws.com", ["AmazonEKSClusterPolicy"])

    cluster_name = ctx.unique_name("sim2real-eks-ca-")
    _create_cluster_with_retry(eks, cluster_name, cluster_role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, eks, cluster_name))
    _wait_cluster_status(ctx, eks, cluster_name, "ACTIVE", timeout_s=1200)

    # The cluster is provisioned with exactly one, already-active, certificate authority.
    initial_cas = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(initial_cas) == 1, f"expected exactly 1 certificate authority on a fresh cluster, got {initial_cas!r}"
    outgoing_ca_id = initial_cas[0]["id"]
    assert initial_cas[0]["signingStatus"] == "IN_USE", (
        f"expected the sole initial CA to be signingStatus=IN_USE, got {initial_cas[0]['signingStatus']!r}"
    )

    created = eks.create_certificate_authority(clusterName=cluster_name)["certificateAuthority"]
    successor_id = created["id"]
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, eks, cluster_name, successor_id))
    assert successor_id != outgoing_ca_id, f"successor CA id {successor_id!r} collided with the outgoing CA id"
    assert created["signingStatus"] == "NOT_USED", "a freshly appended successor CA must not start as the signer"

    # The successor shows up in the listing right away, alongside the outgoing signer.
    listed = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    listed_ids = {c["id"] for c in listed}
    assert {outgoing_ca_id, successor_id} <= listed_ids, "successor CA was not reflected by ListCertificateAuthorities"

    # CA distribution to AWS-managed components varies by cluster and can take well beyond a
    # single test's budget; poll a bounded window rather than block on completion.
    distribution_complete = _poll_ca_field_bounded(
        eks, cluster_name, successor_id, "distributionStatus", "COMPLETE", timeout_s=480, interval_s=20.0
    )

    if distribution_complete:
        # Positive path: distribution finished in time, so activation is real and observable.
        eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
        _wait_ca_field(ctx, eks, cluster_name, successor_id, "signingStatus", "IN_USE", timeout_s=240)

        listed_after_activate = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
        by_id = {c["id"]: c for c in listed_after_activate}
        assert by_id[successor_id]["signingStatus"] == "IN_USE", (
            f"expected activated successor {successor_id} to be signingStatus=IN_USE, "
            f"got {by_id[successor_id]['signingStatus']!r}"
        )
        # The outgoing CA is retired (no longer the signer) but still trusted/present.
        assert by_id[outgoing_ca_id]["signingStatus"] == "NOT_USED", (
            f"expected retired outgoing CA {outgoing_ca_id} to be signingStatus=NOT_USED, "
            f"got {by_id[outgoing_ca_id]['signingStatus']!r}"
        )

        # Negative: the active signer itself is protected and cannot be deleted while in use.
        code, message = _error(
            lambda: eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
        )
        assert code == "ResourceInUseException", f"expected ResourceInUseException deleting the active signer, got {code!r}"
        assert message == _ACTIVE_CA_DELETE, message
        still_listed = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
        assert any(c["id"] == successor_id for c in still_listed), "active signer must not have been removed"

        # Positive: now that a successor has been activated, the retired outgoing CA can be deleted.
        eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=outgoing_ca_id)
        _wait_ca_gone(ctx, eks, cluster_name, outgoing_ca_id, timeout_s=240)

        final_listed = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
        final_ids = {c["id"] for c in final_listed}
        assert outgoing_ca_id not in final_ids, "deleted outgoing CA still present in the listing"
        assert successor_id in final_ids, "activated successor CA disappeared unexpectedly"
    else:
        # Distribution is still in progress: activating the successor now must be rejected --
        # this is the real safeguard from the docs ("successor CA can't be activated until
        # distribution is complete"), not a client-side assumption.
        _error(
            lambda: eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
        )

        # The successor is untouched: still listed, still NOT_USED.
        still = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
        by_id = {c["id"]: c for c in still}
        assert by_id[successor_id]["signingStatus"] == "NOT_USED", (
            f"expected untouched successor {successor_id} to remain signingStatus=NOT_USED, "
            f"got {by_id[successor_id]['signingStatus']!r}"
        )

        # The outgoing CA remains the sole signer, and remains protected from deletion while
        # it is IN_USE -- the exact same safeguard the positive path exercises after rotation.
        code2, message2 = _error(
            lambda: eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=outgoing_ca_id)
        )
        assert code2 == "ResourceInUseException", (
            f"expected ResourceInUseException deleting the sole active signer, got {code2!r}"
        )
        assert message2 == _ACTIVE_CA_DELETE, message2


#: DeleteCertificateAuthority's refusal for the CA that is signing.
_ACTIVE_CA_DELETE = "Cannot delete the active certificate authority. Activate a different CA first."


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses is not reduced to an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected real AWS to reject this call, but it SUCCEEDED and returned {result!r}")


def _gone(fn):
    """True once fn() answers ResourceNotFoundException, False while it succeeds (for gone-polling)."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return True
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
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


def _safe_delete_cluster(ctx, eks, name: str) -> None:
    _delete_eks_cluster_retrying(eks, name)
    _wait_cluster_gone(ctx, eks, name, timeout_s=900)


def _wait_ca_field(ctx, eks, cluster_name: str, ca_id: str, field: str, want: str, timeout_s: float, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)[
            "certificateAuthority"
        ][field]
        if last == want:
            return
        if field == "distributionStatus" and last == "FAILED":
            raise AssertionError(f"certificate authority {ca_id} distribution FAILED while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"certificate authority {ca_id}.{field} did not reach {want} within {timeout_s}s (last={last})")


def _poll_ca_field_bounded(eks, cluster_name: str, ca_id: str, field: str, want: str, timeout_s: float, interval_s: float = 15.0) -> bool:
    """Like _wait_ca_field, but returns False on timeout instead of raising -- distribution
    timing genuinely varies by cluster, so a bounded miss is an expected outcome, not a bug."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        last = eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)[
            "certificateAuthority"
        ][field]
        if last == want:
            return True
        if field == "distributionStatus" and last == "FAILED":
            raise AssertionError(f"certificate authority {ca_id} distribution FAILED while waiting for {want}")
        time.sleep(interval_s)
    return False


def _wait_ca_gone(ctx, eks, cluster_name: str, ca_id: str, timeout_s: float, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _gone(
            lambda: eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
        ):
            return
        time.sleep(interval_s)
    raise AssertionError(f"certificate authority {ca_id} was not deleted within {timeout_s}s")


def _safe_delete_ca(ctx, eks, cluster_name: str, ca_id: str) -> None:
    try:
        eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
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
