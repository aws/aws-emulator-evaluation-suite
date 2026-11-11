"""delete-certificate-authority-active-state-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-certificate-authority-active-state-blocked"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCertificateAuthority on the IN_USE signer fails with ResourceInUseException and its exact
    message and the CA stays IN_USE, while a NOT_USED successor deletes and then fails Describe and Activate
    with ResourceNotFoundException.
    """
    eks = ctx.client("eks")
    subnet_ids = _pick_two_az_subnets(ctx)
    role_arn = _create_role(ctx, "eks.amazonaws.com", ["AmazonEKSClusterPolicy"])

    cluster_name = ctx.unique_name("sim2real-eks-cadel-")
    _create_cluster_with_retry(eks, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, eks, cluster_name))
    _wait_cluster_status(ctx, eks, cluster_name, "ACTIVE", timeout_s=1500)

    initial = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(initial) == 1, f"expected exactly one CA on a fresh cluster, got {initial}"
    outgoing_id = initial[0]["id"]
    assert initial[0]["signingStatus"] == "IN_USE", (
        f"expected the sole CA on a fresh cluster to be the active signer, "
        f"got signingStatus={initial[0]['signingStatus']!r}"
    )

    # Negative: the sole, currently-signing CA cannot be deleted.
    code, message = _error(
        lambda: eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=outgoing_id)
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code!r}"
    expected = "Cannot delete the active certificate authority. Activate a different CA first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the CA is untouched -- still present, still the active signer.
    still = eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=outgoing_id)[
        "certificateAuthority"
    ]
    assert still["id"] == outgoing_id, (
        f"describe_certificate_authority returned a different CA than requested: "
        f"expected id={outgoing_id!r}, got {still['id']!r}"
    )
    assert still["signingStatus"] == "IN_USE", (
        f"the rejected delete must leave the active signer untouched, but "
        f"signingStatus={still['signingStatus']!r} after the rejected call"
    )

    # Positive control: a freshly appended successor, which is NOT the active signer,
    # can be deleted normally -- the rejection above is about signing state, not a
    # generally-broken DeleteCertificateAuthority. Wait for the append's own update to
    # settle first so the delete's outcome is unambiguously about signing state, not a
    # "cluster busy with an in-progress update" conflict.
    created = eks.create_certificate_authority(clusterName=cluster_name)
    successor = created["certificateAuthority"]
    successor_id = successor["id"]
    assert successor["signingStatus"] == "NOT_USED", (
        f"a freshly appended successor must start NOT_USED, got {successor['signingStatus']!r}"
    )
    append_terminal = _wait_update_terminal(ctx, eks, cluster_name, created["update"]["id"], timeout_s=600)
    assert append_terminal == "Successful", (
        f"append of successor {successor_id} did not succeed: update status={append_terminal!r}"
    )

    deleted = eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    delete_terminal = _wait_update_terminal(ctx, eks, cluster_name, deleted["update"]["id"], timeout_s=900)
    assert delete_terminal == "Successful", (
        f"delete of successor {successor_id} did not succeed: update status={delete_terminal!r}"
    )
    _wait_ca_gone(eks, cluster_name, successor_id, timeout_s=900)

    final = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    final_ids = {c["id"] for c in final}
    assert final_ids == {outgoing_id}, f"unexpected CA set after deleting the successor: {final_ids}"

    # The delete must also make the id independently unreadable, not merely absent
    # from the list, and a further mutation on the dead id must fail the same way.
    describe_dead_code, describe_dead_msg = _error(
        lambda: eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    )
    assert describe_dead_code == "ResourceNotFoundException", (
        f"deleted successor {successor_id} is gone from the list but describe returned "
        f"{describe_dead_code!r}, expected ResourceNotFoundException"
    )
    # The message embeds a backend request id the check never sees; its fixed text is asserted.
    assert describe_dead_msg.startswith(
        "certificate authority not found (Service: EksCertificateAuthority, Status Code: 404, Request ID: "
    ) and describe_dead_msg.endswith(") (SDK Attempt Count: 1)"), describe_dead_msg
    # The delete's update has completed, so the cluster is idle and the id lookup answers.
    activate_dead_code, activate_dead_msg = _error(
        lambda: eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    )
    assert activate_dead_code == "ResourceNotFoundException", (
        f"a mutation on the deleted successor {successor_id} must still fail deterministically, "
        f"got {activate_dead_code!r}"
    )
    expected = f"Certificate authority {successor_id} is not in the trusted list for cluster {cluster_name}"
    assert activate_dead_msg == expected, f"expected message {expected!r}, got {activate_dead_msg!r}"


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _gone(fn) -> bool:
    """Whether fn raises ResourceNotFoundException; any other error raises."""
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
                tags={"sim2real": "true"},
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


def _safe_delete_cluster(ctx, eks, name: str) -> None:
    try:
        eks.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    try:
        _wait_cluster_gone(ctx, eks, name, timeout_s=900)
    except AssertionError:
        pass


def _wait_update_terminal(ctx, eks, cluster_name: str, update_id: str, timeout_s: float, interval_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"]
        if last in ("Successful", "Failed", "Cancelled"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} on {cluster_name} did not reach a terminal status within {timeout_s}s (last={last})")


def _wait_ca_gone(eks, cluster_name: str, ca_id: str, timeout_s: float, interval_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _gone(
            lambda: eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
        ):
            return
        time.sleep(interval_s)
    raise AssertionError(f"certificate authority {ca_id} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
