"""certificate-authority-delete-while-active-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-authority-delete-while-active-blocked"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After rotation, DeleteCertificateAuthority on the new IN_USE signer fails with ResourceInUseException
    and its exact message and the CA stays IN_USE, while the retired CA deletes and then fails Describe and
    Activate with ResourceNotFoundException.
    """
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    original = eks.list_certificate_authorities(clusterName=cluster)["certificateAuthorities"]
    assert len(original) == 1, f"expected exactly one CA on a fresh cluster, got {original}"
    original_ca_id = original[0]["id"]
    assert original[0]["signingStatus"] == "IN_USE", (
        f"expected the sole CA on a fresh cluster to be the active signer, "
        f"got signingStatus={original[0]['signingStatus']!r}"
    )

    # Append a successor CA and rotate to it so it becomes the active signer.
    #
    # distributionStatus COMPLETE is a real precondition for activation, not a side effect of
    # it: real AWS rejects an early ActivateCertificateAuthority deterministically with
    # InvalidRequestException("cannot activate CA: distributionStatus must be COMPLETE").
    # A fresh successor's distribution can still be IN_PROGRESS well past 900s, so the poll
    # needs real headroom. Once COMPLETE is reached, activation is
    # also wrapped in a bounded retry that tolerates a transient ResourceInUseException (the
    # successor's own just-created update briefly still settling under account contention).
    successor_id = eks.create_certificate_authority(clusterName=cluster)["certificateAuthority"]["id"]

    _poll_until(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster, certificateAuthorityId=successor_id
        )["certificateAuthority"],
        lambda ca: ca["distributionStatus"] == "COMPLETE",
        timeout_s=1800,
        interval_s=15,
    )

    activate_resp = _retry_activation(eks, cluster, successor_id, timeout_s=900, interval_s=10)
    finished_update = _poll_until(
        lambda: eks.describe_update(name=cluster, updateId=activate_resp["update"]["id"])["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=900,
        interval_s=15,
    )
    assert finished_update["status"] == "Successful", (
        f"CA activation update {activate_resp['update']['id']} did not succeed: {finished_update}"
    )

    successor = eks.describe_certificate_authority(
        clusterName=cluster, certificateAuthorityId=successor_id
    )["certificateAuthority"]
    assert successor["signingStatus"] == "IN_USE", (
        f"successor {successor_id} activated but signingStatus={successor['signingStatus']!r}, "
        f"expected IN_USE"
    )
    assert successor["distributionStatus"] == "COMPLETE", (
        f"successor {successor_id} activation update succeeded but distributionStatus="
        f"{successor['distributionStatus']!r}, expected COMPLETE"
    )

    # Negative: deleting the now-active signer is blocked.
    code, message = _error(
        lambda: eks.delete_certificate_authority(
            clusterName=cluster, certificateAuthorityId=successor_id
        )
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    expected = "Cannot delete the active certificate authority. Activate a different CA first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the active CA is still present, unmodified.
    still_there = eks.describe_certificate_authority(
        clusterName=cluster, certificateAuthorityId=successor_id
    )["certificateAuthority"]
    assert still_there["id"] == successor_id, (
        f"describe_certificate_authority returned a different CA than requested: "
        f"expected id={successor_id!r}, got {still_there['id']!r}"
    )
    assert still_there["signingStatus"] == "IN_USE", (
        f"the blocked delete must leave the active signer untouched, but "
        f"signingStatus={still_there['signingStatus']!r} after the rejected call"
    )

    # Positive control: the retired (NOT_USED) original CA CAN be deleted.
    eks.delete_certificate_authority(clusterName=cluster, certificateAuthorityId=original_ca_id)

    def _original_gone() -> bool:
        listing = eks.list_certificate_authorities(clusterName=cluster)["certificateAuthorities"]
        ids = {ca["id"] for ca in listing}
        return original_ca_id not in ids

    # DeleteCertificateAuthority is async: the retired CA can stay listed for more than 300s
    # after the call, so the bound needs real headroom.
    _poll_until(
        lambda: _original_gone(),
        lambda gone: gone,
        timeout_s=900,
        interval_s=15,
    )

    # The delete must also make the id independently unreadable, not merely absent
    # from the list, and a further mutation on the dead id must fail the same way.
    describe_code, describe_msg = _error(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster, certificateAuthorityId=original_ca_id
        )
    )
    assert describe_code == "ResourceNotFoundException", (
        f"deleted CA {original_ca_id} is gone from the list but describe returned "
        f"{describe_code!r}, expected ResourceNotFoundException"
    )
    # The message embeds a backend request id the check never sees; its fixed text is asserted.
    assert describe_msg.startswith(
        "certificate authority not found (Service: EksCertificateAuthority, Status Code: 404, Request ID: "
    ) and describe_msg.endswith(") (SDK Attempt Count: 1)"), describe_msg
    # The delete runs as a cluster update, and while any update is in progress every CA mutation
    # answers ResourceInUseException; wait the update out so the probe sees the dead id itself.
    _wait_no_update_in_progress(eks, cluster)
    activate_dead_code, activate_dead_msg = _error(
        lambda: eks.activate_certificate_authority(
            clusterName=cluster, certificateAuthorityId=original_ca_id
        )
    )
    assert activate_dead_code == "ResourceNotFoundException", (
        f"a mutation on the deleted CA {original_ca_id} must fail not-found, "
        f"got {activate_dead_code!r}"
    )
    expected = f"Certificate authority {original_ca_id} is not in the trusted list for cluster {cluster}"
    assert activate_dead_msg == expected, f"expected message {expected!r}, got {activate_dead_msg!r}"


def _wait_no_update_in_progress(eks, cluster, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while True:
        in_progress = [
            u for u in eks.list_updates(name=cluster)["updateIds"]
            if eks.describe_update(name=cluster, updateId=u)["update"]["status"] == "InProgress"
        ]
        if not in_progress:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {cluster} still has updates in progress: {in_progress}")
        time.sleep(interval_s)


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _retry_activation(eks, cluster_name, certificate_authority_id, *, timeout_s=900.0, interval_s=10.0):
    """ActivateCertificateAuthority, tolerating a transient ResourceInUseException (the
    successor CA's own just-created update briefly still settling) with a bounded retry."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return eks.activate_certificate_authority(
                clusterName=cluster_name, certificateAuthorityId=certificate_authority_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceInUseException":
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _pick_subnets(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            "account/region lacks a shared network VPC with subnets in >=2 AZs; cannot "
            "provision a real EKS cluster for this check"
        )
    return list(by_az.values())[:3]


def _create_cluster_role(ctx):
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
            )
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


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    subnet_ids = _pick_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    cluster_name = ctx.unique_name("sim2real-ekscl-")

    # A just-created role is refused with InvalidParameterException until IAM propagates it.
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else min(120.0, left))
    while True:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real": "true"},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, cluster_name))
    eks.get_waiter("cluster_active").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )
    return cluster_name


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
    deadline = time.monotonic() + timeout_s
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
