"""certificate-authority-delete-in-use-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-authority-delete-in-use-rejected"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCertificateAuthority on the IN_USE signer fails with ResourceInUseException "Cannot delete the
    active certificate authority. Activate a different CA first." and the CA stays IN_USE, while a NOT_USED
    successor's delete update ends Successful and only the signer remains.
    """
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    original = eks.list_certificate_authorities(clusterName=cluster["name"])["certificateAuthorities"]
    assert len(original) == 1, f"expected exactly one CA on a freshly-created cluster, got {original}"
    active_id = original[0]["id"]
    assert original[0]["signingStatus"] == "IN_USE", f"expected the cluster's sole CA to be IN_USE, got {original[0]}"

    # --- negative: cannot delete the active signer ---
    err = _error(
        lambda: eks.delete_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=active_id)
    )
    assert err == ("ResourceInUseException", "Cannot delete the active certificate authority. Activate a different CA first."), f"expected ResourceInUseException deleting the active signer, got {err!r}"

    still_there = eks.describe_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=active_id)[
        "certificateAuthority"
    ]
    assert still_there["id"] == active_id, f"active CA id changed after a rejected delete: {still_there}"
    assert still_there["signingStatus"] == "IN_USE", f"active CA left the IN_USE state after a rejected delete: {still_there}"

    # --- positive control: a NOT_USED successor CA (never activated) deletes cleanly ---
    created = eks.create_certificate_authority(clusterName=cluster["name"])
    successor = created["certificateAuthority"]
    successor_id = successor["id"]
    assert successor["signingStatus"] == "NOT_USED", f"freshly-appended successor should start NOT_USED, got {successor}"

    # A cluster admits exactly one in-flight update at a time. Appending the successor is
    # itself an async update, so deleting immediately races it and surfaces as
    # ResourceInUseException("... currently has update ... in progress"), not a signing-status
    # rejection. Wait for that append's
    # own update to settle before the delete, so the delete's outcome is unambiguously about
    # signing state.
    append_status = _poll_until(
        lambda: eks.describe_update(name=cluster["name"], updateId=created["update"]["id"])["update"]["status"],
        lambda s: s in ("Successful", "Failed", "Cancelled"),
        timeout_s=600.0,
        interval_s=10.0,
        description=f"successor-append update {created['update']['id']} reaching a terminal status",
    )
    assert append_status == "Successful", f"successor CA append did not succeed: {append_status}"

    delete_resp = eks.delete_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=successor_id)

    # DeleteCertificateAuthority is also async: it returns its own `update`, and the successor
    # stays listed until that update completes. Wait for its terminal status before an
    # independent read.
    delete_status = _poll_until(
        lambda: eks.describe_update(name=cluster["name"], updateId=delete_resp["update"]["id"])["update"]["status"],
        lambda s: s in ("Successful", "Failed", "Cancelled"),
        timeout_s=600.0,
        interval_s=10.0,
        description=f"successor-delete update {delete_resp['update']['id']} reaching a terminal status",
    )
    assert delete_status == "Successful", f"successor CA delete did not succeed: {delete_status}"

    def _still_present():
        ids = [ca["id"] for ca in eks.list_certificate_authorities(clusterName=cluster["name"])["certificateAuthorities"]]
        return successor_id in ids

    gone = _poll_until(
        lambda: _still_present(),
        lambda still: not still,
        timeout_s=300.0,
        interval_s=10.0,
        description="successor CA removal from ListCertificateAuthorities",
    )
    assert gone is False, "successor CA is still listed after a successful delete"

    final_ids = {ca["id"] for ca in eks.list_certificate_authorities(clusterName=cluster["name"])["certificateAuthorities"]}
    assert final_ids == {active_id}, f"expected only the untouched active signer to remain, got {final_ids}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s, last observed: {last}")


def _default_subnets(ctx, min_azs=2):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = list(by_az.values())
    if len(ids) < min_azs:
        raise AssertionError(
            "account/region has no shared network VPC with >=2 AZ subnets required for EKS "
            "cluster creation; provision one to close this gap"
        )
    return ids[:min_azs]


def _create_cluster_with_retry(eks, kwargs, *, timeout_s=180.0, interval_s=10.0):
    """CreateCluster can reject a role that has not finished IAM propagation yet. Retry on the
    specific transient error codes for a bounded window instead of sleeping unconditionally before
    the first attempt -- a fast propagation should not pay a fixed 10s tax, and a slow one should
    not fail after exactly one try."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code in ("InvalidParameterException", "ClientException"):
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"CreateCluster kept failing with {last_code} after {timeout_s}s (IAM role propagation?)")


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )["Role"]
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
    return role["Arn"]


def _create_active_cluster(ctx, extra_kwargs=None):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnet_ids = _default_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        tags={"sim2real-managed": "true"},
    )
    if extra_kwargs:
        kwargs.update(extra_kwargs)
    _create_cluster_with_retry(eks, kwargs)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
        interval_s=20.0,
        description=f"cluster {name} reaching a terminal status",
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster did not reach ACTIVE: {cluster['status']}")
    return {"name": name, "arn": cluster["arn"], "role_arn": role_arn, "subnet_ids": subnet_ids}


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
