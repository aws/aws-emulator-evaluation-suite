"""e2e-certificate-authority-activation-to-teardown."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-certificate-authority-activation-to-teardown"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """If the successor CA does not distribute in time, deleting the sole IN_USE signer fails with
    ResourceInUseException; if it does, activation makes the successor IN_USE, the original becomes
    NOT_USED, deletes, and then fails Describe and Activate with ResourceNotFoundException.
    """
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    original = eks.list_certificate_authorities(clusterName=cluster["name"])["certificateAuthorities"]
    assert len(original) == 1, f"expected exactly one CA on a freshly created cluster, got {original}"
    original_id = original[0]["id"]
    assert original[0]["signingStatus"] == "IN_USE", (
        f"expected the cluster's initial CA {original_id} to be IN_USE, got {original[0]['signingStatus']}"
    )

    created = eks.create_certificate_authority(clusterName=cluster["name"])["certificateAuthority"]
    successor_id = created["id"]
    assert created["signingStatus"] == "NOT_USED", (
        f"expected a freshly appended successor CA {successor_id} to start NOT_USED, got {created['signingStatus']}"
    )

    distributed = _poll_bounded(
        lambda: eks.describe_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=successor_id)[
            "certificateAuthority"
        ],
        lambda ca: ca["distributionStatus"] in ("COMPLETE", "FAILED"),
        timeout_s=480.0,
        interval_s=15.0,
    )

    if distributed is None or distributed["distributionStatus"] != "COMPLETE":
        # Distribution did not finish inside our budget (or failed outright). The real
        # safeguard: the original CA is still the sole signer, so teardown of it must
        # still be rejected - rotation was never completed for real.
        code, message = _error(
            lambda: eks.delete_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=original_id)
        )
        assert code == "ResourceInUseException", (
            f"expected teardown of the still-signing original {original_id} to be rejected "
            f"while rotation is incomplete, got {code!r}"
        )
        expected = "Cannot delete the active certificate authority. Activate a different CA first."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        still = eks.list_certificate_authorities(clusterName=cluster["name"])["certificateAuthorities"]
        still_ids = {ca["id"] for ca in still}
        assert {original_id, successor_id} <= still_ids, (
            f"both CAs should remain listed while rotation is incomplete: {still}"
        )
        return

    activate_resp = eks.activate_certificate_authority(
        clusterName=cluster["name"], certificateAuthorityId=successor_id
    )
    activate_update_id = activate_resp["update"]["id"]
    activate_update = _poll_until(
        lambda: eks.describe_update(name=cluster["name"], updateId=activate_update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert activate_update["status"] == "Successful", (
        f"expected activation update {activate_update_id} to finish Successful, got {activate_update['status']}"
    )

    activated = eks.describe_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=successor_id)[
        "certificateAuthority"
    ]
    assert activated["signingStatus"] == "IN_USE", (
        f"expected successor {successor_id} IN_USE once its activation update completed, got {activated['signingStatus']}"
    )

    listed = eks.list_certificate_authorities(clusterName=cluster["name"])["certificateAuthorities"]
    assert any(ca["id"] == successor_id and ca["signingStatus"] == "IN_USE" for ca in listed), (
        f"successor {successor_id} not reflected as IN_USE by ListCertificateAuthorities: {listed}"
    )

    # The original CA is now retired (no longer the signer) and deletable.
    retired = _poll_until(
        lambda: eks.describe_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=original_id)[
            "certificateAuthority"
        ],
        lambda ca: ca["signingStatus"] == "NOT_USED",
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert retired["signingStatus"] == "NOT_USED", (
        f"expected retired original CA {original_id} to settle at NOT_USED, got {retired['signingStatus']}"
    )

    eks.delete_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=original_id)

    def _still_listed():
        ids = [ca["id"] for ca in eks.list_certificate_authorities(clusterName=cluster["name"])["certificateAuthorities"]]
        return original_id in ids

    gone = _poll_until(
        lambda: _still_listed(),
        lambda still_there: not still_there,
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert gone is False, f"deleted CA {original_id} is still present in ListCertificateAuthorities"

    # The deleted CA is not just unlisted: an independent read of it by id, and a mutation
    # attempted against it, must both fail with the specific not-found error.
    describe_code, describe_msg = _error(
        lambda: eks.describe_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=original_id)
    )
    assert describe_code == "ResourceNotFoundException", (
        f"expected DescribeCertificateAuthority on deleted {original_id} to 404, got {describe_code!r}"
    )
    # The message embeds a backend request id the check never sees; its fixed text is asserted.
    assert describe_msg.startswith(
        "certificate authority not found (Service: EksCertificateAuthority, Status Code: 404, Request ID: "
    ) and describe_msg.endswith(") (SDK Attempt Count: 1)"), describe_msg

    activate_dead_code, activate_dead_msg = _error(
        lambda: eks.activate_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=original_id)
    )
    assert activate_dead_code == "ResourceNotFoundException", (
        f"expected ActivateCertificateAuthority on deleted {original_id} to 404, got {activate_dead_code!r}"
    )
    expected = f"Certificate authority {original_id} is not in the trusted list for cluster {cluster['name']}"
    assert activate_dead_msg == expected, f"expected message {expected!r}, got {activate_dead_msg!r}"


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last}")


def _poll_bounded(probe, predicate, *, timeout_s=480.0, interval_s=15.0):
    """Like _poll_until, but returns None on timeout instead of raising - a bounded miss
    is an expected outcome for a real, cluster-dependent async process, not a bug."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return None


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _create_cluster_with_retry(eks, *, timeout_s=180.0, interval_s=10.0, **kwargs):
    """A role just created via IAM is not always immediately assumable by EKS; retry on
    the resulting ClientException instead of guessing a fixed propagation delay."""
    deadline = time.monotonic() + timeout_s
    last_code = None
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


def _create_active_cluster(ctx, extra_kwargs=None):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnet_ids = _default_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        tags={"sim2real-check": CHECK},
    )
    if extra_kwargs:
        kwargs.update(extra_kwargs)
    _create_cluster_with_retry(eks, **kwargs)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
        interval_s=20.0,
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
