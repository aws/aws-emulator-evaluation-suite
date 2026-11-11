"""certificate-authority-activate-before-distribution-complete-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "certificate-authority-activate-before-distribution-complete-rejected"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ActivateCertificateAuthority on a successor CA whose distribution is not COMPLETE fails with
    ResourceInUseException and its exact message and the CA stays NOT_USED with no activatedAt; once the
    update settles the CA can be deleted and a re-delete fails with ResourceNotFoundException.
    """
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    create_resp = eks.create_certificate_authority(clusterName=cluster["name"])
    ca_id = create_resp["certificateAuthority"]["id"]
    append_update_id = create_resp["update"]["id"]

    def _cleanup_ca():
        try:
            eks.delete_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=ca_id)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_ca)
    # A freshly appended successor CA always starts as NOT_USED with distribution pending.
    assert create_resp["certificateAuthority"]["signingStatus"] == "NOT_USED"

    described_before = eks.describe_certificate_authority(
        clusterName=cluster["name"], certificateAuthorityId=ca_id
    )["certificateAuthority"]
    if described_before["distributionStatus"] == "COMPLETE":
        raise AssertionError(
            "successor CA distributed to the trust bundle faster than this check could "
            "race it -- ActivateCertificateAuthority's pre-COMPLETE rejection could not be "
            "triggered deterministically this run"
        )

    def _activate_too_early():
        eks.activate_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=ca_id)

    try:
        _activate_too_early()
    except ClientError as err:
        code, message = err.response["Error"]["Code"], err.response["Error"].get("Message")
    else:
        raise AssertionError(
            "successor CA finished distributing before the too-early activation attempt "
            "could reach the server -- ActivateCertificateAuthority's pre-COMPLETE "
            "rejection could not be triggered deterministically this run"
        )
    # ResourceInUseException, not InvalidParameterException: the cluster is busy with the
    # in-progress append+distribute update.
    assert code == "ResourceInUseException", f"unexpected error code: {code!r}"
    expected = (
        f"Cannot CertificateAuthorityUpdate because cluster {cluster['name']} currently has "
        f"update {append_update_id} in progress"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect must be absent: signingStatus is still NOT_USED, nothing was activated.
    described_after = eks.describe_certificate_authority(
        clusterName=cluster["name"], certificateAuthorityId=ca_id
    )["certificateAuthority"]
    assert described_after["signingStatus"] == "NOT_USED"
    assert "activatedAt" not in described_after, "successor recorded an activation timestamp despite the rejected activation"

    # Positive control: once the append update itself settles, the still-unactivated
    # successor deletes cleanly and is independently confirmed gone -- so the earlier
    # rejection was about activation timing, not a frozen CA record.
    _wait_update_terminal(eks, cluster["name"], append_update_id, timeout_s=600.0)
    delete_resp = eks.delete_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=ca_id)
    delete_update_id = delete_resp["update"]["id"]
    _wait_ca_gone(eks, cluster["name"], ca_id, timeout_s=600.0)
    # The delete is itself an async update; a mutation racing that update's own settling
    # reads as ResourceInUseException rather than not-found,
    # so wait for it to reach a terminal status before demanding the specific not-found code.
    _wait_update_terminal(eks, cluster["name"], delete_update_id, timeout_s=600.0)
    redelete_code, redelete_msg = _error(
        lambda: eks.delete_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=ca_id)
    )
    assert redelete_code == "ResourceNotFoundException", f"unexpected error code on re-delete: {redelete_code!r}"
    expected = f"Certificate authority {ca_id} not found for cluster {cluster['name']}"
    assert redelete_msg == expected, f"expected re-delete message {expected!r}, got {redelete_msg!r}"


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _wait_update_terminal(eks, cluster_name, update_id, timeout_s=600.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"]
        if last in ("Successful", "Failed", "Cancelled"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} on {cluster_name} did not reach a terminal status within {timeout_s}s (last={last!r})")


def _wait_ca_gone(eks, cluster_name, ca_id, timeout_s=600.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"certificate authority {ca_id} was not deleted within {timeout_s}s")


def _get_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision an EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in at least two availability zones required by EKS")
    return list(by_az.values())[:2]


def _create_cluster_role(ctx):
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


def _poll_until(probe, predicate, timeout_s=1200.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _wait_cluster_status(ctx, name, statuses, timeout_s=1200.0, interval_s=15.0):
    eks = ctx.client("eks")
    return _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnets = _get_two_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnets})

    def _cleanup():
        try:
            _wait_cluster_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 900.0
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            time.sleep(15.0)

    ctx.on_cleanup(_cleanup)
    desc = _wait_cluster_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
    if desc["status"] != "ACTIVE":
        raise AssertionError(f"cluster {name} entered status {desc['status']} instead of ACTIVE")
    return {"name": name, "arn": desc["arn"], "role_arn": role_arn, "subnets": subnets}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
