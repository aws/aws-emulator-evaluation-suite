"""delete-certificate-authority-in-use-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-certificate-authority-in-use-blocked"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCertificateAuthority on the cluster's current active signer (signingStatus
    IN_USE) is blocked with ResourceInUseException and the CA remains attached, while
    deleting a not-yet-activated successor CA on the same cluster succeeds."""
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _get_subnets(ctx)
    cluster_name, _cluster = _create_active_cluster(ctx, role_arn, subnet_ids)

    cas = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    in_use = [c for c in cas if c["signingStatus"] == "IN_USE"]
    assert len(in_use) == 1, f"expected exactly one IN_USE CA on a fresh cluster, got {in_use}"
    active_ca_id = in_use[0]["id"]

    code, message = _error(lambda: eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=active_ca_id))
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    assert message == "Cannot delete the active certificate authority. Activate a different CA first.", message

    # effect absent: the active CA is still present and still IN_USE
    still_there = [c for c in eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"] if c["id"] == active_ca_id]
    assert len(still_there) == 1, f"expected the blocked CA {active_ca_id} to remain listed, got {still_there}"
    assert still_there[0]["signingStatus"] == "IN_USE", f"expected signingStatus IN_USE, got {still_there[0]['signingStatus']!r}"

    # positive control: a freshly appended, not-yet-activated successor CA can be deleted.
    # Wait for the cluster's create-CA update to settle first: while it's InProgress the
    # cluster is busy and a second CertificateAuthorityUpdate (the delete) is rejected too.
    successor = eks.create_certificate_authority(clusterName=cluster_name)
    successor_id = successor["certificateAuthority"]["id"]
    successor_update_id = successor["update"]["id"]
    assert successor["certificateAuthority"]["signingStatus"] == "NOT_USED", (
        f"expected a freshly appended successor CA to start NOT_USED, "
        f"got {successor['certificateAuthority']['signingStatus']!r}"
    )

    # A CertificateAuthorityUpdate can run well past 10 minutes on AWS.
    _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=successor_update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed"),
        timeout_s=_ca_update_deadline(ctx),
        interval_s=2,
    )

    delete_resp = eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    delete_update_id = delete_resp["update"]["id"]

    delete_update = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=delete_update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed"),
        timeout_s=_ca_update_deadline(ctx),
        interval_s=2,
    )
    assert delete_update["status"] == "Successful", f"expected the successor deletion to succeed, got {delete_update}"

    remaining_ids = _poll_until(
        lambda: {c["id"] for c in eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]},
        lambda ids: successor_id not in ids,
        timeout_s=120,
        interval_s=5,
    )
    assert successor_id not in remaining_ids, f"expected {successor_id} gone from the list, still present in {remaining_ids}"

    # deletes prove gone and unusable: a second, independent read by id gives the specific
    # not-found code, not just an absence from the collection.
    # message varies: the text embeds a per-request Request ID and SDK attempt count
    gone_code, _gone_message = _error(
        lambda: eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    )
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException for deleted CA {successor_id}, got {gone_code}"


_EKS_CLUSTER_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_EKS_CLUSTER_TRUST),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _get_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    assert len(subnet_ids) >= 2, f"need >=2 AZ-distinct subnets in vpc {vpc_id}, found {subnet_ids}"
    return subnet_ids[:3]


def _ca_update_deadline(ctx) -> float:
    left = ctx.time_left()
    return 1800.0 if left is None else max(0.0, min(1800.0, left - 60.0))


def _poll_until(probe, predicate, timeout_s, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _create_active_cluster(ctx, role_arn: str, subnet_ids: list[str]):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-cl-")
    # A fresh role is refused with InvalidParameterException until IAM propagates it.
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real-managed": "true"},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200,
        interval_s=20,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster}")
    return name, cluster



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
