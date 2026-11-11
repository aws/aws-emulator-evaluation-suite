"""certificate-authority-full-state-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "certificate-authority-full-state-transitions"
GROUP = "state-machine"
SERVICES = ["eks"]

_CLUSTER_WAIT_TIMEOUT_S = 20 * 60
_CLUSTER_POLL_INTERVAL_S = 2
_CA_WAIT_TIMEOUT_S = 40 * 60
_CA_POLL_INTERVAL_S = 20


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created successor CA is NOT_USED and can't be activated before distribution completes.
    The IN_USE CA can't be deleted, but the never-activated successor can; the check uses these
    fast preconditions because full rotation outlasts a bounded test window."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    originals = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    signing = [ca for ca in originals if ca["signingStatus"] == "IN_USE"]
    assert len(signing) == 1, f"expected exactly one signing CA on a fresh cluster, got {signing}"
    original_id = signing[0]["id"]

    baseline_update_ids = set(eks.list_updates(name=cluster_name)["updateIds"])
    created = eks.create_certificate_authority(clusterName=cluster_name)["certificateAuthority"]
    successor_id = created["id"]
    assert created["signingStatus"] == "NOT_USED", created

    described = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=successor_id
    )["certificateAuthority"]
    assert described["signingStatus"] == "NOT_USED", described
    assert described["distributionStatus"] in ("IN_PROGRESS", "PENDING", "COMPLETE"), described

    # A freshly created successor can't be activated yet: CreateCertificateAuthority
    # itself starts a CertificateAuthorityUpdate on the cluster, and any further
    # CertificateAuthorityUpdate-class call is rejected with ResourceInUseException
    # while that update is still settling -- a fast, deterministic rejection that
    # doesn't require waiting out the (often 15-40+ minute) real distribution.
    if described["distributionStatus"] != "COMPLETE":
        try:
            eks.activate_certificate_authority(
                clusterName=cluster_name, certificateAuthorityId=successor_id
            )
        except ClientError:
            pass
        else:
            raise AssertionError("activating a successor before distribution completes must be rejected")

    # The CreateCertificateAuthority update above is also what blocks the delete
    # calls below with the *same* ResourceInUseException, for the *same* in-flight-
    # update reason rather than the signing-status/distribution reason each of those
    # calls actually means to exercise. Wait it out once here so the two negatives
    # below assert what they claim to.
    _wait_for_ca_update_to_settle(ctx, cluster_name, baseline_update_ids)

    code, message = _error(
        lambda: eks.delete_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=original_id
        )
    )
    assert code == "ResourceInUseException", code
    expected = "Cannot delete the active certificate authority. Activate a different CA first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    still_signing = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=original_id
    )["certificateAuthority"]
    assert still_signing["signingStatus"] == "IN_USE", still_signing

    eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)

    def _successor_state():
        try:
            ca = eks.describe_certificate_authority(
                clusterName=cluster_name, certificateAuthorityId=successor_id
            )["certificateAuthority"]
            return ca["distributionStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "REMOVED"
            raise

    final_state = _poll_until(
        _successor_state,
        lambda s: s in ("REMOVED", "DELETING"),
        timeout_s=5 * 60,
        interval_s=15,
    )
    assert final_state in ("REMOVED", "DELETING"), final_state


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _wait_for_ca_update_to_settle(ctx, cluster_name: str, baseline_update_ids: set[str]) -> None:
    eks = ctx.client("eks")

    def _new_update_id():
        ids = set(eks.list_updates(name=cluster_name)["updateIds"])
        new_ids = ids - baseline_update_ids
        return next(iter(new_ids), None)

    update_id = _poll_until(
        _new_update_id,
        lambda uid: uid is not None,
        timeout_s=2 * 60,
        interval_s=5,
    )

    final_status = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"],
        lambda s: s in ("Successful", "Failed", "Cancelled"),
        timeout_s=_CA_WAIT_TIMEOUT_S,
        interval_s=_CA_POLL_INTERVAL_S,
    )
    assert final_status == "Successful", f"certificate authority creation update ended in {final_status}"


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_network(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs][:2]
    assert len(az_names) >= 2, "region needs at least two availability zones"

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _delete_cluster_and_wait(ctx, name: str) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + _CLUSTER_WAIT_TIMEOUT_S
    # DeleteCluster is refused with ResourceInUseException while a cluster update is in progress.
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            in_use = err["Code"] == "ResourceInUseException" and "in progress" in err.get("Message", "")
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(_CLUSTER_POLL_INTERVAL_S)
    raise AssertionError(f"cluster {name} still present {_CLUSTER_WAIT_TIMEOUT_S}s after DeleteCluster")


_NET_NOT_FOUND = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound")


def _retry_delete(fn, timeout_s: float = 120.0) -> None:
    """Delete a subnet/VPC, retrying DependencyViolation every 2 s while the cluster's ENIs are
    released; not-found counts as deleted and every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _NET_NOT_FOUND:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_active_cluster(ctx, version: str | None = None) -> str:
    eks = ctx.client("eks")
    subnet_ids = _create_network(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")

    kwargs = {"name": name, "roleArn": role_arn, "resourcesVpcConfig": {"subnetIds": subnet_ids}}
    if version:
        kwargs["version"] = version

    # A brand-new IAM role is rejected with InvalidParameterException until it propagates.
    deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(**kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)

    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))

    active = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_WAIT_TIMEOUT_S,
        interval_s=_CLUSTER_POLL_INTERVAL_S,
    )
    assert active["status"] == "ACTIVE", f"cluster ended in status {active['status']}"
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
