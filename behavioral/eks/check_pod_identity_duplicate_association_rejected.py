"""pod-identity-duplicate-association-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-duplicate-association-rejected"
GROUP = 'overly-permissive'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _client_error(fn):
    """Call fn, require that it raises ClientError, return (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _trust(service, extra_actions=()):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole", *extra_actions],
                }
            ],
        }
    )


def _ensure_role(ctx, name, service="eks.amazonaws.com", managed_policies=()):
    """Create-or-reuse an IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="SimParityProbe EKS behavioral fidelity fixture",
            Tags=[{"Key": "sim2real-managed", "Value": "true"}],
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"probe identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError:
            pass
    return arn


def _retry_until_success(fn, timeout_s=90, interval_s=5, desc=""):
    """Retry fn() while it raises ClientError -- e.g. while a just-created IAM role has
    not yet propagated to an AWS control plane's own synchronous validation. Raises the
    last ClientError, not a swallowed sentinel, once the deadline passes."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if time.time() >= deadline:
                raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}: {exc}") from exc
            time.sleep(interval_s)


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs of the shared network."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = sn["AvailabilityZone"]
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(az, sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:2]


def _wait_for(fn, pred, timeout_s=300, interval_s=5, desc=""):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)


def _active_cluster(ctx, c, suffix):
    """Provision (create + wait ACTIVE) a throwaway cluster, register cleanup, return its name."""
    role_arn = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + suffix)
    _retry_until_success(
        lambda: c.create_cluster(
            name=name,
            roleArn=role_arn,
            resourcesVpcConfig={
                "subnetIds": _subnet_ids(ctx),
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
            },
            accessConfig={
                "authenticationMode": "API_AND_CONFIG_MAP",
                "bootstrapClusterCreatorAdminPermissions": True,
            },
            tags={"sim2real-managed": "true"},
        ),
        desc=f"cluster role {CLUSTER_ROLE} to propagate to EKS's synchronous validation",
    )
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))
    resp = _wait_for(
        lambda: c.describe_cluster(name=name),
        lambda r: r["cluster"]["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1500,
        interval_s=20,
        desc=f"cluster {name} status==ACTIVE",
    )
    cluster = resp["cluster"]
    assert cluster["status"] == "ACTIVE", f"cluster {name} landed in {cluster['status']!r}"
    return name

def _pods_role(ctx, label="eks-pods-"):
    """A fresh pods.eks trust-policy role EKS pod identity will accept.

    Propagation is not waited out here with a flat sleep: the caller uses
    `_retry_until_success` around the role's first real use instead.
    """
    name = ctx.unique_name(PREFIX + label)
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust("pods.eks.amazonaws.com", ("sts:TagSession",)),
            Description="SimParityProbe EKS behavioral fidelity fixture",
            Tags=[{"Key": "sim2real-managed", "Value": "true"}],
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"probe identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    else:
        ctx.on_cleanup(lambda: _delete_role_if_present(iam, name))
    return arn


def _delete_role_if_present(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_association_if_present(c, cluster, association_id):
    """Idempotent teardown: tolerate an association this check already deleted itself."""
    try:
        c.delete_pod_identity_association(clusterName=cluster, associationId=association_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """One namespace/serviceAccount pair may hold exactly one pod identity association;
    the rejection is that specific uniqueness rule -- not role_two being unusable, and not
    every association being blocked -- and it stops applying once the conflict is gone.
    """
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-pidup-")
    role_one = _pods_role(ctx)
    role_two = _pods_role(ctx)
    namespace = "sim2real-dup-ns"
    service_account = ctx.unique_name("dup-sa-")
    other_service_account = ctx.unique_name("dup-sa-other-")

    # Positive control: role_one, freshly created, is accepted once propagated.
    created = _retry_until_success(
        lambda: c.create_pod_identity_association(
            clusterName=cluster,
            namespace=namespace,
            serviceAccount=service_account,
            roleArn=role_one,
            tags={"sim2real-managed": "true"},
        ),
        desc="role_one to propagate to EKS pod identity's synchronous validation",
    )["association"]
    assoc_id = created["associationId"]
    ctx.on_cleanup(lambda: _delete_association_if_present(c, cluster, assoc_id))

    # Second positive control, on role_two: a *different* serviceAccount in the same
    # namespace succeeds. This both proves role_two has propagated (so the rejection
    # below cannot be confused with role_two being unusable) and proves the mechanism
    # is not blanket-denying every association.
    other = _retry_until_success(
        lambda: c.create_pod_identity_association(
            clusterName=cluster,
            namespace=namespace,
            serviceAccount=other_service_account,
            roleArn=role_two,
            tags={"sim2real-managed": "true"},
        ),
        desc="role_two to propagate to EKS pod identity's synchronous validation",
    )["association"]
    ctx.on_cleanup(lambda: _delete_association_if_present(c, cluster, other["associationId"]))
    assert other["associationId"] != assoc_id, (other["associationId"], assoc_id)

    # Break exactly one thing: reuse the same (namespace, serviceAccount) pair.
    dup_code, dup_message = _client_error(
        lambda: c.create_pod_identity_association(
            clusterName=cluster, namespace=namespace, serviceAccount=service_account, roleArn=role_two
        )
    )
    assert dup_code == "ResourceInUseException", f"expected ResourceInUseException, got {dup_code!r}"
    assert dup_message == f"The service account is already associated with a different IAM role: {role_one}", (
        dup_message
    )
    still = c.describe_pod_identity_association(clusterName=cluster, associationId=assoc_id)["association"]
    assert still["roleArn"] == role_one, f"expected unchanged roleArn {role_one!r}, got {still!r}"

    # Restore: once the conflicting association is gone, the identical call succeeds.
    c.delete_pod_identity_association(clusterName=cluster, associationId=assoc_id)
    restored = _retry_until_success(
        lambda: c.create_pod_identity_association(
            clusterName=cluster,
            namespace=namespace,
            serviceAccount=service_account,
            roleArn=role_two,
            tags={"sim2real-managed": "true"},
        ),
        desc="the freed (namespace, serviceAccount) slot to accept a new association",
    )["association"]
    restored_id = restored["associationId"]
    ctx.on_cleanup(lambda: _delete_association_if_present(c, cluster, restored_id))
    assert restored["roleArn"] == role_two, f"expected restored association to carry role_two, got {restored!r}"

    # Derive an unused id from the real one so it is guaranteed well-formed.
    absent_id = restored_id[:-1] + ("b" if restored_id[-1] != "b" else "c")
    update_code, update_message = _client_error(
        lambda: c.update_pod_identity_association(clusterName=cluster, associationId=absent_id, roleArn=role_two)
    )
    assert update_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {update_code!r}"
    assert update_message == f"No service account role association found for ID: {absent_id}", update_message
    delete_code, delete_message = _client_error(
        lambda: c.delete_pod_identity_association(clusterName=cluster, associationId=absent_id)
    )
    assert delete_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {delete_code!r}"
    assert delete_message == f"No service account role association found for ID: {absent_id}", delete_message
    absent_cluster = ctx.unique_name("absent-clu-")
    list_code, list_message = _client_error(lambda: c.list_pod_identity_associations(clusterName=absent_cluster))
    assert list_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {list_code!r}"
    assert list_message == f"No cluster found for name: {absent_cluster}.", list_message


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
