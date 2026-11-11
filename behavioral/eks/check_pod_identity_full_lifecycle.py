"""pod-identity-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-full-lifecycle"
GROUP = 'data-plane'
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


def _delete_association_if_present(c, cluster, assoc_id):
    """Teardown: delete the association unless run() already deleted it."""
    try:
        c.delete_pod_identity_association(clusterName=cluster, associationId=assoc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _retry_while_propagating(fn, timeout_s=90, interval_s=5, desc=""):
    """Retry fn() while a just-created IAM role is still propagating; raise after timeout_s."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if time.time() >= deadline:
                raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}: {exc}") from exc
            time.sleep(interval_s)


def _principal_role(ctx, label="eks-principal-"):
    """A fresh, IAM-propagated throwaway principal EKS will accept."""
    return _ensure_role(ctx, ctx.unique_name(PREFIX + label), "ec2.amazonaws.com")


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
    subnet_ids = _subnet_ids(ctx)

    def _create():
        try:
            c.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": subnet_ids,
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                accessConfig={
                    "authenticationMode": "API_AND_CONFIG_MAP",
                    "bootstrapClusterCreatorAdminPermissions": True,
                },
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException":
                raise

    _retry_while_propagating(_create, desc=f"cluster role {role_arn} to propagate for CreateCluster")
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
    """A pods.eks trust-policy role EKS pod identity will accept."""
    name = ctx.unique_name(PREFIX + label)
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust("pods.eks.amazonaws.com", ("sts:TagSession",)),
            Description="SimParityProbe EKS behavioral fidelity fixture",
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"probe identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pod identity association is created, described and listed with its role, namespace and service account,
    and updated to a second role; once deleted, Describe and Update fail with ResourceNotFoundException "No
    service account role association found for ID: <id>" and it is no longer listed."""
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-pi-")
    role_one = _pods_role(ctx)
    role_two = _pods_role(ctx)
    namespace = "sim2real-pi-ns"
    service_account = ctx.unique_name("sa-")

    created = _retry_while_propagating(
        lambda: c.create_pod_identity_association(
            clusterName=cluster,
            namespace=namespace,
            serviceAccount=service_account,
            roleArn=role_one,
            tags={"sim2real": "1"},
        )["association"],
        desc=f"pod identity role {role_one} to propagate for CreatePodIdentityAssociation",
    )
    assoc_id = created["associationId"]
    ctx.on_cleanup(lambda: _delete_association_if_present(c, cluster, assoc_id))
    assert created["roleArn"] == role_one, created
    assert created["namespace"] == namespace, created
    assert created["serviceAccount"] == service_account, created
    assert created["associationArn"], created
    assert created["clusterName"] == cluster, created

    described = c.describe_pod_identity_association(clusterName=cluster, associationId=assoc_id)["association"]
    assert described["associationId"] == assoc_id, described
    assert described["roleArn"] == role_one, described

    listed = c.list_pod_identity_associations(clusterName=cluster)["associations"]
    assert assoc_id in [a["associationId"] for a in listed], listed

    _retry_while_propagating(
        lambda: c.update_pod_identity_association(clusterName=cluster, associationId=assoc_id, roleArn=role_two),
        desc=f"pod identity role {role_two} to propagate for UpdatePodIdentityAssociation",
    )
    updated = c.describe_pod_identity_association(clusterName=cluster, associationId=assoc_id)["association"]
    assert updated["roleArn"] == role_two, updated
    assert updated["associationId"] == assoc_id, updated
    assert updated["namespace"] == namespace, updated
    assert updated["serviceAccount"] == service_account, updated

    c.delete_pod_identity_association(clusterName=cluster, associationId=assoc_id)
    describe_code_after_delete, describe_message_after_delete = _client_error(
        lambda: c.describe_pod_identity_association(clusterName=cluster, associationId=assoc_id)
    )
    assert describe_code_after_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing a deleted association, got {describe_code_after_delete!r}"
    )
    not_found = f"No service account role association found for ID: {assoc_id}"
    assert describe_message_after_delete == not_found, describe_message_after_delete
    update_code_after_delete, update_message_after_delete = _client_error(
        lambda: c.update_pod_identity_association(clusterName=cluster, associationId=assoc_id, roleArn=role_one)
    )
    assert update_code_after_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted association, got {update_code_after_delete!r}"
    )
    assert update_message_after_delete == not_found, update_message_after_delete
    after = c.list_pod_identity_associations(clusterName=cluster)["associations"]
    assert assoc_id not in [a["associationId"] for a in after], after


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
