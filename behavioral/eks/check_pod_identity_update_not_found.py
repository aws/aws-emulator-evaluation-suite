"""pod-identity-update-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-update-not-found"
GROUP = 'error-semantics'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _trust(service: str, extra_actions: tuple[str, ...] = ()) -> str:
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
    """Create-or-reuse an IAM role and return its ARN. Real backing infrastructure
    provisioned against the target account (support services always hit real AWS on a
    real-EKS run)."""
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

def _create_pod_identity_role(ctx):
    """Create a unique, per-run pod-identity role (trusts pods.eks.amazonaws.com; needs
    sts:TagSession alongside sts:AssumeRole), register its teardown, and return its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-eks-pia-role-")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust("pods.eks.amazonaws.com", ("sts:TagSession",)),
            Description="SimParityProbe EKS behavioral fidelity fixture",
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"probe identity cannot create IAM role {name}: {exc}") from exc
        raise
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn

def _retry_while_role_propagates(fn, timeout_s=90, interval_s=5):
    """IAM role trust is eventually consistent: EKS rejects a brand-new role's ARN with
    InvalidParameterException until the role is visible to its own AssumeRole check. Retry
    the specific call that consumes the role, bounded, instead of guessing a sleep."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.time() >= deadline:
                raise
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

def _client_error(fn):
    """Call fn, require that it raises ClientError, return (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Update, Describe and DeletePodIdentityAssociation on an id EKS issued and then deleted answer
    ResourceNotFoundException "No service account role association found for ID: <id>", and the id is no
    longer listed: a well-formed id, so the 404 is not format validation."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-eks-pia-")
    role_arn = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    subnet_ids = _subnet_ids(ctx)
    _retry_while_role_propagates(lambda: c.create_cluster(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={
            "subnetIds": subnet_ids,
            "endpointPublicAccess": True,
            "endpointPrivateAccess": False,
        },
        accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
    ))
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))
    _wait_for(
        lambda: c.describe_cluster(name=name),
        lambda r: r["cluster"]["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1500,
        interval_s=20,
        desc=f"cluster {name} status==ACTIVE",
    )
    status = c.describe_cluster(name=name)["cluster"]["status"]
    assert status == "ACTIVE", f"cluster {name} reached {status}, not ACTIVE"

    pia_role = _create_pod_identity_role(ctx)
    created = _retry_while_role_propagates(lambda: c.create_pod_identity_association(
        clusterName=name,
        namespace="sim2real-behav-ns",
        serviceAccount=ctx.unique_name("sim2real-behav-sa-"),
        roleArn=pia_role,
    ))["association"]
    retired_id = created["associationId"]
    c.delete_pod_identity_association(clusterName=name, associationId=retired_id)

    errors = {
        "update": _client_error(
            lambda: c.update_pod_identity_association(
                clusterName=name, associationId=retired_id, roleArn=pia_role
            )
        ),
        "describe": _client_error(
            lambda: c.describe_pod_identity_association(
                clusterName=name, associationId=retired_id
            )
        ),
        "delete": _client_error(
            lambda: c.delete_pod_identity_association(
                clusterName=name, associationId=retired_id
            )
        ),
    }
    codes = {op: code for op, (code, _message) in errors.items()}
    assert set(codes.values()) == {"ResourceNotFoundException"}, codes
    not_found = f"No service account role association found for ID: {retired_id}"
    messages = {op: message for op, (_code, message) in errors.items()}
    assert messages == {op: not_found for op in errors}, messages
    remaining = c.list_pod_identity_associations(clusterName=name)["associations"]
    assert not any(a["associationId"] == retired_id for a in remaining), remaining


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
