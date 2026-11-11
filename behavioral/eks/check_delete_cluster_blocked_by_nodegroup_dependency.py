"""delete-cluster-blocked-by-nodegroup-dependency."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
NODE_ROLE = PREFIX + "eks-node-role"
FARGATE_ROLE = PREFIX + "eks-fargate-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_NODE_POLICIES = (
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
)
_FARGATE_POLICY = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
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
    """Create-or-reuse an IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="SimParityProbe EKS behavioral fidelity fixture",
            Tags=[{"Key": "sim2real", "Value": "1"}],
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

def _call_with_iam_propagation_retry(fn, desc, timeout_s=90, interval_s=6):
    """Retry fn while it fails: a just-created IAM role's trust policy can take a
    few seconds to propagate to EKS's own AssumeRole check. Bounded, not a sleep."""
    deadline = time.time() + timeout_s
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"{desc} kept failing (likely IAM propagation lag): {last_exc}")

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

def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")

_FARGATE_REJECTION_CODES = {"InvalidParameterException", "InvalidRequestException", "ClientException"}
# EKS's refusal of a pod execution role whose trust IAM has not yet propagated.
_FARGATE_ROLE_PROPAGATING = (
    "Misconfigured PodExecutionRole Trust Policy; Please add the eks-fargate-pods.amazonaws.com Service Principal"
)

def _fargate_profile_rejection_code(ctx, cluster, fp, role_arn, timeout_s=90, interval_s=6):
    """Attempt CreateFargateProfile; return the rejection code, or None if it
    unexpectedly succeeded. Retries only while IAM propagation lag on the
    freshly created pod execution role produces a code outside the expected
    set or the role-propagation refusal — never retries away an actual acceptance."""
    c = ctx.client("eks")
    deadline = time.time() + timeout_s
    while True:
        try:
            c.create_fargate_profile(
                fargateProfileName=fp,
                clusterName=cluster,
                podExecutionRoleArn=role_arn,
                subnets=_subnet_ids(ctx),
                selectors=[{"namespace": "default"}],
                tags={"sim2real": "1"},
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
        else:
            return None
        propagating = code == "InvalidParameterException" and message == _FARGATE_ROLE_PROPAGATING
        if code in _FARGATE_REJECTION_CODES and not propagating:
            return code
        if time.time() >= deadline:
            if propagating:
                raise AssertionError(f"pod execution role {role_arn} still refused as propagating after {timeout_s}s")
            return code
        time.sleep(interval_s)

def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "GONE"
        raise

def _cluster_params(ctx, name, version=None):
    params = dict(
        name=name,
        roleArn=_ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY]),
        resourcesVpcConfig={
            "subnetIds": _subnet_ids(ctx),
            "endpointPublicAccess": True,
            "endpointPrivateAccess": False,
        },
        accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
        tags={"sim2real": "1"},
    )
    if version:
        params["version"] = version
    return params

def _provision_cluster(ctx, version=None):
    """Create a cluster owned solely by this check and wait for ACTIVE."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-eks-cl-")
    _call_with_iam_propagation_retry(
        lambda: c.create_cluster(**_cluster_params(ctx, name, version=version)),
        desc=f"create_cluster {name}",
    )
    ctx.on_cleanup(lambda: _gone_ok(lambda: c.delete_cluster(name=name)))
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=1500,
        interval_s=20,
        desc=f"cluster {name} status==ACTIVE",
    )
    status = _cluster_status(c, name)
    assert status == "ACTIVE", f"cluster {name} reached {status}, expected ACTIVE"
    return name

def _nodegroup_params(ctx, cluster, name):
    """Kwargs for a valid zero-capacity CreateNodegroup call (no EC2 instances)."""
    return {
        "clusterName": cluster,
        "nodegroupName": name,
        "subnets": _subnet_ids(ctx),
        "nodeRole": _ensure_role(ctx, NODE_ROLE, "ec2.amazonaws.com", _NODE_POLICIES),
        "scalingConfig": {"minSize": 0, "maxSize": 1, "desiredSize": 0},
        "instanceTypes": ["t3.medium"],
        "amiType": "AL2023_x86_64_STANDARD",
        "capacityType": "ON_DEMAND",
        "diskSize": 20,
        "tags": {"sim2real": "1"},
    }

def _nodegroup_status(c, cluster, ng):
    try:
        return c.describe_nodegroup(clusterName=cluster, nodegroupName=ng)["nodegroup"]["status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "GONE"
        raise

def _wait_nodegroup_status(c, cluster, ng, targets, timeout_s=600, interval_s=15):
    return _wait_for(
        lambda: _nodegroup_status(c, cluster, ng),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        desc=f"nodegroup {ng} status in {sorted(targets)}",
    )

def _register_nodegroup_cleanup(ctx, c, cluster, ng):
    """Delete the node group and wait (bounded) for it to disappear so the
    cluster's own cleanup (registered earlier, hence run after this one) is not
    refused with ResourceInUseException."""
    def _cleanup():
        try:
            c.delete_nodegroup(clusterName=cluster, nodegroupName=ng)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            _wait_for(
                lambda: _nodegroup_status(c, cluster, ng),
                lambda s: s == "GONE",
                timeout_s=600,
                interval_s=15,
                desc=f"nodegroup {ng} gone",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

CHECK = "delete-cluster-blocked-by-nodegroup-dependency"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster with a nodegroup attached fails with ResourceInUseException "Cluster has nodegroups
    attached" and the cluster stays ACTIVE, a Fargate profile on public subnets is refused, and once the
    nodegroup is gone DeleteCluster is accepted and the cluster reads DELETING.
    """
    c = ctx.client("eks")
    cluster = _provision_cluster(ctx)
    ng = ctx.unique_name("sim2real-behav-ng-dep-")[:63]
    _call_with_iam_propagation_retry(
        lambda: c.create_nodegroup(**_nodegroup_params(ctx, cluster, ng)),
        desc=f"create_nodegroup {ng}",
    )
    _register_nodegroup_cleanup(ctx, c, cluster, ng)
    listed = c.list_nodegroups(clusterName=cluster)["nodegroups"]
    assert ng in listed, f"nodegroup {ng} missing from ListNodegroups, got {listed}"

    code, message = _error(lambda: c.delete_cluster(name=cluster))
    assert code == "ResourceInUseException", (
        f"DeleteCluster with a dependent node group must be "
        f"ResourceInUseException, got {code}"
    )
    assert message == "Cluster has nodegroups attached", f"unexpected DeleteCluster message {message!r}"
    status = c.describe_cluster(name=cluster)["cluster"]["status"]
    assert status == "ACTIVE", f"a rejected DeleteCluster must not start deletion; status={status}"

    # A Fargate profile is the other dependent class. EKS requires private subnets
    # for Fargate, so creating one on the cluster's public subnets must be refused.
    fp = ctx.unique_name("sim2real-behav-fp-")[:63]
    fargate_role_arn = _ensure_role(
        ctx, FARGATE_ROLE, "eks-fargate-pods.amazonaws.com", [_FARGATE_POLICY]
    )
    fp_code = _fargate_profile_rejection_code(ctx, cluster, fp, fargate_role_arn)
    assert fp_code is not None, (
        "CreateFargateProfile on public subnets must be rejected (Fargate requires "
        "private subnets), but it was accepted"
    )
    assert fp_code in _FARGATE_REJECTION_CODES, (
        f"unexpected CreateFargateProfile rejection code {fp_code}"
    )
    assert c.list_fargate_profiles(clusterName=cluster)["fargateProfileNames"] == [], (
        "a rejected CreateFargateProfile must not leave a profile behind"
    )

    # dependency removed -> DeleteCluster is accepted
    c.delete_nodegroup(clusterName=cluster, nodegroupName=ng)
    _wait_nodegroup_status(c, cluster, ng, {"GONE"}, timeout_s=600, interval_s=15)
    deleted = c.delete_cluster(name=cluster)["cluster"]
    assert deleted["status"] == "DELETING", f"expected DELETING, got {deleted['status']}"

    # Independent read at the destination, not the mutating call's own response.
    final_status = c.describe_cluster(name=cluster)["cluster"]["status"]
    assert final_status == "DELETING", (
        f"an independent DescribeCluster read must also show DELETING right after "
        f"DeleteCluster was accepted, got {final_status}"
    )


def _gone_ok(fn):
    """Run a teardown call; a resource the check already deleted in band is done, not a leak."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
