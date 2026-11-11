"""capability-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capability-full-lifecycle"
GROUP = 'data-plane'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _error(fn):
    """Call fn, require it raises ClientError, return its (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


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


def _capability_role(ctx):
    """A fresh role trusted by the EKS capabilities service principal, as CreateCapability
    requires (empirically sts:AssumeRole + sts:TagSession)."""
    iam = ctx.client("iam")
    name = ctx.unique_name(PREFIX + "cap-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust("capabilities.eks.amazonaws.com", ["sts:TagSession"]),
        Description="SimParityProbe EKS behavioral fidelity fixture",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


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
    # A brand-new role's trust policy is not always immediately visible to EKS (IAM is eventually
    # consistent): retry that signature every 2 s up to 120 s, capped by the run's remaining time.
    retry_deadline = time.monotonic() + 120.0
    left = ctx.time_left()
    if left is not None:
        retry_deadline = min(retry_deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
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
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidParameterException", "ClientException"):
                raise
            if time.monotonic() >= retry_deadline:
                raise AssertionError(f"create_cluster {name} never accepted the role's trust policy: {exc}") from exc
        time.sleep(2)
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

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a fresh cluster ListCapabilities is empty and Describe/Delete/Update of a never-created
    capability, and Create against an absent cluster, fail ResourceNotFoundException."""
    c = ctx.client("eks")
    if not hasattr(c, "list_capabilities"):
        raise AssertionError("botocore in this environment exposes no eks.list_capabilities")
    cluster = _active_cluster(ctx, c, "eks-cap-")
    try:
        listed = c.list_capabilities(clusterName=cluster)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(f"eks:ListCapabilities not usable in this account/region ({code})") from exc
    assert isinstance(listed["capabilities"], list), f"expected a list, got {listed!r}"
    assert listed["capabilities"] == [], f"expected an empty namespace on a fresh cluster, got {listed}"

    absent = ctx.unique_name("cap-")
    describe_code = _error(lambda: c.describe_capability(clusterName=cluster, capabilityName=absent))
    assert describe_code == ("ResourceNotFoundException", "The requested resource does not exist."), (
        f"DescribeCapability on a never-created name must be ResourceNotFoundException, got {describe_code}"
    )
    delete_code = _error(lambda: c.delete_capability(clusterName=cluster, capabilityName=absent))
    assert delete_code == ("ResourceNotFoundException", "The requested resource does not exist."), (
        f"DeleteCapability on a never-created name must be ResourceNotFoundException, got {delete_code}"
    )
    update_code = _error(lambda: c.update_capability(clusterName=cluster, capabilityName=absent))
    assert update_code == ("ResourceNotFoundException", "The requested resource does not exist."), (
        f"UpdateCapability on a never-created name must be ResourceNotFoundException, got {update_code}"
    )

    # Isolate the single broken input under test -- an absent *cluster* -- by giving
    # CreateCapability an otherwise-valid request (a real capabilities-trusted role, a
    # correctly-cased `type`) so a rejection cannot come from some other defect
    # in the request instead of the missing cluster.
    cap_role = _capability_role(ctx)
    absent_cluster = ctx.unique_name("absent-clu-")
    create_code = _error(
        lambda: c.create_capability(
            capabilityName=absent,
            clusterName=absent_cluster,
            type="ARGOCD",
            roleArn=cap_role,
            deletePropagationPolicy="RETAIN",
        )
    )
    assert create_code == ("ResourceNotFoundException", f"No cluster found for name: {absent_cluster}."), (
        f"CreateCapability against a cluster that does not exist must be ResourceNotFoundException "
        f"given an otherwise well-formed request, got {create_code}"
    )
    assert c.list_capabilities(clusterName=cluster)["capabilities"] == [], (
        "the cluster's capability namespace must still be empty after every rejected call"
    )



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
