"""child-apis-unknown-cluster-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _unused_role_arn(ctx, label):
    """A well-formed IAM role ARN in this account that does not exist."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-behav-' + label)}"


def _trust(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
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


def _retry_role_propagation(fn, timeout_s=90, interval_s=10):
    """IAM is eventually consistent: retry the dependent call while EKS reports the just-created
    role (named in the message) as unresolvable, up to a deadline, instead of a fixed delay."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            msg = err.get("Message", "").lower()
            transient = "role" in msg or "principal" in msg
            if err["Code"] != "InvalidParameterException" or not transient or time.time() >= deadline:
                raise
            time.sleep(interval_s)


def _subnet_ids(ctx):
    """Two subnets in distinct EKS-supported AZs of one VPC, preferring the shared network.
    Falls back to any VPC (an account may have no default VPC); EKS rejects mixed-VPC subnets."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_vpc: dict[str, dict[str, str]] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = sn["AvailabilityZone"]
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_vpc.setdefault(sn["VpcId"], {}).setdefault(az, sn["SubnetId"])
    by_az = max(by_vpc.values(), key=len, default={})
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs in one VPC, found {len(by_az)}")
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
    _retry_role_propagation(
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
        )
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


CHECK = "child-apis-unknown-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['eks']

_CHILD_NOT_FOUND = "The requested resource does not exist."
_LIST_OPS = (
    "ListNodegroups",
    "ListAddons",
    "ListFargateProfiles",
    "ListAccessEntries",
    "ListPodIdentityAssociations",
    "ListUpdates",
    "ListIdentityProviderConfigs",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Child-resource APIs (nodegroups, addons, fargate, access, pod identity, updates) answer a
    missing parent cluster with ResourceNotFoundException; on a real ACTIVE cluster every List*
    succeeds and each Describe* of a never-created child raises ResourceNotFoundException."""
    c = ctx.client("eks")
    real_cluster = _active_cluster(ctx, c, "eks-cap-")
    bogus = ctx.unique_name("sim2real-behav-eks-ghost-")
    principal = _unused_role_arn(ctx, "ghost-principal-")

    def calls_for(cluster):
        return {
            "ListNodegroups": lambda: c.list_nodegroups(clusterName=cluster),
            "DescribeNodegroup": lambda: c.describe_nodegroup(
                clusterName=cluster, nodegroupName="ng"
            ),
            "ListAddons": lambda: c.list_addons(clusterName=cluster),
            "DescribeAddon": lambda: c.describe_addon(
                clusterName=cluster, addonName="vpc-cni"
            ),
            "ListFargateProfiles": lambda: c.list_fargate_profiles(clusterName=cluster),
            "DescribeFargateProfile": lambda: c.describe_fargate_profile(
                clusterName=cluster, fargateProfileName="fp"
            ),
            "ListAccessEntries": lambda: c.list_access_entries(clusterName=cluster),
            "DescribeAccessEntry": lambda: c.describe_access_entry(
                clusterName=cluster, principalArn=principal
            ),
            "ListPodIdentityAssociations": lambda: c.list_pod_identity_associations(
                clusterName=cluster
            ),
            "ListUpdates": lambda: c.list_updates(name=cluster),
            "ListIdentityProviderConfigs": lambda: c.list_identity_provider_configs(
                clusterName=cluster
            ),
        }

    # Positive control: every List* op succeeds against the real cluster, so their
    # uniform rejection below cannot be explained by a target that rejects these
    # operations unconditionally regardless of clusterName.
    real_calls = calls_for(real_cluster)
    for op in _LIST_OPS:
        real_calls[op]()

    # Every Describe* op still surfaces ResourceNotFoundException against the SAME real
    # cluster for a child that was never created there - the cluster half of the lookup
    # cannot be responsible, since it undeniably exists. Real AWS replies with the
    # generic child-not-found message, which names neither the child nor the cluster.
    describe_ops = [op for op in real_calls if op not in _LIST_OPS]
    for op in describe_ops:
        code, message = _expect_error(real_calls[op])
        assert code == "ResourceNotFoundException", f"{op} on the real cluster -> {code}"
        assert message == _CHILD_NOT_FOUND, f"{op} on the real cluster -> {message!r}"

    bogus_calls = calls_for(bogus)
    # On the missing cluster, a List* op names the cluster; a Describe* op answers with
    # the same generic child-not-found message it gives on a real cluster.
    cluster_not_found = f"No cluster found for name: {bogus}."
    for op, fn in bogus_calls.items():
        code, message = _expect_error(fn)
        assert code == "ResourceNotFoundException", f"{op} -> {code}"
        expected = cluster_not_found if op in _LIST_OPS else _CHILD_NOT_FOUND
        assert message == expected, f"{op} -> {message!r}, expected {expected!r}"



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.
    DeleteCluster is refused while an update, node group or add-on operation runs; that is retried.
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
