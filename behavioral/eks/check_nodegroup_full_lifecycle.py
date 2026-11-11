"""nodegroup-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodegroup-full-lifecycle"
GROUP = 'data-plane'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
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


_ROLE_PROPAGATION_TIMEOUT_S = 90


def _call_with_role_propagation_retry(fn, desc):
    """Retry fn on EKS's transient "role not yet visible" rejection.

    EKS validates a roleArn synchronously against IAM, and a role created seconds earlier is not
    always visible yet. IAM exposes no condition to poll, so the bounded retry is at first use of
    the role rather than a fixed sleep after creating it, and exhausting the budget FAILS the check.
    """
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"{desc} never accepted the role (IAM propagation?): {last_exc}")


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
    _call_with_role_propagation_retry(
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
        ),
        f"create_cluster {name}",
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

_NODE_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
]


def _nodegroup_gone(c, cluster, nodegroup):
    """Whether DescribeNodegroup reports the nodegroup not found; any other error raises."""
    try:
        c.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNodegroup CREATING -> ACTIVE -> DELETING -> gone, consistently listed/described."""
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-ng-")
    node_role_name = ctx.unique_name(PREFIX + "eks-node-")
    node_role = _ensure_role(ctx, node_role_name, "ec2.amazonaws.com", _NODE_POLICIES)

    def _cleanup_node_role():
        iam = ctx.client("iam")
        for policy_arn in _NODE_POLICIES:
            try:
                iam.detach_role_policy(RoleName=node_role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=node_role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_node_role)
    subnets = _subnet_ids(ctx)
    nodegroup = ctx.unique_name("ng-")

    created = _call_with_role_propagation_retry(
        lambda: c.create_nodegroup(
            clusterName=cluster,
            nodegroupName=nodegroup,
            subnets=subnets,
            nodeRole=node_role,
            instanceTypes=["t3.small"],
            diskSize=20,
            capacityType="ON_DEMAND",
            scalingConfig={"minSize": 1, "maxSize": 2, "desiredSize": 1},
            labels={"sim2real": "behavioral"},
            tags={"sim2real": "1"},
        )["nodegroup"],
        f"create_nodegroup {nodegroup}",
    )
    ctx.on_cleanup(lambda: _gone_ok(lambda: c.delete_nodegroup(clusterName=cluster, nodegroupName=nodegroup)))
    assert created["status"] == "CREATING", created
    assert created["nodegroupName"] == nodegroup, created
    assert created["clusterName"] == cluster, created
    assert nodegroup in c.list_nodegroups(clusterName=cluster)["nodegroups"]

    # Nodegroup deadlines: a managed nodegroup is an Auto Scaling group of real EC2 instances, so
    # both edges cost EC2 time — create waits for an instance to boot and JOIN the cluster, delete
    # waits for the ASG to be drained and scaled to zero, which can take well over 10 minutes.
    # Both budgets below are deliberately generous, so a slow delete is not scored as a defect.
    active = _wait_for(
        lambda: c.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)["nodegroup"],
        lambda n: n["status"] in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=900, interval_s=15, desc=f"nodegroup {nodegroup} ACTIVE",
    )
    assert active["status"] == "ACTIVE", f"nodegroup landed in {active['status']!r}"
    assert active["scalingConfig"] == {"minSize": 1, "maxSize": 2, "desiredSize": 1}, active["scalingConfig"]
    assert active["labels"]["sim2real"] == "behavioral", active["labels"]
    assert active["nodeRole"] == node_role, active
    assert active["resources"]["autoScalingGroups"], active["resources"]
    assert set(active["subnets"]) == set(subnets), active["subnets"]
    assert active["nodegroupArn"], active

    # An ACTIVE nodegroup owns its name.
    dup_code, dup_msg = _error(
        lambda: c.create_nodegroup(
            clusterName=cluster,
            nodegroupName=nodegroup,
            subnets=subnets,
            nodeRole=node_role,
        )
    )
    assert dup_code == "ResourceInUseException", dup_code
    assert dup_msg == f"NodeGroup already exists with name {nodegroup} and cluster name {cluster}", dup_msg

    deleting = c.delete_nodegroup(clusterName=cluster, nodegroupName=nodegroup)["nodegroup"]
    assert deleting["status"] == "DELETING", deleting
    assert c.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)["nodegroup"]["status"] == "DELETING"

    _wait_for(
        lambda: _nodegroup_gone(c, cluster, nodegroup),
        lambda gone: gone,
        timeout_s=1200, interval_s=10, desc=f"nodegroup {nodegroup} gone",
    )
    gone_code, gone_msg = _error(lambda: c.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup))
    assert gone_code == "ResourceNotFoundException", gone_code
    assert gone_msg == "The requested resource does not exist.", gone_msg
    assert nodegroup not in c.list_nodegroups(clusterName=cluster)["nodegroups"]

    # Gone means unusable, not just unlisted: a control-plane-only mutation against the dead
    # nodegroup name must fail the same way a read does.
    dead_code, dead_msg = _error(
        lambda: c.update_nodegroup_config(
            clusterName=cluster,
            nodegroupName=nodegroup,
            labels={"addOrUpdateLabels": {"post-delete": "probe"}},
        )
    )
    assert dead_code == "ResourceNotFoundException", dead_code
    assert dead_msg == "The requested resource does not exist.", dead_msg


def _gone_ok(fn):
    """Run a teardown call; a resource the check already deleted in band is done, not a leak."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise



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
