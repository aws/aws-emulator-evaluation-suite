"""nodegroup-update-config-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodegroup-update-config-lifecycle"
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


def _call_tolerating_role_propagation(fn, timeout_s=60, interval_s=10, desc=""):
    """Call fn, retrying while EKS still reports the just-created role as invalid.

    EKS validates roleArn synchronously against IAM, and a role created seconds
    earlier is not yet visible to it -- IAM's own eventual consistency, not an
    EKS defect. Bounded, and exhaustion re-raises the real error.
    """
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.time() >= deadline:
                raise
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
    _call_tolerating_role_propagation(
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
            tags={"sim2real": "1"},
        ),
        desc=f"CreateCluster accepting cluster role {role_arn}",
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNodegroupConfig returns an InProgress ConfigUpdate that DescribeUpdate tracks to Successful,
    after which the ACTIVE nodegroup carries the new maxSize, label and maxUnavailable; UpdateNodegroupVersion
    on an absent nodegroup and a minSize above desiredSize are refused with their exact codes and messages."""
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-ngu-")
    node_role = _ensure_role(ctx, ctx.unique_name(PREFIX + "eks-node-"), "ec2.amazonaws.com", _NODE_POLICIES)
    subnets = _subnet_ids(ctx)
    nodegroup = ctx.unique_name("ngu-")

    _call_tolerating_role_propagation(
        lambda: c.create_nodegroup(
            clusterName=cluster,
            nodegroupName=nodegroup,
            subnets=subnets,
            nodeRole=node_role,
            instanceTypes=["t3.small"],
            diskSize=20,
            scalingConfig={"minSize": 1, "maxSize": 2, "desiredSize": 1},
            tags={"sim2real": "1"},
        ),
        desc=f"CreateNodegroup accepting node role {node_role}",
    )
    ctx.on_cleanup(lambda: _delete_nodegroup_and_wait(c, cluster, nodegroup))
    _wait_for(
        lambda: c.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)["nodegroup"],
        lambda n: n["status"] in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=600, interval_s=15, desc=f"nodegroup {nodegroup} ACTIVE",
    )

    update = c.update_nodegroup_config(
        clusterName=cluster,
        nodegroupName=nodegroup,
        scalingConfig={"minSize": 1, "maxSize": 4, "desiredSize": 1},
        labels={"addOrUpdateLabels": {"sim2real-updated": "yes"}},
        updateConfig={"maxUnavailable": 1},
    )["update"]
    assert update["status"] == "InProgress", update
    assert update["type"] == "ConfigUpdate", update

    interim = c.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)["nodegroup"]
    assert interim["status"] in ("UPDATING", "ACTIVE"), interim["status"]

    seen = c.describe_update(name=cluster, nodegroupName=nodegroup, updateId=update["id"])["update"]
    assert seen["id"] == update["id"], seen
    assert seen["type"] == "ConfigUpdate", seen

    terminal = _wait_for(
        lambda: c.describe_update(name=cluster, nodegroupName=nodegroup, updateId=update["id"])["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=300, interval_s=10, desc=f"update {update['id']} terminal",
    )
    assert terminal["status"] == "Successful", terminal

    settled = _wait_for(
        lambda: c.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)["nodegroup"],
        lambda n: n["status"] == "ACTIVE",
        timeout_s=180, interval_s=10, desc=f"nodegroup {nodegroup} settled ACTIVE",
    )
    assert settled["scalingConfig"]["maxSize"] == 4, settled["scalingConfig"]
    assert settled["labels"]["sim2real-updated"] == "yes", settled["labels"]
    assert settled["updateConfig"]["maxUnavailable"] == 1, settled["updateConfig"]

    code, message = _error(
        lambda: c.update_nodegroup_version(
            clusterName=cluster, nodegroupName=ctx.unique_name("absent-ng-"), force=True
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The requested resource does not exist.", f"unexpected message {message!r}"
    code, message = _error(
        lambda: c.update_nodegroup_config(
            clusterName=cluster,
            nodegroupName=nodegroup,
            scalingConfig={"minSize": 5, "maxSize": 4, "desiredSize": 1},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "Minimum capacity 5 can't be greater than desired size 1", f"unexpected message {message!r}"


def _delete_nodegroup_and_wait(c, cluster, nodegroup):
    """Delete the nodegroup and wait until it is gone: DeleteCluster refuses while one is attached."""
    from botocore.exceptions import ClientError

    c.delete_nodegroup(clusterName=cluster, nodegroupName=nodegroup)
    deadline = time.monotonic() + 1200
    while True:
        try:
            c.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"nodegroup {nodegroup} still exists 1200s after DeleteNodegroup")
        time.sleep(20)


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
