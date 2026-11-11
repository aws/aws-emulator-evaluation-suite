"""create-nodegroup-invalid-scaling-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-nodegroup-invalid-scaling-rejected"
GROUP = 'overly-permissive'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_ROLE_PROPAGATION_TIMEOUT_S = 180.0


def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
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


def _create_cluster_with_role_propagation_retry(c, kwargs, timeout_s=_ROLE_PROPAGATION_TIMEOUT_S, interval_s=10.0):
    """IAM is eventually consistent: EKS rejects a brand-new cluster role until it propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return c.create_cluster(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_nodegroup_with_role_propagation_retry(c, kwargs, timeout_s=_ROLE_PROPAGATION_TIMEOUT_S, interval_s=10.0):
    """IAM is eventually consistent: EKS rejects a brand-new node role until it propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return c.create_nodegroup(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


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
    _create_cluster_with_role_propagation_retry(c, dict(
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
    ))
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


def _delete_nodegroup(c, cluster_name, nodegroup_name, timeout_s=900.0, interval_s=20.0):
    try:
        c.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            c.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After an in-bounds nodegroup goes ACTIVE, CreateNodegroup with desiredSize above maxSize fails with
    InvalidParameterException "desiredSize can't be greater than maxSize" and the nodegroup is neither
    describable nor listed; exact ResourceNotFoundException messages for the absent cases.
    """
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-ngbad-")
    node_role = _ensure_role(ctx, ctx.unique_name(PREFIX + "eks-node-"), "ec2.amazonaws.com", _NODE_POLICIES)
    subnets = _subnet_ids(ctx)

    good_nodegroup = ctx.unique_name("ng-good-")
    _create_nodegroup_with_role_propagation_retry(c, dict(
        clusterName=cluster,
        nodegroupName=good_nodegroup,
        subnets=subnets,
        nodeRole=node_role,
        scalingConfig={"minSize": 1, "maxSize": 2, "desiredSize": 1},
    ))
    ctx.on_cleanup(lambda: _delete_nodegroup(c, cluster, good_nodegroup))
    active = _wait_for(
        lambda: c.describe_nodegroup(clusterName=cluster, nodegroupName=good_nodegroup)["nodegroup"],
        lambda n: n["status"] in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=900,
        interval_s=15,
        desc=f"positive-control nodegroup {good_nodegroup} ACTIVE",
    )
    assert active["status"] == "ACTIVE", (
        f"positive control (in-bounds scaling config) landed in {active['status']!r} instead of "
        "ACTIVE; the wiring itself is broken, so a rejection below would not be attributable to "
        "the invalid scaling config"
    )

    nodegroup = ctx.unique_name("ng-bad-")

    create_code, create_message = _error(
        lambda: c.create_nodegroup(
            clusterName=cluster,
            nodegroupName=nodegroup,
            subnets=subnets,
            nodeRole=node_role,
            scalingConfig={"minSize": 2, "maxSize": 3, "desiredSize": 9},
        )
    )
    assert create_code == "InvalidParameterException", (
        f"desiredSize=9 outside [minSize=2, maxSize=3] was rejected with {create_code!r}, "
        "expected InvalidParameterException"
    )
    assert create_message == "desiredSize can't be greater than maxSize", create_message
    describe_code, describe_message = _error(
        lambda: c.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)
    )
    assert describe_code == "ResourceNotFoundException", (
        f"the rejected nodegroup {nodegroup!r} described as {describe_code!r}, expected "
        "ResourceNotFoundException (nothing should have been created)"
    )
    assert describe_message == "The requested resource does not exist.", describe_message
    listed = c.list_nodegroups(clusterName=cluster)["nodegroups"]
    assert nodegroup not in listed, f"rejected nodegroup {nodegroup!r} appeared in ListNodegroups: {listed!r}"

    absent_cluster = ctx.unique_name("absent-clu-")
    absent_cluster_code, absent_cluster_message = _error(
        lambda: c.create_nodegroup(
            clusterName=absent_cluster,
            nodegroupName=nodegroup,
            subnets=subnets,
            nodeRole=node_role,
        )
    )
    assert absent_cluster_code == "ResourceNotFoundException", (
        f"CreateNodegroup against a nonexistent cluster returned {absent_cluster_code!r}, "
        "expected ResourceNotFoundException"
    )
    assert absent_cluster_message == f"No cluster found for name: {absent_cluster}.", absent_cluster_message
    delete_code, delete_message = _error(lambda: c.delete_nodegroup(clusterName=cluster, nodegroupName=nodegroup))
    assert delete_code == "ResourceNotFoundException", (
        f"DeleteNodegroup on the never-created nodegroup {nodegroup!r} returned {delete_code!r}, "
        "expected ResourceNotFoundException"
    )
    assert delete_message == "The requested resource does not exist.", delete_message


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
