"""nodegroup-update-serialization."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
NODE_ROLE = PREFIX + "eks-node-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_NODE_POLICIES = (
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
)
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
CONFLICT_CODES = {"ResourceInUseException", "InvalidRequestException", "InvalidStateException"}
BOGUS_UPDATE_ID = "1e2f3a4b-5c6d-7e8f-9a0b-1c2d3e4f5a6b"


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

def _with_role_propagation_retry(fn, timeout_s=90, interval_s=10):
    """A just-created IAM role is eventually consistent into EKS; retry the
    dependent call on InvalidParameterException instead of sleeping blind."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise

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

_NOT_ACTIVE = "Nodegroup cannot be updated as it is currently not in Active State"

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
    _with_role_propagation_retry(
        lambda: c.create_cluster(**_cluster_params(ctx, name, version=version))
    )
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))
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

CHECK = "nodegroup-update-serialization"
GROUP = 'ordering'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CREATING node group refuses both UpdateNodegroupVersion and UpdateNodegroupConfig without
    queuing an update record; once it is ACTIVE the same UpdateNodegroupConfig is accepted."""
    c = ctx.client("eks")
    cluster = _provision_cluster(ctx)
    ng = ctx.unique_name("sim2real-behav-ng-ser-")[:63]
    _with_role_propagation_retry(
        lambda: c.create_nodegroup(**_nodegroup_params(ctx, cluster, ng))
    )
    _register_nodegroup_cleanup(ctx, c, cluster, ng)

    status = c.describe_nodegroup(clusterName=cluster, nodegroupName=ng)["nodegroup"]["status"]
    assert status == "CREATING", f"expected CREATING right after CreateNodegroup, got {status}"

    ver_code, ver_msg = _error(
        lambda: c.update_nodegroup_version(clusterName=cluster, nodegroupName=ng, force=True)
    )
    assert ver_code in CONFLICT_CODES, (
        f"UpdateNodegroupVersion on a CREATING node group must be rejected, got {ver_code}"
    )
    if ver_code == "ResourceInUseException":
        assert ver_msg == _NOT_ACTIVE, f"unexpected UpdateNodegroupVersion message {ver_msg!r}"

    cfg_code, cfg_msg = _error(
        lambda: c.update_nodegroup_config(
            clusterName=cluster,
            nodegroupName=ng,
            scalingConfig={"minSize": 0, "maxSize": 2, "desiredSize": 0},
        )
    )
    assert cfg_code in CONFLICT_CODES, (
        f"UpdateNodegroupConfig on a CREATING node group must be rejected, got {cfg_code}"
    )
    if cfg_code == "ResourceInUseException":
        assert cfg_msg == _NOT_ACTIVE, f"unexpected UpdateNodegroupConfig message {cfg_msg!r}"

    # rejected updates must not be silently queued
    ids = c.list_updates(name=cluster, nodegroupName=ng)["updateIds"]
    assert ids == [], f"rejected node group updates must not be recorded; got {ids}"
    missing, missing_msg = _error(
        lambda: c.describe_update(name=cluster, updateId=BOGUS_UPDATE_ID, nodegroupName=ng)
    )
    assert missing == "ResourceNotFoundException", (
        f"DescribeUpdate for an unknown update id must be ResourceNotFoundException, got {missing}"
    )
    assert missing_msg == f"No update found for ID: {BOGUS_UPDATE_ID}", missing_msg

    # The refusal is ordering, not permanent: once ACTIVE the same call succeeds.
    final = _wait_nodegroup_status(
        c, cluster, ng, {"ACTIVE", "CREATE_FAILED", "DEGRADED"},
        timeout_s=600, interval_s=15,
    )
    assert final == "ACTIVE", f"nodegroup {ng} reached {final}, expected ACTIVE"
    upd = c.update_nodegroup_config(
        clusterName=cluster,
        nodegroupName=ng,
        scalingConfig={"minSize": 0, "maxSize": 2, "desiredSize": 0},
    )["update"]
    assert upd["status"] == "InProgress", f"expected InProgress, got {upd['status']}"
    ids_after = c.list_updates(name=cluster, nodegroupName=ng)["updateIds"]
    assert ids_after == [upd["id"]], f"expected only update {upd['id']!r} queued, got {ids_after}"



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
