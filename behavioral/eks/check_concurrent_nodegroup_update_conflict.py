"""concurrent-nodegroup-update-conflict."""
from __future__ import annotations

import concurrent.futures
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
_BAD_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}
CONFLICT_CODES = {"ResourceInUseException", "InvalidRequestException", "InvalidStateException"}


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

def _retry_role_propagation(fn, timeout_s=90, interval_s=5):
    """Retry fn while EKS still rejects a freshly created IAM role as not-yet-assumable.
    IAM's eventual consistency has no API to poll directly, so the observable is EKS's own
    InvalidParameterException on the role -- bounded, rather than a flat sleep."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidParameterException" or time.time() >= deadline:
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
        if az in _BAD_AZS:
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

def _error_code(fn):
    """Call fn; return the botocore error code, or None if it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None

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
    _retry_role_propagation(lambda: c.create_cluster(**_cluster_params(ctx, name, version=version)))
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
    cluster's own cleanup is not refused with ResourceInUseException."""
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

def _run_concurrent(calls, timeout_s=180):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(calls)) as ex:
        futs = [ex.submit(fn) for fn in calls]
        for fut in futs:
            try:
                results.append(fut.result(timeout=timeout_s))
            except BaseException as exc:  # noqa: BLE001 — capture per-racer outcome
                results.append(exc)
    return results

def _successes(results):
    return sum(1 for r in results if not isinstance(r, BaseException))

def _error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

CHECK = "concurrent-nodegroup-update-conflict"
GROUP = 'concurrency'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Four simultaneous UpdateNodegroupConfig calls on one node group produce exactly
    one accepted update with one update record, the rest rejected; if the node group
    has not settled yet, every call is rejected instead — never partially applied."""
    c = ctx.client("eks")
    cluster = _provision_cluster(ctx)
    ng = ctx.unique_name("sim2real-behav-ng-race-")[:63]
    _retry_role_propagation(lambda: c.create_nodegroup(**_nodegroup_params(ctx, cluster, ng)))
    _register_nodegroup_cleanup(ctx, c, cluster, ng)

    try:
        _wait_nodegroup_status(
            c, cluster, ng, {"ACTIVE", "CREATE_FAILED", "DEGRADED"},
            timeout_s=max(1.0, min(600.0, (ctx.time_left() or 600.0) - 240.0)), interval_s=2,
        )
    except AssertionError:
        pass
    status = c.describe_nodegroup(clusterName=cluster, nodegroupName=ng)["nodegroup"]["status"]

    calls = [
        (
            lambda m=m: c.update_nodegroup_config(
                clusterName=cluster,
                nodegroupName=ng,
                scalingConfig={"minSize": 0, "maxSize": m, "desiredSize": 0},
            )
        )
        for m in (2, 3, 4, 5)
    ]
    results = _run_concurrent(calls, timeout_s=180)
    successes = _successes(results)
    codes = _error_codes(results)

    if status == "ACTIVE":
        assert successes == 1, (
            f"exactly one concurrent UpdateNodegroupConfig may be accepted, got "
            f"{successes} (codes={codes})"
        )
        assert set(codes) == {"ResourceInUseException"}, (
            f"losing racers must get ResourceInUseException, got {codes}"
        )
        winner = next(r for r in results if not isinstance(r, BaseException))
        upd = winner["update"]
        assert upd["status"] == "InProgress", f"expected InProgress, got {upd['status']}"
        desc = c.describe_update(name=cluster, updateId=upd["id"], nodegroupName=ng)["update"]
        assert desc["id"] == upd["id"], "DescribeUpdate returned a different update"
        ids = c.list_updates(name=cluster, nodegroupName=ng)["updateIds"]
        assert ids == [upd["id"]], f"exactly one update record must exist, got {ids}"
    else:
        assert successes == 0, (
            f"node group is {status}, so every concurrent update must be rejected, "
            f"but {successes} were accepted"
        )
        assert set(codes) <= CONFLICT_CODES, f"unexpected rejection codes {codes}"
        rejected_ids = c.list_updates(name=cluster, nodegroupName=ng)["updateIds"]
        assert rejected_ids == [], (
            f"no update record may exist when every concurrent update was rejected, got {rejected_ids}"
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
