"""concurrent-access-entry-update."""
from __future__ import annotations

import concurrent.futures
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
PRINCIPAL_ROLE = PREFIX + "eks-principal-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
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
    )
    if version:
        params["version"] = version
    return params

def _call_with_iam_propagation_retry(fn, timeout_s=90, interval_s=10):
    """Retry fn() while EKS reports the just-created IAM role as not yet visible."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidParameterException" and time.time() < deadline:
                time.sleep(interval_s)
                continue
            raise

def _provision_cluster(ctx, version=None):
    """Create a cluster owned solely by this check and wait for ACTIVE."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-eks-cl-")
    params = _cluster_params(ctx, name, version=version)
    _call_with_iam_propagation_retry(lambda: c.create_cluster(**params))
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

CHECK = "concurrent-access-entry-update"
GROUP = 'concurrency'
SERVICES = ['eks']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateAccessEntry calls on the same principal are serialised: the
    final entry MUST equal exactly one of the racing writes, never a merge of
    several (e.g. username from one write and groups from another)."""
    c = ctx.client("eks")
    cluster = _provision_cluster(ctx)
    principal = _ensure_role(ctx, PRINCIPAL_ROLE, "ec2.amazonaws.com")
    _call_with_iam_propagation_retry(
        lambda: c.create_access_entry(
            clusterName=cluster,
            principalArn=principal,
            kubernetesGroups=["sim2real-base"],
            username="sim2real-base",
            type="STANDARD",
        )
    )
    ctx.on_cleanup(lambda: c.delete_access_entry(clusterName=cluster, principalArn=principal))

    writes = [
        {"username": f"sim2real-w{i}", "kubernetesGroups": [f"sim2real-grp-{i}"]}
        for i in range(4)
    ]
    calls = [
        (
            lambda w=w: c.update_access_entry(
                clusterName=cluster,
                principalArn=principal,
                username=w["username"],
                kubernetesGroups=w["kubernetesGroups"],
            )
        )
        for w in writes
    ]
    results = _run_concurrent(calls, timeout_s=120)
    successes = _successes(results)
    codes = _error_codes(results)

    assert successes >= 1, f"at least one UpdateAccessEntry must be applied; codes={codes}"
    for code in codes:
        assert code in CONFLICT_CODES, (
            f"a rejected concurrent UpdateAccessEntry must use a conflict code, got {code}"
        )

    final = c.describe_access_entry(clusterName=cluster, principalArn=principal)["accessEntry"]
    matches = [
        w
        for w in writes
        if w["username"] == final.get("username")
        and sorted(w["kubernetesGroups"]) == sorted(final.get("kubernetesGroups", []))
    ]
    assert len(matches) == 1, (
        "the final access entry must equal exactly one racing write, not a merged "
        f"state: username={final.get('username')!r} "
        f"groups={final.get('kubernetesGroups')!r}"
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
