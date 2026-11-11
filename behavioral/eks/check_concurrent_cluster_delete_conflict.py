"""concurrent-cluster-delete-conflict."""
from __future__ import annotations

import concurrent.futures
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

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

def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")

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
    params = _cluster_params(ctx, name, version=version)
    deadline = time.monotonic() + 90
    while True:
        try:
            c.create_cluster(**params)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidParameterException", "ClientException") or time.monotonic() >= deadline:
                raise
            time.sleep(2)
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

CHECK = "concurrent-cluster-delete-conflict"
GROUP = 'concurrency'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent DeleteCluster calls resolve to one deletion: accepted racers report DELETING on the same
    ARN, a repeat delete returns it again, and CreateCluster on the name fails with ResourceInUseException
    "Cluster already exists with name: ..." both before and during deletion.
    """
    c = ctx.client("eks")
    cluster = _provision_cluster(ctx)

    # CreateCluster must not clobber a live cluster of the same name
    dup, dup_msg = _error(lambda: c.create_cluster(**_cluster_params(ctx, cluster)))
    assert dup == "ResourceInUseException", (
        f"CreateCluster for an existing name must be ResourceInUseException, got {dup}"
    )
    assert dup_msg == f"Cluster already exists with name: {cluster}", dup_msg

    results = _run_concurrent(
        [lambda: c.delete_cluster(name=cluster) for _ in range(2)], timeout_s=180
    )
    successes = _successes(results)
    codes = _error_codes(results)
    assert successes >= 1, f"at least one DeleteCluster must be accepted; codes={codes}"
    assert successes + len(codes) == 2, "unexpected result count from the racers"
    for code in codes:
        assert code == "ResourceInUseException", (
            f"a losing concurrent DeleteCluster must be ResourceInUseException, got {code}"
        )

    # Every accepted racer must describe the SAME resource transitioning once.
    arns = set()
    for res in results:
        if isinstance(res, BaseException):
            continue
        payload = res["cluster"]
        assert payload["status"] == "DELETING", (
            f"an accepted DeleteCluster reported status {payload['status']}, expected DELETING"
        )
        arns.add(payload["arn"])
    assert len(arns) == 1, f"racers must resolve to one cluster resource, got {arns}"
    single_arn = next(iter(arns))

    status = c.describe_cluster(name=cluster)["cluster"]["status"]
    assert status == "DELETING", (
        f"the cluster must be in exactly one DELETING transition, got {status}"
    )

    # A further DeleteCluster is idempotent.
    again = c.delete_cluster(name=cluster)["cluster"]
    assert again["status"] == "DELETING", f"repeat DeleteCluster reported {again['status']}"
    assert again["arn"] == single_arn, "repeat DeleteCluster returned a different resource"

    # ...and the name is still claimed, so it cannot be recreated mid-deletion.
    recreate, recreate_msg = _error(lambda: c.create_cluster(**_cluster_params(ctx, cluster)))
    assert recreate == "ResourceInUseException", (
        f"CreateCluster for a DELETING cluster's name must be ResourceInUseException, "
        f"got {recreate}"
    )
    assert recreate_msg == f"Cluster already exists with name: {cluster}", recreate_msg


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
