"""eks-kubectl-namespace."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eks-kubectl-namespace"
GROUP = "data-plane"
SERVICES = ["eks"]

PREFIX = "sim2real-behav-"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
# Zones where EKS refuses to place a control plane, by AZ ID (AZ names map to physical zones
# differently in each account).
_BAD_AZ_IDS = {"use1-az3", "usw2-az4", "cac1-az3"}
_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}
_ROLE_PROPAGATION_TIMEOUT_S = 180
# The harness's per-check budget for this suite: every wait ends only where the runner would
# stop the check anyway, so no wait is an assertion on elapsed time.
_SUITE_BUDGET_S = 3600
# A cluster with no nodegroups deletes in minutes; this teardown window fits the cleanup budget.
_CLUSTER_DELETE_TIMEOUT_S = 900


def _trust(service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_cluster_role(ctx) -> str:
    """A per-run EKS cluster role, deleted at teardown (after the cluster, which is registered later)."""
    iam = ctx.client("iam")
    name = ctx.unique_name(PREFIX + "eks-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust("eks.amazonaws.com"),
        Description="SimParityProbe EKS behavioral fidelity fixture",
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_EKS_CLUSTER_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_EKS_CLUSTER_POLICY))
    return arn


def _default_subnet_ids(ctx) -> list[str]:
    """Two default-VPC subnets (account baseline) in distinct EKS-supported AZs."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "this account has no shared network VPC (account baseline) to place the cluster in"
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az_id = sn.get("AvailabilityZoneId") or sn["AvailabilityZone"]
        if az_id not in _BAD_AZ_IDS:
            by_az.setdefault(az_id, sn["SubnetId"])
    assert len(by_az) >= 2, f"the shared network has network subnets in {len(by_az)} EKS-supported AZs, need 2"
    return [by_az[az] for az in sorted(by_az)][:2]


def _wait_for(fn, pred, timeout_s=300, interval_s=5, desc=""):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {desc}; last={last!r}"
            )
        time.sleep(interval_s)


def _cluster_gone(c, name) -> bool:
    """True once DescribeCluster reports the cluster as not found."""
    try:
        c.describe_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _delete_cluster_and_wait(c, name) -> None:
    """Teardown: delete the cluster (retrying an in-progress update) and wait until it is gone."""
    deadline = time.monotonic() + _CLUSTER_DELETE_TIMEOUT_S
    while True:
        try:
            c.delete_cluster(name=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    _wait_for(lambda: _cluster_gone(c, name), bool,
              timeout_s=max(0.0, deadline - time.monotonic()), interval_s=2,
              desc=f"cluster {name} deleted")


def _create_cluster(ctx, c) -> dict:
    """A check-owned cluster in the default VPC, polled to ACTIVE; its teardown is registered."""
    name = ctx.unique_name(PREFIX + "eks-ns-")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _default_subnet_ids(ctx)
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
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
                tags=dict(_TAGS),
            )
            break
        except ClientError as exc:
            # IAM is eventually consistent: EKS rejects a brand-new role until it propagates.
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(c, name))
    cluster = _wait_for(
        lambda: c.describe_cluster(name=name)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_SUITE_BUDGET_S,
        interval_s=15,
        desc=f"cluster {name} status ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", f"cluster {name} ended {cluster['status']!r}"
    assert cluster.get("endpoint"), f"ACTIVE cluster {name} publishes no API server endpoint"
    return cluster


def _bearer_token(ctx, cluster_name: str) -> str:
    """An EKS bearer token: a presigned STS GetCallerIdentity bound to the cluster name, signed
    with the same identity ctx.client uses and aimed at the target's own STS endpoint."""
    from botocore.signers import RequestSigner

    sts = ctx.client("sts")
    signer = RequestSigner(
        sts.meta.service_model.service_id,
        ctx.region,
        "sts",
        "v4",
        sts._request_signer._credentials,
        sts.meta.events,
    )
    url = signer.generate_presigned_url(
        {
            "method": "GET",
            "url": ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com") + "/?Action=GetCallerIdentity&Version=2011-06-15",
            "body": {},
            "headers": {"x-k8s-aws-id": cluster_name},
            "context": {},
        },
        region_name=ctx.region,
        expires_in=60,
        operation_name="",
    )
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _write_kubeconfig(ctx, cluster: dict, path: str) -> None:
    """A kubeconfig for the cluster built in-check: the published endpoint reached on the target,
    trusting the published cluster CA (as `aws eks update-kubeconfig` does), plus the run's own CA
    bundle when ctx.http_verify names one; a run without verification skips it."""
    server = ctx.endpoint_url(cluster["endpoint"])
    entry: dict = {"server": server}
    if server.startswith("https://"):
        if ctx.http_verify is False:
            entry["insecure-skip-tls-verify"] = True
        else:
            pem = base64.b64decode((cluster.get("certificateAuthority") or {}).get("data") or "")
            if isinstance(ctx.http_verify, str):
                with open(ctx.http_verify, "rb") as fh:
                    pem = pem.rstrip(b"\n") + b"\n" + fh.read()
            if pem:
                entry["certificate-authority-data"] = base64.b64encode(pem).decode()
    config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "c", "cluster": entry}],
        "users": [{"name": "u", "user": {"token": _bearer_token(ctx, cluster["name"])}}],
        "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "u"}}],
        "current-context": "ctx",
    }
    with open(path, "w") as fh:
        json.dump(config, fh)  # JSON is valid YAML, which kubectl reads


# A real-backend data-plane FAIL marker: a run that cannot reach the Kubernetes API server is
# graded a fidelity failure, not excluded as an environment gap, because kubectl talks straight
# to that server and reports its own failure in the driver's wording.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _kubectl(args: list[str], env: dict, timeout: float = 120) -> subprocess.CompletedProcess:
    """One fresh kubectl process; returns the completed process without judging it."""
    return subprocess.run(["kubectl", *args], env=env, capture_output=True, text=True, timeout=timeout)


def _run_cli(args: list[str], env: dict, timeout: float = 120) -> str:
    proc = _kubectl(args, env, timeout)
    if proc.returncode != 0:
        # kubectl IS the data plane here, and it fails in its own wording ("connection refused",
        # "couldn't get current server API group list"): a missing Kubernetes API is a fidelity
        # failure, not an environment gap excluded from the pass/fail count.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: command failed (rc={proc.returncode}): kubectl {' '.join(args)}\n"
            f"  stderr: {proc.stderr[-500:]}"
        )
    return proc.stdout


def _not_found(proc: subprocess.CompletedProcess) -> bool:
    return proc.returncode != 0 and "notfound" in proc.stderr.lower().replace(" ", "")


_API_DNS_PROPAGATION_TIMEOUT_S = 300


def _dns_or_connect_failure(stderr: str) -> bool:
    s = stderr.lower()
    return "no such host" in s or "i/o timeout" in s or "connection refused" in s


def _wait_api_reachable(env: dict) -> None:
    """ACTIVE can precede the published endpoint's DNS record; retry the first contact."""
    deadline = time.monotonic() + _API_DNS_PROPAGATION_TIMEOUT_S
    while True:
        proc = _kubectl(["get", "namespaces", "-o", "name"], env, timeout=30)
        if proc.returncode == 0:
            return
        if not _dns_or_connect_failure(proc.stderr) or time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: command failed (rc={proc.returncode}): kubectl get namespaces\n"
                f"  stderr: {proc.stderr[-500:]}"
            )
        time.sleep(5)


def _wait_namespace_gone(ns: str, env: dict) -> None:
    """Poll an independent `kubectl get` until it reports NotFound: namespace deletion is
    asynchronous at the API server (the namespace finalizes its contents first)."""
    deadline = time.monotonic() + _SUITE_BUDGET_S
    last = None
    while time.monotonic() < deadline:
        proc = _kubectl(["get", "namespace", ns, "-o", "name"], env, timeout=30)
        if _not_found(proc):
            return
        if proc.returncode != 0:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: unexpected error waiting for namespace {ns} "
                f"to disappear: {proc.stderr[-500:]}"
            )
        last = proc.stdout
        time.sleep(3)
    raise AssertionError(f"namespace {ns} still visible via kubectl get after delete: last={last!r}")


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """Drives the real Kubernetes API via kubectl against a check-owned ACTIVE cluster: a
    namespaced ConfigMap holding a per-run nonce is written and read back by a fresh kubectl
    process, then the namespace is deleted and proven gone by three independent reads.
    """
    from fidelity_tests_runner import require_tools

    require_tools("kubectl")
    c = ctx.client("eks")
    cluster = _create_cluster(ctx, c)

    env = ctx.subprocess_env()
    kcfg = tempfile.NamedTemporaryFile(prefix="sim2real-kubeconfig-", suffix=".yaml", delete=False)
    kcfg.close()
    ctx.on_cleanup(lambda: os.unlink(kcfg.name))
    _write_kubeconfig(ctx, cluster, kcfg.name)
    env["KUBECONFIG"] = kcfg.name
    _wait_api_reachable(env)

    ns = ctx.unique_name("sim2real-behav-ns-")  # lowercase + hyphens => valid DNS-1123 label
    nonce = ctx.unique_name("")
    _run_cli(["create", "namespace", ns], env)
    out = _run_cli(["get", "namespace", ns, "-o", "name"], env, timeout=60)
    assert out.strip() == f"namespace/{ns}", f"namespace {ns} not visible via kubectl get: {out!r}"

    _run_cli(["create", "configmap", "sim2real-nonce", "-n", ns, f"--from-literal=nonce={nonce}"], env)
    read = _run_cli(
        ["get", "configmap", "sim2real-nonce", "-n", ns, "-o", "jsonpath={.data.nonce}"], env, timeout=60
    )
    assert read == nonce, f"the ConfigMap read back by a fresh kubectl holds {read!r}, expected {nonce!r}"

    _run_cli(["delete", "namespace", ns, "--wait=false"], env)
    # Gone beat 1: the read by name reports NotFound once the namespace finalizes.
    _wait_namespace_gone(ns, env)
    # Gone beat 2: the namespace list excludes it.
    listed = _run_cli(["get", "namespaces", "-o", "name"], env, timeout=60).split()
    assert f"namespace/{ns}" not in listed, f"kubectl get namespaces still lists {ns}"
    # Gone beat 3: writing into the dead namespace is refused NotFound.
    proc = _kubectl(["create", "configmap", "sim2real-after", "-n", ns, "--from-literal=a=b"], env)
    assert _not_found(proc), (
        f"creating a ConfigMap in the deleted namespace {ns} was not refused NotFound: "
        f"rc={proc.returncode} stdout={proc.stdout[-300:]!r} stderr={proc.stderr[-300:]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
