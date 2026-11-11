"""k8s-rolling-update-replaces-pods-without-dropping-the-service."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "k8s-rolling-update-replaces-pods-without-dropping-the-service"
GROUP = "data-plane"
SERVICES = ["eks"]

# ---- the shared cluster fixture: create-or-reuse under a deterministic sim2real- name ----
_SHARED_CLUSTER = "sim2real-ga-eks-shr"
_SHARED_NODEGROUP = "shared-ng"
_CLUSTER_ROLE = "sim2real-ga-eks-cluster-role"
_NODE_ROLE = "sim2real-ga-eks-node-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_NODE_POLICIES = (
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
)
_BAD_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "ga-depth-eks"}

_CLUSTER_TIMEOUT_S = 1500
_NODEGROUP_TIMEOUT_S = 900
_DELETE_RETRY_TIMEOUT_S = 900
_NODE_READY_TIMEOUT_S = 600
_ROLE_PROPAGATION_TIMEOUT_S = 120
_POD_TIMEOUT_S = 300
_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

_REPLICAS = 2
_V1 = "sim2real-roll-v1"
_V2 = "sim2real-roll-v2"
# A sequential maxSurge=1 / maxUnavailable=0 replacement of two pods costs a container start and a
# 10s preStop each, so the rollout budget is that plus room for a slow node; polled throughout.
_ROLLOUT_TIMEOUT_S = 420

# Marks a failure as a Kubernetes data-plane failure: a target that stands up no Kubernetes API
# fails this check rather than reading as a client-side connection problem in kubectl's wording.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _wait_for(fn, pred, *, timeout_s, interval_s, desc):
    """Poll an observable condition to a deadline. Never a bare sleep standing in for a wait."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {desc}; last={val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _trust(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole"],
                }
            ],
        }
    )


def _ensure_role(ctx, name, service, managed_policies=()):
    """Create-or-reuse the fixture's IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="sim2real eks kubernetes-data-plane shared fixture",
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError:
            pass
    return arn


def _call_tolerating_role_propagation(fn, *, timeout_s=_ROLE_PROPAGATION_TIMEOUT_S, interval_s=10):
    """Issue an EKS create that validates a just-created role's trust policy, bounded-retried.

    IAM is eventually consistent and EKS validates roleArn synchronously, so the first attempt can
    fail with InvalidParameterException even though the role is already correct. Retry the real
    dependent call, never a blind pre-sleep.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _fixture_subnets(ctx):
    """Subnets in EKS-supported AZs that actually offer the node instance type."""
    ec2 = ctx.client("ec2")
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_NODE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered and z["ZoneName"] not in _BAD_AZS
    }
    assert usable, (
        f"no available AZ in {ctx.region} offers {_NODE_TYPE!r}; offerings were {sorted(offered)!r}"
    )
    by_az = {}
    paginator = ec2.get_paginator("describe_subnets")
    for page in paginator.paginate(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]):
        for sn in sorted(page.get("Subnets", []), key=lambda s: s["AvailabilityZone"]):
            if sn["AvailabilityZone"] in usable:
                by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= 2, (
        f"a Kubernetes control plane needs subnets in >=2 EKS-supported AZs; this account offers "
        f"{sorted(by_az)!r} out of usable AZs {sorted(usable)!r}"
    )
    return [by_az[az] for az in sorted(by_az)][:3]


def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _nodegroup_status(c, cluster, ng):
    try:
        return c.describe_nodegroup(clusterName=cluster, nodegroupName=ng)["nodegroup"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _delete_with_retry(fn, desc):
    """Retry a delete AWS can transiently refuse with ResourceInUseException."""
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{desc} was still refused with ResourceInUseException after "
                    f"{_DELETE_RETRY_TIMEOUT_S}s: {exc}"
                ) from exc
            time.sleep(15)


def _teardown_nodegroup(ctx, cluster, ng):
    """Delete a node group and wait until it is gone -- ONLY called by whoever created it."""
    c = ctx.client("eks")
    _delete_with_retry(
        lambda: c.delete_nodegroup(clusterName=cluster, nodegroupName=ng),
        f"delete nodegroup {ng}",
    )
    _wait_for(
        lambda: _nodegroup_status(c, cluster, ng),
        lambda s: s == "GONE",
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"nodegroup {ng} deleted",
    )


def _teardown_cluster(ctx, name):
    """Drain dependents then delete the shared cluster -- ONLY called by whoever created it."""
    c = ctx.client("eks")
    try:
        for ng in c.list_nodegroups(clusterName=name).get("nodegroups", []):
            _teardown_nodegroup(ctx, name, ng)
        for addon in c.list_addons(clusterName=name).get("addons", []):
            try:
                c.delete_addon(clusterName=name, addonName=addon, preserve=False)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        for fp in c.list_fargate_profiles(clusterName=name).get("fargateProfileNames", []):
            c.delete_fargate_profile(clusterName=name, fargateProfileName=fp)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _delete_with_retry(lambda: c.delete_cluster(name=name), f"delete cluster {name}")
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s == "GONE",
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} deleted",
    )


def _adopt_or_create_cluster(ctx):
    """Bring the deterministically named shared cluster to ACTIVE, creating it if absent.

    A create-or-reuse fixture under a fixed `sim2real-` name: a control plane takes ~10 min to
    build and ~10 min to delete, so checks that find it ACTIVE adopt it. Only the run whose
    CreateCluster succeeded registers its teardown (node groups first, then the cluster), so a
    concurrent run that merely adopted it is never disrupted mid-run. Every OTHER resource this
    check makes is namespaced and torn down here.
    """
    c = ctx.client("eks")
    if _cluster_status(c, _SHARED_CLUSTER) == "GONE":
        role_arn = _ensure_role(ctx, _CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
        subnet_ids = _fixture_subnets(ctx)
        try:
            _call_tolerating_role_propagation(lambda: c.create_cluster(
                name=_SHARED_CLUSTER,
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
                tags=dict(_FIXTURE_TAGS),
            ))
            ctx.on_cleanup(lambda: _teardown_cluster(ctx, _SHARED_CLUSTER))
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException":
                raise
    cluster = _wait_for(
        lambda: c.describe_cluster(name=_SHARED_CLUSTER)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {_SHARED_CLUSTER} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", (
        f"the shared cluster landed in {cluster['status']!r}; health={cluster.get('health')!r}"
    )
    return cluster


def _adopt_or_create_nodegroup(ctx):
    """Bring the shared managed node group to ACTIVE and return its desiredSize. Only the run
    whose CreateNodegroup succeeded registers its teardown: see _adopt_or_create_cluster."""
    c = ctx.client("eks")
    if _nodegroup_status(c, _SHARED_CLUSTER, _SHARED_NODEGROUP) == "GONE":
        node_role_arn = _ensure_role(ctx, _NODE_ROLE, "ec2.amazonaws.com", _NODE_POLICIES)
        subnet_ids = _fixture_subnets(ctx)
        try:
            _call_tolerating_role_propagation(lambda: c.create_nodegroup(
                clusterName=_SHARED_CLUSTER,
                nodegroupName=_SHARED_NODEGROUP,
                subnets=subnet_ids,
                nodeRole=node_role_arn,
                scalingConfig={"minSize": 2, "maxSize": 2, "desiredSize": 2},
                instanceTypes=[_NODE_TYPE],
                amiType="AL2023_x86_64_STANDARD",
                capacityType="ON_DEMAND",
                diskSize=20,
                tags=dict(_FIXTURE_TAGS),
            ))
            ctx.on_cleanup(lambda: _teardown_nodegroup(ctx, _SHARED_CLUSTER, _SHARED_NODEGROUP))
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException":
                raise
    _wait_for(
        lambda: _nodegroup_status(c, _SHARED_CLUSTER, _SHARED_NODEGROUP),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"node group {_SHARED_NODEGROUP} ACTIVE",
    )
    ng = c.describe_nodegroup(
        clusterName=_SHARED_CLUSTER, nodegroupName=_SHARED_NODEGROUP
    )["nodegroup"]
    assert ng["status"] == "ACTIVE", f"the shared node group is {ng['status']!r}: {ng.get('health')!r}"
    return ng["scalingConfig"]["desiredSize"]


def _run(cmd, env, timeout, stdin=None):
    """Run a subprocess with the check's credentials in its environment."""
    return subprocess.run(
        cmd, env=env, input=stdin, capture_output=True, text=True, timeout=timeout
    )


def _sh(cmd, env, timeout=90, stdin=None):
    """Run a command that must succeed, reporting a failure as a DATA PLANE failure.

    kubectl IS the data plane here and it fails in its OWN wording ("connection refused", "couldn't
    get current server API group list") -- which reads like a client-side environment problem rather
    than a missing Kubernetes API. The sentinel says the check already ruled out its own
    environment.
    """
    proc = _run(cmd, env, timeout, stdin=stdin)
    if proc.returncode != 0:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: command failed (rc={proc.returncode}): {' '.join(cmd)}\n"
            f"  stderr: {proc.stderr[-600:]}"
        )
    return proc.stdout


def _kubectl(env, args, timeout=90, stdin=None):
    return _sh(["kubectl", *args], env, timeout=timeout, stdin=stdin)


def _kjson(env, args, timeout=90):
    return json.loads(_kubectl(env, [*args, "-o", "json"], timeout=timeout))


def _kapply(env, ns, objects, timeout=120):
    """`kubectl apply` a manifest list from stdin -- the way a customer ships a workload."""
    body = json.dumps({"apiVersion": "v1", "kind": "List", "items": objects})
    return _kubectl(env, ["apply", "-n", ns, "-f", "-"], timeout=timeout, stdin=body)


def _kexec(env, ns, pod, argv, timeout=90):
    """Run a command INSIDE a pod. The output is produced by the cluster, not by an AWS API."""
    return _kubectl(env, ["exec", pod, "-n", ns, "--", *argv], timeout=timeout)


def _rmtree(path):
    shutil.rmtree(path, ignore_errors=True)


def _delete_namespace(env, ns):
    """Reclaim every object the check made: they all live in this one namespace."""
    _run(["kubectl", "delete", "namespace", ns, "--ignore-not-found", "--wait=false"], env, 120)


def _kubeconfig(ctx):
    """A kubeconfig for the shared cluster, minted by the AWS CLI with the check's credentials.

    ctx.subprocess_env() is the only seam that puts the check's keys in front of a child process:
    a bare subprocess would inherit the ambient credential chain instead.
    """
    tmpdir = tempfile.mkdtemp(prefix="sim2real-kubecfg-")
    ctx.on_cleanup(lambda: _rmtree(tmpdir))
    env = ctx.subprocess_env()
    env["KUBECONFIG"] = os.path.join(tmpdir, "config")
    _sh(
        ["aws", "eks", "update-kubeconfig", "--name", _SHARED_CLUSTER, "--region", ctx.region],
        env,
        timeout=180,
    )
    return env


def _ready_nodes(env):
    return [
        n
        for n in _kjson(env, ["get", "nodes"])["items"]
        if any(
            c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"]
        )
    ]


def _fixture(ctx):
    """(kubectl env, sorted Ready node names) for the shared cluster, built if this run is first."""
    _adopt_or_create_cluster(ctx)
    desired = _adopt_or_create_nodegroup(ctx)
    env = _kubeconfig(ctx)
    nodes = _wait_for(
        lambda: _ready_nodes(env),
        lambda ns_: len(ns_) >= desired,
        timeout_s=_NODE_READY_TIMEOUT_S,
        interval_s=15,
        desc=f"{desired} Ready Kubernetes nodes (the node group's desiredSize)",
    )
    return env, sorted(n["metadata"]["name"] for n in nodes)


def _namespace(ctx, env):
    """A namespace only this check can occupy, torn down with everything inside it."""
    ns = ctx.unique_name("sim2real-k8s-")[:63].lower()
    _kubectl(env, ["create", "namespace", ns], timeout=60)
    ctx.on_cleanup(lambda: _delete_namespace(env, ns))
    return ns


def _pods(env, ns, selector):
    """Every non-terminating pod matching a label selector, newest listing each call."""
    items = _kjson(env, ["get", "pods", "-n", ns, "-l", selector])["items"]
    return [p for p in items if not p["metadata"].get("deletionTimestamp")]


def _is_ready(pod):
    return pod["status"].get("phase") == "Running" and any(
        c["type"] == "Ready" and c["status"] == "True"
        for c in pod["status"].get("conditions", [])
    )


def _server_pod_template(sentinel, labels):
    """A busybox web server that PROVES it executed: it writes and then serves its own payload."""
    return {
        "metadata": {"labels": labels},
        "spec": {
            "terminationGracePeriodSeconds": 30,
            "containers": [
                {
                    "name": "web",
                    "image": _IMAGE,
                    "command": [
                        "sh",
                        "-c",
                        "mkdir -p /www && printf '%s %s' \"$SENTINEL\" \"$POD_NAME\" "
                        "> /www/index.html && printf 'serving %s\\n' \"$SENTINEL\" "
                        "&& exec httpd -f -p 8080 -h /www",
                    ],
                    "env": [
                        {"name": "SENTINEL", "value": sentinel},
                        {
                            "name": "POD_NAME",
                            "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}},
                        },
                    ],
                    "ports": [{"containerPort": 8080}],
                    "readinessProbe": {
                        "httpGet": {"path": "/index.html", "port": 8080},
                        "initialDelaySeconds": 1,
                        "periodSeconds": 2,
                    },
                    # Keep serving while kube-proxy withdraws the endpoint, so a rolling
                    # replacement is observably non-disruptive rather than merely fast.
                    "lifecycle": {"preStop": {"exec": {"command": ["sleep", "10"]}}},
                }
            ],
        },
    }


def _client_pod(name):
    """A long-lived pod the check execs into: an in-cluster HTTP client."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": {"app": name}},
        "spec": {
            "restartPolicy": "Never",
            "containers": [
                {"name": "client", "image": _IMAGE, "command": ["sh", "-c", "sleep 1800"]}
            ],
        },
    }

def _ready_endpoint_ips(env, ns, svc):
    """The Ready addresses kube-proxy programs for a Service, over every EndpointSlice it owns."""
    slices = _kjson(
        env, ["get", "endpointslices", "-n", ns, "-l", f"kubernetes.io/service-name={svc}"]
    )["items"]
    ips = set()
    for sl in slices:
        for ep in sl.get("endpoints", []):
            if ep.get("conditions", {}).get("ready") is True:
                ips.update(ep.get("addresses", []))
    return ips


def _converged(d, want):
    """Has the Deployment controller finished this generation at `want` up-to-date replicas?"""
    s, m = d["status"], d["metadata"]
    return (
        s.get("observedGeneration") == m["generation"]
        and s.get("replicas") == want
        and s.get("updatedReplicas") == want
        and s.get("readyReplicas") == want
        and s.get("availableReplicas") == want
    )


def _replicasets(env, ns, dep_uid):
    return [
        rs
        for rs in _kjson(env, ["get", "replicasets", "-n", ns])["items"]
        if any(o.get("uid") == dep_uid for o in rs["metadata"].get("ownerReferences", []))
    ]


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """A rolling update of a 2-replica Deployment behind a ClusterIP Service replaces both pods while an
    in-cluster client never sees a failed request or zero Ready endpoints, and the old ReplicaSet
    survives scaled to zero.
    """
    from fidelity_tests_runner import require_tools

    require_tools("aws", "kubectl")

    env, node_names = _fixture(ctx)
    ns = _namespace(ctx, env)
    dep, svc, client = "sim2real-roll", "sim2real-roll-svc", "sim2real-client"
    sel = "app=sim2real-roll"

    _kapply(env, ns, [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": dep, "labels": {"app": "sim2real-roll"}},
            "spec": {
                "replicas": _REPLICAS,
                "selector": {"matchLabels": {"app": "sim2real-roll"}},
                # maxUnavailable 0 is the contract under test: Kubernetes must bring a replacement
                # to Ready BEFORE it withdraws the pod it replaces.
                "strategy": {
                    "type": "RollingUpdate",
                    "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
                },
                "template": _server_pod_template(_V1, {"app": "sim2real-roll"}),
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": svc},
            "spec": {
                "type": "ClusterIP",
                "selector": {"app": "sim2real-roll"},
                "ports": [{"port": 8080, "targetPort": 8080, "protocol": "TCP"}],
            },
        },
        _client_pod(client),
    ])

    old = _wait_for(
        lambda: _pods(env, ns, sel),
        lambda ps: len(ps) == _REPLICAS and all(_is_ready(p) for p in ps),
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=f"{_REPLICAS} Running+Ready pods of the original revision",
    )
    _wait_for(
        lambda: _kjson(env, ["get", "pod", client, "-n", ns])["status"].get("phase"),
        lambda ph: ph == "Running",
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=f"the in-cluster client pod {client} Running",
    )
    old_uids = {p["metadata"]["uid"] for p in old}
    old_names = {p["metadata"]["name"] for p in old}
    d0 = _kjson(env, ["get", "deployment", dep, "-n", ns])
    dep_uid = d0["metadata"]["uid"]
    original_rs = {rs["metadata"]["uid"] for rs in _replicasets(env, ns, dep_uid)}
    assert len(original_rs) == 1, (
        f"the fresh Deployment owns {len(original_rs)} ReplicaSets, want exactly 1 before any "
        f"update: {sorted(original_rs)!r}"
    )
    cluster_ip = _kjson(env, ["get", "service", svc, "-n", ns])["spec"]["clusterIP"]

    url = f"http://{svc}.{ns}.svc.cluster.local:8080/index.html"
    baseline = _kexec(env, ns, client, ["wget", "-q", "-T", "5", "-O-", url], timeout=60)
    assert baseline.split(" ")[0] == _V1, (
        f"before the rollout the Service returned {baseline!r}, want the {_V1!r} payload -- the "
        f"continuity measurement is worthless if the Service was not serving to begin with"
    )

    # Trigger the rollout by changing the pod template (a customer's image/config bump).
    _kubectl(env, ["set", "env", f"deployment/{dep}", f"SENTINEL={_V2}", "-n", ns], timeout=60)

    # Sample the rollout: the controller's own status, the Service's Ready endpoints, and one real
    # in-cluster request, on every pass -- a failed request here is a dropped Service.
    failures, bodies, ready_counts, in_progress, samples = [], [], [], 0, 0
    deadline = time.monotonic() + _ROLLOUT_TIMEOUT_S
    converged = None
    while True:
        samples += 1
        d = _kjson(env, ["get", "deployment", dep, "-n", ns])
        ready_counts.append(len(_ready_endpoint_ips(env, ns, svc)))
        proc = _run(
            ["kubectl", "exec", client, "-n", ns, "--", "wget", "-q", "-T", "5", "-O-", url],
            env,
            60,
        )
        if proc.returncode != 0:
            failures.append(f"rc={proc.returncode} stderr={proc.stderr[-200:]!r}")
        else:
            bodies.append(proc.stdout.strip())
        if _converged(d, _REPLICAS):
            converged = d
            break
        in_progress += 1
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the rolling update did not converge within "
                f"{_ROLLOUT_TIMEOUT_S}s; last deployment status={d['status']!r}"
            )
        time.sleep(3)

    # (1) Continuity: no request through the Service failed, and no sample saw it with no backends.
    assert not failures, (
        f"{len(failures)} of {samples} in-cluster requests through the ClusterIP failed DURING the "
        f"rolling update, so the Service was dropped: {failures[:5]!r}. maxUnavailable=0 means a "
        f"replacement is Ready before the pod it replaces is withdrawn"
    )
    assert min(ready_counts) >= 1, (
        f"the Service had zero Ready endpoints at some point in the rollout (per-sample counts "
        f"{ready_counts!r}) -- with maxUnavailable=0 it must never be emptied"
    )
    assert in_progress >= 1, (
        f"every one of the {samples} samples already showed the Deployment converged, so no rolling "
        f"update was observed at all: a fleet that is swapped atomically is not rolling"
    )
    seen = {b.split(" ")[0] for b in bodies}
    assert seen and seen <= {_V1, _V2}, (
        f"requests during the rollout returned sentinels {sorted(seen)!r}; every body must carry "
        f"the old {_V1!r} or the new {_V2!r} payload and nothing else. Bodies: {bodies[:5]!r}"
    )

    # (2) Replacement: both pods are genuinely new objects serving the new payload.
    new = _wait_for(
        lambda: _pods(env, ns, sel),
        lambda ps: len(ps) == _REPLICAS and all(_is_ready(p) for p in ps),
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=f"{_REPLICAS} Running+Ready pods of the new revision, with the old ones gone",
    )
    new_uids = {p["metadata"]["uid"] for p in new}
    new_names = {p["metadata"]["name"] for p in new}
    assert not (new_uids & old_uids), (
        f"the rollout kept pod objects from the old revision: UIDs {sorted(new_uids & old_uids)!r} "
        f"appear before and after. A rolling update REPLACES pods; it does not mutate them"
    )
    assert not (new_names & old_names), (
        f"pods {sorted(new_names & old_names)!r} carry their old names after the rollout: "
        f"{sorted(old_names)!r} -> {sorted(new_names)!r}"
    )
    for p in new:
        name = p["metadata"]["name"]
        env_vars = {e["name"]: e.get("value") for e in p["spec"]["containers"][0]["env"]}
        assert env_vars.get("SENTINEL") == _V2, (
            f"pod {name!r} still carries SENTINEL={env_vars.get('SENTINEL')!r}, want {_V2!r}"
        )
        assert p["spec"]["nodeName"] in node_names, (
            f"pod {name!r} claims node {p['spec'].get('nodeName')!r}, but the cluster reports these "
            f"Ready nodes: {node_names!r}"
        )
        assert p["status"]["containerStatuses"][0]["restartCount"] == 0, (
            f"replacement pod {name!r} reached Ready by restarting: "
            f"{p['status']['containerStatuses'][0]!r}"
        )

    # (3) The new revision is what the Service now serves, from exactly the new pods.
    final = _kexec(env, ns, client, ["wget", "-q", "-T", "5", "-O-", url], timeout=60)
    parts = final.split(" ")
    assert parts[0] == _V2 and parts[1] in new_names, (
        f"after the rollout the Service returned {final!r}; want the {_V2!r} payload from one of "
        f"{sorted(new_names)!r}"
    )
    new_ips = {p["status"]["podIP"] for p in new}
    endpoints = _wait_for(
        lambda: _ready_endpoint_ips(env, ns, svc),
        lambda ips: ips == new_ips,
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=f"the Service's Ready endpoints to be exactly the new pod IPs {sorted(new_ips)!r}",
    )
    assert endpoints == new_ips, (
        f"the Service's Ready endpoints are {sorted(endpoints)!r} but the new pods report "
        f"{sorted(new_ips)!r} -- a stale endpoint set points traffic at pods that no longer exist"
    )
    assert _kjson(env, ["get", "service", svc, "-n", ns])["spec"]["clusterIP"] == cluster_ip, (
        f"the Service's ClusterIP changed across the rollout (was {cluster_ip!r}) -- the stable "
        f"virtual IP is the whole point of fronting a Deployment with one"
    )

    # (4) The rollout is reversible: the old ReplicaSet is retained at zero replicas.
    sets = _replicasets(env, ns, dep_uid)
    by_uid = {rs["metadata"]["uid"]: rs for rs in sets}
    assert original_rs <= set(by_uid), (
        f"the original ReplicaSet {sorted(original_rs)!r} was deleted by the rollout; Kubernetes "
        f"retains it so the update can be rolled back. Present: {sorted(by_uid)!r}"
    )
    assert len(sets) == 2, (
        f"the Deployment owns {len(sets)} ReplicaSets after one template change, want 2 (old and "
        f"new): {[rs['metadata']['name'] for rs in sets]!r}"
    )
    old_rs = by_uid[sorted(original_rs)[0]]
    assert old_rs["spec"]["replicas"] == 0, (
        f"the superseded ReplicaSet {old_rs['metadata']['name']!r} still requests "
        f"{old_rs['spec']['replicas']!r} replicas, want 0"
    )
    new_rs = [rs for rs in sets if rs["metadata"]["uid"] not in original_rs][0]
    assert new_rs["spec"]["replicas"] == _REPLICAS, (
        f"the new ReplicaSet {new_rs['metadata']['name']!r} requests "
        f"{new_rs['spec']['replicas']!r} replicas, want {_REPLICAS!r}"
    )
    assert _converged(converged, _REPLICAS), (
        f"the Deployment status recorded at convergence does not hold: {converged['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
