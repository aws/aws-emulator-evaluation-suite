"""hpa-min-replicas-above-max-replicas-rejected."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hpa-min-replicas-above-max-replicas-rejected"
GROUP = "data-plane"
SERVICES = ["eks"]

# ---- the shared cluster fixture: create-or-reuse under a deterministic sim2real- name ----
# Fixed names, so every run that adopts the cluster pays for one control plane rather than one each.
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
_NODE_READY_TIMEOUT_S = 600
_ROLE_PROPAGATION_TIMEOUT_S = 120
_ADDON_TIMEOUT_S = 900
_DELETE_RETRY_TIMEOUT_S = 900
_POD_TIMEOUT_S = 300
_METRICS_TIMEOUT_S = 420
_SCALE_OUT_TIMEOUT_S = 480
_SCALE_IN_TIMEOUT_S = 600

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_ADDON = "metrics-server"

# The autoscaling target. Utilization is usage/request, so a container throttled at its 200m limit
# reports ~400% of a 50m request -- comfortably over the 60% target, and comfortably under what two
# t3.medium nodes can serve at _MAX replicas.
_CPU_REQUEST = "50m"
_CPU_LIMIT = "200m"
_TARGET_UTILIZATION = 60
_MIN = 1
_MAX = 4

# The marker file the workload's own loop watches: present -> burn CPU, absent -> idle. Load is
# therefore started and stopped from OUTSIDE the container, by `kubectl exec`, which is what lets
# this check assert both directions -- a container that burns unconditionally can only ever scale
# out.
_BURN_MARKER = "/tmp/burn"
_BURN_LOOP = f"while true; do if [ -f {_BURN_MARKER} ]; then :; else sleep 1; fi; done"

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


def _delete_role(iam, name, managed_policies):
    """Detach the role's managed policies and delete it; a role already gone is fine."""
    for policy_arn in managed_policies:
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _ensure_role(ctx, name, service, managed_policies=()):
    """Create-or-reuse the fixture's IAM role and return its ARN. Deleted at cleanup only if this
    call created it."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="sim2real eks kubernetes-data-plane shared fixture",
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: _delete_role(iam, name, managed_policies))
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


def _addon_status(c, cluster, addon):
    try:
        return c.describe_addon(clusterName=cluster, addonName=addon)["addon"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _delete_with_retry(fn, desc):
    """Issue a delete AWS can transiently refuse, retrying it within a bounded budget.

    DeleteCluster can answer ResourceInUseException ("currently has an update in progress") on an
    ACTIVE cluster with no dependents, so the delete itself is retried.
    """
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
            time.sleep(2)


def _teardown_addon(c, cluster, addon):
    try:
        c.delete_addon(clusterName=cluster, addonName=addon, preserve=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _wait_for(
        lambda: _addon_status(c, cluster, addon),
        lambda s: s == "GONE",
        timeout_s=_ADDON_TIMEOUT_S,
        interval_s=15,
        desc=f"addon {addon} deleted",
    )


def _teardown_nodegroup(c, cluster, ng):
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


def _teardown_cluster(c, name):
    """Drain dependents then delete the control plane, polling it to actually gone."""
    try:
        for ng in c.list_nodegroups(clusterName=name).get("nodegroups", []):
            _teardown_nodegroup(c, name, ng)
        for addon in c.list_addons(clusterName=name).get("addons", []):
            _teardown_addon(c, name, addon)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _delete_with_retry(lambda: c.delete_cluster(name=name), f"delete cluster {name}")
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s == "GONE",
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} fully deleted",
    )


def _adopt_or_create_cluster(ctx):
    """Bring the deterministically named shared cluster to ACTIVE, creating it if absent.

    Teardown is registered only for what this run creates: a cluster, node group, role or the
    metrics-server addon that already exists is adopted and left in place, and one this run
    creates is deleted by this run. Every OTHER resource this check makes is namespaced and torn
    down here.
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
            ctx.on_cleanup(lambda: _teardown_cluster(c, _SHARED_CLUSTER))
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
    """Bring the shared managed node group to ACTIVE and return its desiredSize. Torn down
    only if this run created it: see _adopt_or_create_cluster."""
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
            ctx.on_cleanup(lambda: _teardown_nodegroup(c, _SHARED_CLUSTER, _SHARED_NODEGROUP))
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
    assert ng["status"] == "ACTIVE", (
        f"the shared node group is {ng['status']!r}: {ng.get('health')!r}"
    )
    return ng["scalingConfig"]["desiredSize"]


def _default_addon_version(ctx, kubernetes_version):
    """The addon version EKS itself marks default for this cluster's Kubernetes version.

    Paginated and derived rather than pinned: an addon version literal rots the moment EKS
    publishes a new build, and the default for 1.33 is not the default for 1.34.
    """
    c = ctx.client("eks")
    offered, token = [], None
    while True:
        kwargs = {"addonName": _ADDON, "kubernetesVersion": kubernetes_version}
        if token:
            kwargs["nextToken"] = token
        page = c.describe_addon_versions(**kwargs)
        for addon in page["addons"]:
            for version in addon["addonVersions"]:
                offered.append(version["addonVersion"])
                for compat in version.get("compatibilities", []):
                    if compat.get("defaultVersion"):
                        return version["addonVersion"]
        token = page.get("nextToken")
        if not token:
            break
    raise AssertionError(
        f"DescribeAddonVersions offered no defaultVersion of {_ADDON!r} for Kubernetes "
        f"{kubernetes_version!r}; versions offered were {offered!r} -- without the metrics pipeline "
        f"a HorizontalPodAutoscaler cannot read CPU at all"
    )


def _ensure_metrics_server(ctx, kubernetes_version):
    """Bring the metrics-server addon to ACTIVE on the shared cluster. Torn down only if this run
    created it (see _adopt_or_create_cluster); an addon that already exists is adopted and left in
    place."""
    c = ctx.client("eks")
    if _addon_status(c, _SHARED_CLUSTER, _ADDON) == "GONE":
        version = _default_addon_version(ctx, kubernetes_version)
        try:
            c.create_addon(
                clusterName=_SHARED_CLUSTER,
                addonName=_ADDON,
                addonVersion=version,
                resolveConflicts="OVERWRITE",
                tags=dict(_FIXTURE_TAGS),
            )
            ctx.on_cleanup(lambda: _teardown_addon(c, _SHARED_CLUSTER, _ADDON))
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException":
                raise
    status = _wait_for(
        lambda: _addon_status(c, _SHARED_CLUSTER, _ADDON),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_ADDON_TIMEOUT_S,
        interval_s=15,
        desc=f"addon {_ADDON} to leave CREATING",
    )
    assert status == "ACTIVE", (
        f"the {_ADDON} addon landed in {status!r}, expected ACTIVE; health="
        f"{c.describe_addon(clusterName=_SHARED_CLUSTER, addonName=_ADDON)['addon'].get('health')!r}"
        f" -- the HPA has no CPU metric source without it"
    )


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
    cluster = _adopt_or_create_cluster(ctx)
    desired = _adopt_or_create_nodegroup(ctx)
    _ensure_metrics_server(ctx, cluster["version"])
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
    ns = ctx.unique_name("sim2real-hpa-")[:63].lower()
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


def _ready_pods(env, ns, selector):
    return [p for p in _pods(env, ns, selector) if _is_ready(p)]


def _names(pods):
    return {p["metadata"]["name"] for p in pods}


def _burn_workload(name, *, requests, limits):
    """A Deployment whose pods burn CPU only while the marker file exists.

    The loop is the pod's own PID 1, so `kubectl exec ... touch` and `... rm` are the whole load
    generator -- no sidecar, no external load driver, and a replica the autoscaler creates starts
    idle, which is what lets the average utilization fall as the Deployment grows.
    """
    resources = {}
    if requests:
        resources["requests"] = requests
    if limits:
        resources["limits"] = limits
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "labels": {"app": name}},
        "spec": {
            "replicas": _MIN,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "terminationGracePeriodSeconds": 5,
                    "containers": [
                        {
                            "name": "burn",
                            "image": _IMAGE,
                            "command": ["sh", "-c", _BURN_LOOP],
                            "resources": resources,
                        }
                    ],
                },
            },
        },
    }


def _hpa(name, target_deployment, *, minr=_MIN, maxr=_MAX):
    """An autoscaling/v2 HPA on CPU utilization, with both stabilization windows made explicit.

    The windows are CONFIGURATION, not an assertion: the defaults (0s up, 300s down) would make the
    scale-in leg cost five minutes of wall clock for no extra evidence. Nothing below asserts a
    timing or an interval -- only the direction of the change and the value it converges to.
    """
    return {
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {"name": name},
        "spec": {
            "scaleTargetRef": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": target_deployment,
            },
            "minReplicas": minr,
            "maxReplicas": maxr,
            "metrics": [
                {
                    "type": "Resource",
                    "resource": {
                        "name": "cpu",
                        "target": {
                            "type": "Utilization",
                            "averageUtilization": _TARGET_UTILIZATION,
                        },
                    },
                }
            ],
            "behavior": {
                "scaleUp": {
                    "stabilizationWindowSeconds": 0,
                    "selectPolicy": "Max",
                    "policies": [
                        {"type": "Pods", "value": _MAX, "periodSeconds": 15},
                        {"type": "Percent", "value": 100, "periodSeconds": 15},
                    ],
                },
                "scaleDown": {
                    "stabilizationWindowSeconds": 15,
                    "selectPolicy": "Max",
                    "policies": [{"type": "Percent", "value": 100, "periodSeconds": 15}],
                },
            },
        },
    }


def _get_hpa(env, ns, name):
    """Read the HPA through its v2 resource name, so the status fields asserted below are v2's."""
    return _kjson(env, ["get", f"horizontalpodautoscalers.v2.autoscaling/{name}", "-n", ns])


def _hpa_cpu_utilization(hpa):
    """The CPU utilization the HPA ITSELF currently reports, or None while it has no reading."""
    for metric in hpa.get("status", {}).get("currentMetrics") or []:
        resource = metric.get("resource") or {}
        if resource.get("name") == "cpu":
            return (resource.get("current") or {}).get("averageUtilization")
    return None


def _hpa_condition(hpa, kind):
    for cond in hpa.get("status", {}).get("conditions") or []:
        if cond.get("type") == kind:
            return cond
    return None


def _pod_cpu_millicores(env, ns):
    """`kubectl top pod` per pod, in millicores -- the metrics pipeline read as a customer reads it.

    Parsed strictly: an unexpected unit is a failure naming the line, not a silent 0 that would
    make the "the load really landed" assertion below pass on no evidence.
    """
    out = _kubectl(env, ["top", "pod", "-n", ns, "--no-headers"], timeout=90)
    usage = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, cpu = parts[0], parts[1]
        assert cpu.endswith("m") and cpu[:-1].isdigit(), (
            f"`kubectl top pod` reported CPU {cpu!r} for {name!r}, which is not millicores: "
            f"{line!r}"
        )
        usage[name] = int(cpu[:-1])
    return usage


def _start_load(env, ns, pods):
    for pod in sorted(pods):
        _kubectl(env, ["exec", pod, "-n", ns, "--", "touch", _BURN_MARKER], timeout=90)


def _stop_load(env, ns, pods):
    for pod in sorted(pods):
        _kubectl(env, ["exec", pod, "-n", ns, "--", "rm", "-f", _BURN_MARKER], timeout=90)


def _try_apply(env, ns, objects, timeout=120):
    """`kubectl apply` a manifest list that may be REJECTED -> (returncode, stdout, stderr).

    Deliberately not routed through _kapply/_sh: those raise on a non-zero exit, which would turn
    the rejection this check exists to observe into a data-plane failure. The response of a call
    expected to fail is captured rather than asserted away, so a target that WRONGLY ACCEPTS the
    object is caught by the next assertion instead of aborting here.
    """
    body = json.dumps({"apiVersion": "v1", "kind": "List", "items": objects})
    proc = _run(["kubectl", "apply", "-n", ns, "-f", "-"], env, timeout, stdin=body)
    return proc.returncode, proc.stdout, proc.stderr


def _get_or_missing(env, ns, name, timeout=60):
    """(True, object) if the HPA exists, (False, stderr) if the API server says it does not."""
    proc = _run(
        ["kubectl", "get", f"horizontalpodautoscalers.v2.autoscaling/{name}", "-n", ns, "-o",
         "json"],
        env,
        timeout,
    )
    if proc.returncode == 0:
        return True, json.loads(proc.stdout)
    return False, proc.stderr


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """The API server rejects a HorizontalPodAutoscaler with minReplicas above maxReplicas, naming
    spec.maxReplicas, and stores nothing, while the corrected manifest is accepted and adopted by a
    live autoscaler controller that writes status back.
    """
    from fidelity_tests_runner import require_tools

    require_tools("aws", "kubectl")

    env, node_names = _fixture(ctx)
    assert node_names, "the shared cluster reports no Ready nodes"
    ns = _namespace(ctx, env)
    dep = "sim2real-hpa-bounds"
    bad_hpa, good_hpa = f"{dep}-bad", f"{dep}-ok"

    _kapply(env, ns, [
        _burn_workload(
            dep,
            requests={"cpu": _CPU_REQUEST, "memory": "32Mi"},
            limits={"cpu": _CPU_LIMIT, "memory": "64Mi"},
        ),
    ])
    _wait_for(
        lambda: _ready_pods(env, ns, f"app={dep}"),
        lambda ps: len(ps) == _MIN,
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=f"the scale target's {_MIN} Running+Ready pod(s)",
    )

    # (1) The one broken thing: minReplicas above maxReplicas.
    inverted = _hpa(bad_hpa, dep, minr=_MAX, maxr=_MIN)
    rc, out, err = _try_apply(env, ns, [inverted])
    assert rc != 0, (
        f"the API server ACCEPTED a HorizontalPodAutoscaler with minReplicas={_MAX} > "
        f"maxReplicas={_MIN}: rc={rc}, stdout={out!r} -- Kubernetes validation forbids this, and an "
        f"accepted one would have no reachable replica range at all"
    )
    assert "is invalid" in err, (
        f"the rejection does not read as a Kubernetes validation failure: {err[-600:]!r}"
    )
    assert "spec.maxReplicas" in err, (
        f"the rejection does not name spec.maxReplicas as the invalid field, so it is not the "
        f"validation under test: {err[-600:]!r}"
    )

    # (2) The effect is ABSENT: nothing was partially created under that name.
    exists, detail = _get_or_missing(env, ns, bad_hpa)
    assert not exists, (
        f"the rejected HorizontalPodAutoscaler {bad_hpa!r} exists anyway: "
        f"{json.dumps(detail.get('spec'), sort_keys=True)}"
    )
    assert "not found" in detail.lower(), (
        f"GET of the rejected {bad_hpa!r} failed for some reason other than its absence: "
        f"{detail[-600:]!r}"
    )

    # (3) The positive control: the same manifest with the bound the right way round is accepted,
    # and a real controller adopts it.
    _kapply(env, ns, [_hpa(good_hpa, dep)])
    adopted = _wait_for(
        lambda: _get_hpa(env, ns, good_hpa),
        lambda h: (h.get("status") or {}).get("currentReplicas") is not None,
        timeout_s=_POD_TIMEOUT_S,
        interval_s=10,
        desc=f"the HPA controller to write a status onto {good_hpa!r}",
    )
    assert adopted["status"]["currentReplicas"] == _MIN, (
        f"the controller adopted {good_hpa!r} but reports currentReplicas="
        f"{adopted['status']['currentReplicas']!r} for a target running {_MIN} replica(s): "
        f"status={adopted['status']!r}"
    )
    assert adopted["spec"]["minReplicas"] <= adopted["spec"]["maxReplicas"], (
        f"the accepted HPA came back with an inverted bound: {adopted['spec']!r}"
    )
    reappeared, _ = _get_or_missing(env, ns, bad_hpa)
    assert not reappeared, (
        f"{bad_hpa!r} appeared after the valid sibling was created, so the rejection above was not "
        f"durable"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
