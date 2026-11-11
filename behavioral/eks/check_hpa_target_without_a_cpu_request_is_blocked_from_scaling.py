"""hpa-target-without-a-cpu-request-is-blocked-from-scaling."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hpa-target-without-a-cpu-request-is-blocked-from-scaling"
GROUP = "data-plane"
SERVICES = ["eks"]

# ---- the shared cluster fixture: create-or-reuse under a deterministic sim2real- name ----
# Fixed names, so runs of checks that adopt the same fixture pay for one control plane rather
# than one each.
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

# Marks a failure in which the cluster's Kubernetes API did not do its part, so a target without
# a Kubernetes API fails the check rather than reading as a local connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


# ===== helpers =====


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

    kubectl IS the data plane here and it fails in its OWN wording ("connection refused",
    "couldn't get current server API group list"), which reads like a local environment error;
    the marker says the check already ruled out its own environment.
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

    ctx.subprocess_env() is what passes the check's credentials to a child process; a bare
    subprocess would inherit the ambient environment instead.
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


#: A floor on load THIS CHECK CAUSED, not a service constant: the unthrottled busy loop measures
#: ~1000m, and the throttled positive control is capped at its own 200m limit. Asserting the
#: broken Deployment is above this floor is what makes "it did not scale" mean "the missing
#: request blocked it" rather than "nothing was ever loaded".
_LOAD_FLOOR_M = 100

#: The Kubernetes condition an HPA reports when it cannot compute utilization because the target's
#: container declares no CPU request. Observed on real EKS; asserted exactly, never as a substring
#: of the longer message.
_BLOCKED_REASON = "FailedGetResourceMetric"


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
    """An HPA whose Deployment declares no `requests.cpu` reports ScalingActive=False /
    FailedGetResourceMetric and its burning pod's replica count stays unchanged at the moment an
    identical Deployment WITH a CPU request, under the same load, is seen scaling out."""
    from fidelity_tests_runner import require_tools

    require_tools("aws", "kubectl")

    env, node_names = _fixture(ctx)
    ns = _namespace(ctx, env)
    good, bad = "sim2real-hpa-req", "sim2real-hpa-noreq"

    _kapply(env, ns, [
        # The control: a CPU request, so utilization is computable.
        _burn_workload(
            good,
            requests={"cpu": _CPU_REQUEST, "memory": "32Mi"},
            limits={"cpu": _CPU_LIMIT, "memory": "64Mi"},
        ),
        _hpa(good, good),
        # The one broken thing: no `requests.cpu`. A memory limit is kept so the pod is still
        # bounded, and no CPU LIMIT is set either -- Kubernetes defaults an absent request to the
        # limit, so a cpu limit here would silently repair the very thing under test.
        _burn_workload(bad, requests={"memory": "32Mi"}, limits={"memory": "64Mi"}),
        _hpa(bad, bad),
    ])

    started = {}
    for dep in (good, bad):
        pods = _wait_for(
            lambda d=dep: _ready_pods(env, ns, f"app={d}"),
            lambda ps: len(ps) == _MIN,
            timeout_s=_POD_TIMEOUT_S,
            interval_s=5,
            desc=f"the initial {_MIN} Running+Ready pod(s) of {dep}",
        )
        started[dep] = _names(pods)
        for pod in pods:
            assert pod["spec"]["nodeName"] in node_names, (
                f"pod {pod['metadata']['name']!r} claims node {pod['spec'].get('nodeName')!r}, but "
                f"the cluster reports these Ready nodes: {node_names!r}"
            )

    # The broken Deployment really is broken in exactly one way, read back from the cluster.
    spec = _kjson(env, ["get", "deployment", bad, "-n", ns])["spec"]["template"]["spec"]
    requests = (spec["containers"][0].get("resources") or {}).get("requests") or {}
    assert "cpu" not in requests, (
        f"the negative arm is not set up: Kubernetes defaulted a cpu request onto {bad!r} "
        f"({requests!r}), so there is nothing broken left to detect"
    )
    control_requests = (
        _kjson(env, ["get", "deployment", good, "-n", ns])["spec"]["template"]["spec"]
        ["containers"][0]["resources"]["requests"]
    )
    assert control_requests.get("cpu") == _CPU_REQUEST, (
        f"the positive control lost its cpu request: {control_requests!r}"
    )

    # The control's autoscaler must be live before any load: a fresh HPA reports desiredReplicas 0 and
    # no currentMetrics until its first sync, which is neither a bound violation nor a baseline.
    _wait_for(
        lambda: _get_hpa(env, ns, good),
        lambda h: (
            _hpa_cpu_utilization(h) is not None
            and h["status"]["desiredReplicas"] == _MIN
        ),
        timeout_s=_METRICS_TIMEOUT_S,
        interval_s=10,
        desc=(
            f"the control HPA on {good!r} to report a CPU utilization from the {_ADDON} addon "
            f"while leaving its idle Deployment at minReplicas={_MIN}"
        ),
    )

    # Load both, at the same moment, from inside the pods.
    for dep in (good, bad):
        _start_load(env, ns, started[dep])

    # (1) The EFFECT: the control scales out. This is also the clock -- the negative is evaluated
    # at the moment the positive control has demonstrably autoscaled, not after a fixed sleep.
    deadline = time.monotonic() + _SCALE_OUT_TIMEOUT_S
    while True:
        control = _get_hpa(env, ns, good)
        desired = control["status"]["desiredReplicas"]
        ready = _ready_pods(env, ns, f"app={good}")
        assert _MIN <= desired <= _MAX, (
            f"the control HPA wants {desired!r} replicas, outside its own declared bounds "
            f"[{_MIN}, {_MAX}]: status={control['status']!r}"
        )
        if desired > _MIN and len(ready) > _MIN:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the POSITIVE CONTROL never scaled out in {_SCALE_OUT_TIMEOUT_S}s, so the "
                f"negative arm below would prove nothing: the HPA on {good!r} wants {desired!r} "
                f"(min {_MIN}), {len(ready)} pods are Ready, it reports cpu utilization "
                f"{_hpa_cpu_utilization(control)!r} against a {_TARGET_UTILIZATION}% target, and "
                f"its conditions are {control.get('status', {}).get('conditions')!r}"
            )
        time.sleep(2)

    # (2) The ABSENCE: the same load, the same namespace, the same instant -- and no scaling.
    # Waited on the condition APPEARING rather than read once, so "no condition yet" cannot be
    # mistaken for "the controller declined to scale". An HPA that never gets evaluated at all
    # times out here, which is a different and equally reportable failure.
    broken = _wait_for(
        lambda: _get_hpa(env, ns, bad),
        lambda h: _hpa_condition(h, "ScalingActive") is not None,
        timeout_s=_POD_TIMEOUT_S,
        interval_s=10,
        desc=f"the HPA controller to evaluate {bad!r} and report a ScalingActive condition",
    )
    active = _hpa_condition(broken, "ScalingActive")
    assert active["status"] == "False", (
        f"the HPA on {bad!r} claims ScalingActive={active['status']!r} with no cpu request to "
        f"divide by; utilization cannot be computed, so this must be False: {active!r}"
    )
    assert active["reason"] == _BLOCKED_REASON, (
        f"ScalingActive is False for the reason {active['reason']!r}, expected "
        f"{_BLOCKED_REASON!r}; message={active.get('message')!r}"
    )
    assert _hpa_cpu_utilization(broken) is None, (
        f"the HPA on {bad!r} reports a cpu utilization of "
        f"{_hpa_cpu_utilization(broken)!r} -- without a request there is no denominator, so there "
        f"can be no utilization: status={broken['status']!r}"
    )
    # currentReplicas, not desiredReplicas: a blocked HPA never computes a desired count at all, so
    # Kubernetes leaves that field at its zero value. What it DOES report is what it observed.
    assert broken["status"].get("currentReplicas") == _MIN, (
        f"the blocked HPA reports currentReplicas={broken['status'].get('currentReplicas')!r} for a "
        f"target still running {_MIN} replica(s): status={broken['status']!r}"
    )
    bad_deployment = _kjson(env, ["get", "deployment", bad, "-n", ns])
    assert bad_deployment["spec"]["replicas"] == _MIN, (
        f"something rewrote spec.replicas on {bad!r} to "
        f"{bad_deployment['spec']['replicas']!r}: an HPA that cannot read utilization must not "
        f"scale its target at all"
    )
    now = _pods(env, ns, f"app={bad}")
    assert _names(now) == started[bad], (
        f"the pod set of {bad!r} changed from {sorted(started[bad])!r} to "
        f"{sorted(_names(now))!r} while its HPA was blocked"
    )

    # (3) The load was real in BOTH arms, so the absence above is about the missing request.
    usage = _pod_cpu_millicores(env, ns)
    bad_pod = sorted(started[bad])[0]
    assert usage.get(bad_pod, 0) >= _LOAD_FLOOR_M, (
        f"`kubectl top pod` reports {usage.get(bad_pod)!r}m for {bad_pod!r}, under the "
        f"{_LOAD_FLOOR_M}m floor this check's own burn loop must clear -- the absent scale-out "
        f"cannot be attributed to the missing cpu request. Whole reading: {usage!r}"
    )
    good_pod = sorted(started[good])[0]
    assert usage.get(good_pod, 0) >= int(_CPU_REQUEST[:-1]), (
        f"`kubectl top pod` reports {usage.get(good_pod)!r}m for the control pod {good_pod!r} "
        f"(request {_CPU_REQUEST}), so its scale-out cannot be attributed to CPU either. Whole "
        f"reading: {usage!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
