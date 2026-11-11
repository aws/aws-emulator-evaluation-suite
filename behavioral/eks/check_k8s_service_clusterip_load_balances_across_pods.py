"""k8s-service-clusterip-load-balances-across-pods."""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "k8s-service-clusterip-load-balances-across-pods"
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

_SENTINEL = "sim2real-lb-v1"
_REPLICAS = 2
_REQUESTS = 20

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


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """A ClusterIP Service carries traffic: its IP lies in the service CIDR the EKS API advertises, its
    Ready endpoints are exactly the pods' IPs, and in-cluster GETs of its DNS name from a second pod
    are answered by every backend.
    """
    from fidelity_tests_runner import require_tools

    require_tools("aws", "kubectl")

    env, node_names = _fixture(ctx)
    cluster = ctx.client("eks").describe_cluster(name=_SHARED_CLUSTER)["cluster"]
    service_cidr = cluster["kubernetesNetworkConfig"]["serviceIpv4Cidr"]
    ns = _namespace(ctx, env)
    dep, svc, client = "sim2real-lb", "sim2real-lb-svc", "sim2real-client"
    sel = "app=sim2real-lb"

    _kapply(env, ns, [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": dep, "labels": {"app": "sim2real-lb"}},
            "spec": {
                "replicas": _REPLICAS,
                "selector": {"matchLabels": {"app": "sim2real-lb"}},
                "template": _server_pod_template(_SENTINEL, {"app": "sim2real-lb"}),
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": svc},
            "spec": {
                "type": "ClusterIP",
                "selector": {"app": "sim2real-lb"},
                "ports": [{"port": 8080, "targetPort": 8080, "protocol": "TCP"}],
            },
        },
        _client_pod(client),
    ])

    pods = _wait_for(
        lambda: _pods(env, ns, sel),
        lambda ps: len(ps) == _REPLICAS and all(_is_ready(p) for p in ps),
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=f"{_REPLICAS} Running+Ready backend pods",
    )
    _wait_for(
        lambda: _kjson(env, ["get", "pod", client, "-n", ns])["status"].get("phase"),
        lambda ph: ph == "Running",
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=f"the in-cluster client pod {client} Running",
    )
    pod_ips = {p["status"]["podIP"] for p in pods}
    pod_names = {p["metadata"]["name"] for p in pods}

    # (1) The ClusterIP came out of the range the EKS API advertises for this cluster.
    s = _kjson(env, ["get", "service", svc, "-n", ns])
    cluster_ip = s["spec"]["clusterIP"]
    net = ipaddress.ip_network(service_cidr)
    assert ipaddress.ip_address(cluster_ip) in net, (
        f"the Service got ClusterIP {cluster_ip!r}, which is outside the serviceIpv4Cidr "
        f"{service_cidr!r} that DescribeCluster advertises for {_SHARED_CLUSTER!r}"
    )
    assert cluster_ip not in pod_ips, (
        f"the ClusterIP {cluster_ip!r} is one of the pod IPs {sorted(pod_ips)!r} -- a virtual IP "
        f"is not a backend address"
    )

    # (2) kube-proxy's programmed backends are exactly the pods, in both directions.
    ready = _wait_for(
        lambda: _ready_endpoint_ips(env, ns, svc),
        lambda ips: ips == pod_ips,
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=f"the Service's Ready endpoint addresses to equal the pod IPs {sorted(pod_ips)!r}",
    )
    assert ready == pod_ips, (
        f"the Service's Ready endpoints are {sorted(ready)!r} but the pods report "
        f"{sorted(pod_ips)!r} -- an endpoint set that is not exactly the pods means either an "
        f"invented backend or a missing one"
    )

    # (3) Real traffic: every response comes from a backend, and every backend answers.
    url = f"http://{svc}.{ns}.svc.cluster.local:8080/index.html"
    out = _kexec(
        env, ns, client,
        ["sh", "-c", f"for i in $(seq 1 {_REQUESTS}); do wget -q -T 5 -O- {url} || exit 1; "
                     f"printf '\\n'; done"],
        timeout=180,
    )
    bodies = [ln for ln in out.splitlines() if ln.strip()]
    assert len(bodies) == _REQUESTS, (
        f"{len(bodies)} of {_REQUESTS} in-cluster GETs of {url} produced a body: {out!r}"
    )
    responders = set()
    for body in bodies:
        parts = body.split(" ")
        assert len(parts) == 2 and parts[0] == _SENTINEL, (
            f"a GET through the Service returned {body!r}, want {_SENTINEL!r} plus the serving "
            f"pod's name -- the payload is written by the container itself"
        )
        assert parts[1] in pod_names, (
            f"a GET through the Service was answered by {parts[1]!r}, which is not one of the "
            f"Deployment's pods {sorted(pod_names)!r}"
        )
        responders.add(parts[1])
    assert responders == pod_names, (
        f"{_REQUESTS} connections through the ClusterIP were answered by {sorted(responders)!r}, "
        f"but the Service has {len(pod_names)} Ready backends {sorted(pod_names)!r} -- an "
        f"emulator that serves every request from one pod passes a reachability test and fails "
        f"load balancing"
    )
    placed = {p["spec"]["nodeName"] for p in pods}
    assert placed <= set(node_names), (
        f"the backend pods claim nodes {sorted(placed)!r} outside the Ready set {node_names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
