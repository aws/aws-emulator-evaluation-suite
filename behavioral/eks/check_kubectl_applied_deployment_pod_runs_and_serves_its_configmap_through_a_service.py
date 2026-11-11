"""kubectl-applied-deployment-pod-runs-and-serves-its-configmap-through-a-service."""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kubectl-applied-deployment-pod-runs-and-serves-its-configmap-through-a-service"
GROUP = "data-plane"
SERVICES = ["eks"]

_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_NODE_POLICIES = (
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
)
#: Zone IDs real AWS refuses for an EKS control plane.
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_NODE_TYPE = "t3.medium"
_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_FIXTURE_TAGS = {"sim2real": "eks-native-dp", "sim2real:managed": "true"}

_CLUSTER_TIMEOUT_S = 1500
_NODEGROUP_TIMEOUT_S = 900
_DELETE_RETRY_TIMEOUT_S = 900
_ROLLOUT_TIMEOUT_S = 420
_ROLE_PROPAGATION_TIMEOUT_S = 180

# Marks a failure in which the cluster's Kubernetes API did not do its part: kubectl fails in ITS
# OWN wording ("connection refused", "couldn't get current server API group list"), which
# otherwise reads like a local connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
#: The sibling marker for a control-plane state machine that accepted the create and never
#: converged, kept distinct so a query for one never silently returns the other.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


# ===== helpers =====


def _wait_for(fn, pred, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{STATE_MARKER}: timed out after {timeout_s}s waiting for {desc}; last={val!r}"
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


def _create_role(ctx, name, service, managed_policies):
    """Create the role this check needs and register its teardown before anything uses it."""
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust(service),
        Description="sim2real eks native data-plane fidelity check",
        Tags=[{"Key": k, "Value": v} for k, v in sorted(_FIXTURE_TAGS.items())],
    )["Role"]["Arn"]

    def _drop_role():
        for policy_arn in managed_policies:
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_drop_role)
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return arn


def _call_tolerating_role_propagation(fn, desc):
    """Retry the EKS call that consumes a just-created role while IAM is still eventually
    consistent. EKS validates the role SYNCHRONOUSLY and rejects it with
    InvalidParameterException until the role is visible to it; retrying the dependent call
    (rather than sleeping a guessed interval) is what makes that correct."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterException" or "role" not in err.get(
                "Message", ""
            ).lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{desc} was still refused with InvalidParameterException on the role after "
                    f"{_ROLE_PROPAGATION_TIMEOUT_S}s: {exc}"
                ) from exc
            time.sleep(2)


def _fixture_subnets(ctx):
    """Subnets in >=2 AZs that both EKS and the node instance type actually support.

    The AZ is derived, never hardcoded: `describe_instance_type_offerings` says which zones
    offer the type but nothing about zone state, and `describe_availability_zones` says the
    reverse, so both catalogues are intersected. The account-level network subnets are used
    (and created, once, if the account has none) because an EKS control plane plus a managed
    node group needs public egress in two zones, and the default VPC quota is 5.
    """
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
        if z["ZoneName"] in offered and z["ZoneId"] not in _BAD_AZS
    }
    assert usable, (
        f"no available AZ in {ctx.region} offers {_NODE_TYPE!r}; offerings were "
        f"{sorted(offered)!r}"
    )
    subnets = [
        sn
        for page in ec2.get_paginator("describe_subnets").paginate(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )
        for sn in page["Subnets"]
    ]
    by_az = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZone"] in usable:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= 2, (
        f"EKS needs subnets in >=2 AZs that offer {_NODE_TYPE!r}; usable AZs were "
        f"{sorted(usable)!r} and the shared-network subnets cover {sorted(by_az)!r}"
    )
    return [by_az[az] for az in sorted(by_az)][:2]


def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _nodegroup_status(c, cluster, ng):
    try:
        return c.describe_nodegroup(clusterName=cluster, nodegroupName=ng)["nodegroup"][
            "status"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _delete_with_retry(fn, desc):
    """Issue a delete AWS can transiently refuse, retrying the DELETE itself.

    DeleteCluster is refused with ResourceInUseException while EKS still believes an update or a
    dependent object exists, and issuing it once and then polling only the status is how a
    billable control plane leaks while the check still passes: `ctx.on_cleanup` swallows the
    exception and the status never changes because nothing was ever deleted.
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
    """Drain dependents, delete the control plane, and poll it to genuinely gone.

    Polled rather than fire-and-forget because the IAM roles this check also deletes are the
    ones EKS uses to release the cluster's ENIs and security groups: returning before the
    cluster is gone would pull the role out from under its own teardown.
    """
    try:
        for ng in c.list_nodegroups(clusterName=name).get("nodegroups", []):
            _teardown_nodegroup(c, name, ng)
        for addon in c.list_addons(clusterName=name).get("addons", []):
            try:
                c.delete_addon(clusterName=name, addonName=addon, preserve=False)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _delete_with_retry(lambda: _delete_eks_cluster_retrying(c, name), f"delete cluster {name}")
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s == "GONE",
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} fully deleted",
    )


def _run(cmd, env, timeout_s, stdin=None):
    """Run a native-client subprocess, failing with the data-plane marker on its own wording."""
    proc = subprocess.run(
        cmd, env=env, input=stdin, capture_output=True, text=True, timeout=timeout_s
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: {' '.join(cmd[:3])} failed rc={proc.returncode}: "
            f"{(proc.stderr or proc.stdout)[-600:]}"
        )
    return proc.stdout


def _kube_env(ctx, cluster):
    """A kubeconfig for the check's principal, written by the AWS CLI, in a temp dir we remove.

    `ctx.subprocess_env()` is the ONLY safe source of credentials for a child process: the
    check's keys live on the Context and are deliberately never exported, so a bare
    `subprocess.run` would use the ambient credential chain.
    """
    env = dict(ctx.subprocess_env())
    tmp = tempfile.mkdtemp(prefix="sim2real-kubeconfig-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
    env["KUBECONFIG"] = f"{tmp}/config"
    _run(
        [
            "aws", "eks", "update-kubeconfig",
            "--name", cluster,
            "--region", ctx.region,
            "--kubeconfig", env["KUBECONFIG"],
        ],
        env,
        timeout_s=180,
    )
    return env


def _kubectl_json(env, args, timeout_s=120):
    return json.loads(_run(["kubectl", *args, "-o", "json"], env, timeout_s))


def _kubectl_logs(env, ns, pod):
    """Pod logs, tolerating a non-zero rc so a pod that ended badly still reports its output
    instead of the failure being reported as an unrelated kubectl error."""
    proc = subprocess.run(
        ["kubectl", "logs", pod, "-n", ns],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc.stdout if proc.returncode == 0 else f"<kubectl logs rc={proc.returncode}: {proc.stderr[-200:]}>"


def _pod_settled(p):
    """True once the pod has either become Running with a ready container, or given up."""
    st = p.get("status", {})
    if st.get("phase") == "Failed":
        return True
    return st.get("phase") == "Running" and any(
        cs.get("ready") for cs in st.get("containerStatuses", [])
    )


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:native",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A kubectl-applied Deployment runs on a node of the managed node group, and a second pod's
    HTTP GET of its ClusterIP Service returns the exact ConfigMap bytes, with pod IP, Endpoints and
    ClusterIP drawn from the VPC subnets and serviceIpv4Cidr EKS reports."""
    from fidelity_tests_runner import require_tools

    # Every decidable precondition ahead of the first create: a billable control plane must
    # never be provisioned for an answer that was available at import time.
    require_tools("aws", "kubectl")
    c = ctx.client("eks")
    subnets = _fixture_subnets(ctx)

    stem = ctx.unique_name("sim2real-eks-dp-")
    cluster = stem
    nodegroup = f"{stem}-ng"
    body = f"served-by-{stem}"

    cluster_role = _create_role(
        ctx, f"{stem}-cl", "eks.amazonaws.com", (_EKS_CLUSTER_POLICY,)
    )
    _call_tolerating_role_propagation(
        lambda: c.create_cluster(
            name=cluster,
            roleArn=cluster_role,
            resourcesVpcConfig={
                "subnetIds": subnets,
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
            },
            accessConfig={
                "authenticationMode": "API_AND_CONFIG_MAP",
                "bootstrapClusterCreatorAdminPermissions": True,
            },
            tags=dict(_FIXTURE_TAGS),
        ),
        f"create_cluster {cluster}",
    )
    ctx.on_cleanup(lambda: _teardown_cluster(c, cluster))

    described = _wait_for(
        lambda: c.describe_cluster(name=cluster)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {cluster} ACTIVE",
    )
    assert described["status"] == "ACTIVE", (
        f"cluster {cluster} landed in {described['status']!r}; health="
        f"{described.get('health')!r}"
    )
    service_cidr = described["kubernetesNetworkConfig"]["serviceIpv4Cidr"]

    node_role = _create_role(ctx, f"{stem}-node", "ec2.amazonaws.com", _NODE_POLICIES)
    _call_tolerating_role_propagation(
        lambda: c.create_nodegroup(
            clusterName=cluster,
            nodegroupName=nodegroup,
            subnets=subnets,
            nodeRole=node_role,
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            instanceTypes=[_NODE_TYPE],
            amiType="AL2023_x86_64_STANDARD",
            capacityType="ON_DEMAND",
            diskSize=20,
            tags=dict(_FIXTURE_TAGS),
        ),
        f"create_nodegroup {nodegroup}",
    )
    ctx.on_cleanup(lambda: _teardown_nodegroup(c, cluster, nodegroup))
    ng_status = _wait_for(
        lambda: _nodegroup_status(c, cluster, nodegroup),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"nodegroup {nodegroup} ACTIVE",
    )
    assert ng_status == "ACTIVE", (
        f"node group {nodegroup} landed in {ng_status!r}: "
        f"{c.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)['nodegroup'].get('health')!r}"
    )

    env = _kube_env(ctx, cluster)
    ns = stem[:60]
    _run(["kubectl", "create", "namespace", ns], env, timeout_s=120)
    ctx.on_cleanup(
        lambda: subprocess.run(
            ["kubectl", "delete", "namespace", ns, "--wait=false"],
            env=env,
            capture_output=True,
            timeout=120,
        )
    )

    manifest = f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: web-content
data:
  index.html: "{body}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: {_IMAGE}
        command: ["httpd", "-f", "-p", "8080", "-h", "/www"]
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: content
          mountPath: /www
      volumes:
      - name: content
        configMap:
          name: web-content
"""
    _run(["kubectl", "apply", "-n", ns, "-f", "-"], env, timeout_s=180, stdin=manifest)

    def _web_pod():
        items = _kubectl_json(env, ["get", "pods", "-n", ns, "-l", "app=web"])["items"]
        return items[0] if items else {}

    pod = _wait_for(
        _web_pod,
        _pod_settled,
        timeout_s=_ROLLOUT_TIMEOUT_S,
        interval_s=10,
        desc=f"pod of deployment web in {ns} Running and ready",
    )
    status = pod["status"]
    assert status["phase"] == "Running", (
        f"the applied Deployment's pod never reached Running: phase={status['phase']!r} "
        f"conditions={status.get('conditions')!r}"
    )
    container = status["containerStatuses"][0]
    assert container["ready"] is True and container["restartCount"] == 0, (
        f"pod container is not cleanly ready: ready={container['ready']!r} "
        f"restartCount={container['restartCount']!r} state={container.get('state')!r}"
    )

    # The Kubernetes node the scheduler chose must be one the EKS node group owns: the label is
    # how the two planes' names for the same machine are tied together.
    node = _kubectl_json(env, ["get", "node", pod["spec"]["nodeName"]])
    assert node["metadata"]["labels"].get("eks.amazonaws.com/nodegroup") == nodegroup, (
        f"pod landed on node {pod['spec']['nodeName']!r} whose nodegroup label is "
        f"{node['metadata']['labels'].get('eks.amazonaws.com/nodegroup')!r}, "
        f"not the node group {nodegroup!r} this check created"
    )

    # The ConfigMap read back through kubectl, field for field.
    cm = _kubectl_json(env, ["get", "configmap", "web-content", "-n", ns])
    assert cm["data"] == {"index.html": body}, (
        f"ConfigMap read back as {cm.get('data')!r}, not the applied "
        f"{{'index.html': {body!r}}}"
    )

    _run(
        [
            "kubectl", "expose", "deployment", "web",
            "-n", ns,
            "--name", "web",
            "--port", "8080",
            "--target-port", "8080",
        ],
        env,
        timeout_s=120,
    )
    svc = _kubectl_json(env, ["get", "service", "web", "-n", ns])
    cluster_ip = svc["spec"]["clusterIP"]
    assert ipaddress.ip_address(cluster_ip) in ipaddress.ip_network(service_cidr), (
        f"Service ClusterIP {cluster_ip!r} is outside the serviceIpv4Cidr "
        f"{service_cidr!r} that DescribeCluster advertises for this cluster"
    )

    pod_ip = status["podIP"]
    ec2 = ctx.client("ec2")
    subnet_cidrs = [
        sn["CidrBlock"]
        for page in ec2.get_paginator("describe_subnets").paginate(SubnetIds=subnets)
        for sn in page["Subnets"]
    ]
    assert any(
        ipaddress.ip_address(pod_ip) in ipaddress.ip_network(cidr)
        for cidr in subnet_cidrs
    ), (
        f"pod IP {pod_ip!r} is in none of the cluster's VPC subnet CIDRs {subnet_cidrs!r}: "
        f"the address did not come from the VPC CNI"
    )

    def _slice_addresses():
        doc = _kubectl_json(
            env,
            [
                "get", "endpointslices",
                "-n", ns,
                "-l", "kubernetes.io/service-name=web",
            ],
        )
        return sorted(
            addr
            for item in doc.get("items", [])
            for ep in item.get("endpoints", [])
            if ep.get("conditions", {}).get("ready")
            for addr in ep.get("addresses", [])
        )

    backends = _wait_for(
        _slice_addresses,
        lambda addrs: bool(addrs),
        timeout_s=120,
        interval_s=5,
        desc=f"an EndpointSlice for Service web in {ns} to list a ready backend",
    )
    assert backends == [pod_ip], (
        f"the Service's EndpointSlice lists ready backends {backends!r}, not exactly the "
        f"running pod's own IP {pod_ip!r}"
    )

    # A SECOND pod fetches the Service by DNS name: the only thing that can produce this output
    # is CoreDNS resolving the name, kube-proxy load-balancing to the pod, and busybox httpd
    # serving the file the kubelet projected from the ConfigMap.
    _run(
        [
            "kubectl", "run", "client",
            "-n", ns,
            "--image", _IMAGE,
            "--restart", "Never",
            "--command", "--",
            "sh", "-c",
            # A bounded retry inside the pod, because the thing being waited for is observable:
            # CoreDNS answering for the Service name. It exits on the first success, so the
            # pod's log holds exactly the served body and nothing else.
            f"i=0; while [ $i -lt 6 ]; do "
            f"wget -q -T 10 -O - http://web.{ns}.svc.cluster.local:8080/ && exit 0; "
            f"i=$((i+1)); sleep 5; done; exit 1",
        ],
        env,
        timeout_s=180,
    )
    client_phase = _wait_for(
        lambda: _kubectl_json(env, ["get", "pod", "client", "-n", ns])["status"]["phase"],
        lambda p: p in ("Succeeded", "Failed"),
        timeout_s=_ROLLOUT_TIMEOUT_S,
        interval_s=5,
        desc=f"client pod in {ns} to terminate",
    )
    logs = _kubectl_logs(env, ns, "client")
    assert client_phase == "Succeeded", (
        f"in-cluster client pod ended {client_phase!r} instead of Succeeded; its output was "
        f"{logs!r} (no HTTP response was served through the Service)"
    )
    assert logs.strip() == body, (
        f"the in-cluster GET of http://web.{ns}.svc.cluster.local:8080/ returned "
        f"{logs.strip()!r}, not the {body!r} the ConfigMap supplied"
    )


def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
