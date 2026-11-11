"""eks-deployment-pod-is-reachable-through-a-cluster-service."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "eks-deployment-pod-is-reachable-through-a-cluster-service"
GROUP = 'data-plane'
SERVICES = ['eks']

# The shared cluster fixture. An EKS control plane takes ~10 minutes to create and a managed
# node group several more, so every data-plane check in this suite adopts ONE cluster under a
# deterministic name and creates it only when it is absent. Teardown is registered ONLY by the
# check that actually created it, so a run leaks nothing and a run that finds the fixture
# already there pays none of the provisioning cost.
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
# AZs that do not offer EKS control planes; CreateCluster rejects a subnet set including one.
_BAD_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "ga-depth-eks"}

_CLUSTER_TIMEOUT_S = 1500
_DELETE_RETRY_TIMEOUT_S = 900
_NODEGROUP_TIMEOUT_S = 900
_NODE_READY_TIMEOUT_S = 600
_ROLLOUT_TIMEOUT_S = 420
_ROLE_PROPAGATION_TIMEOUT_S = 120

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_BODY = "sim2real-eks-clusterip-body-7f3c"


# ===== helpers =====


def _error_code(fn):
    """Call fn; return the botocore error Code. Raises if the call SUCCEEDS, because an
    unexpected success is the strongest signal available and must not read as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to fail but it succeeded")


def _wait_for(fn, pred, *, timeout_s, interval_s, desc):
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
    """Create-or-reuse the fixture's IAM role. Returns (arn, created)."""
    iam = ctx.client("iam")
    created = False
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="sim2real ga-depth eks shared fixture",
        )["Role"]["Arn"]
        created = True
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
    return arn, created


def _call_tolerating_role_propagation(fn, created, *, timeout_s=_ROLE_PROPAGATION_TIMEOUT_S):
    """Call fn(), which consumes a roleArn this run just created, retrying on
    InvalidParameterException within a bounded budget.

    IAM is eventually consistent and EKS validates roleArn synchronously, so the very next
    create_cluster/create_nodegroup call after create_role can be refused even though the role
    now exists. Only retried when THIS call created the role -- an adopted, pre-existing role
    is already propagated, and retrying then would only hide a real InvalidParameterException.
    """
    if not created:
        return fn()
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _fixture_subnets(ctx):
    """Default-VPC subnets in EKS-supported AZs that actually offer the node instance type.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone state,
    and describe_availability_zones says nothing about instance types.
    """
    ec2 = ctx.client("ec2")
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_NODE_TYPE]}, {"Name": "location", "Values": ctx.network().availability_zones}],
        )["InstanceTypeOfferings"]
    }
    usable = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered and z["ZoneName"] not in _BAD_AZS
    }
    assert usable, (
        f"no available AZ in {ctx.region} offers {_NODE_TYPE!r}; offerings were "
        f"{sorted(offered)!r}"
    )
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZone"] in usable:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            f"EKS needs subnets in >=2 supported AZs; the run's shared network offers {sorted(by_az)!r}"
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
    """Issue a delete AWS can transiently refuse, retrying it within a bounded budget.

    DeleteCluster can answer ResourceInUseException ("currently has an update in progress") on an
    ACTIVE cluster with no dependents while ListUpdates is empty, so the delete itself is retried.
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
    """Drain dependents then delete the control plane, polling it to actually gone.

    DeleteCluster is REFUSED while any node group, Fargate profile or EKS-managed addon still
    exists, so firing them in the wrong order (or not polling) leaks a control plane that bills
    per hour forever.
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
        desc=f"cluster {name} fully deleted",
    )


def _adopt_or_create_cluster(ctx):
    """Return (endpoint, ca_pem) for the shared ACTIVE cluster.

    Teardown is registered ONLY when this call actually created the cluster, so an adopting
    check never deletes a fixture it did not build and a creating check never leaks one.
    """
    c = ctx.client("eks")
    role_arn, role_created = _ensure_role(
        ctx, _CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY]
    )
    try:
        _call_tolerating_role_propagation(
            lambda: c.create_cluster(
                name=_SHARED_CLUSTER,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": _fixture_subnets(ctx),
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                accessConfig={
                    "authenticationMode": "API_AND_CONFIG_MAP",
                    "bootstrapClusterCreatorAdminPermissions": True,
                },
                tags=dict(_FIXTURE_TAGS),
            ),
            role_created,
        )
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
        f"shared cluster landed in {cluster['status']!r}; health={cluster.get('health')!r}"
    )
    ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    assert ca_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"certificateAuthority.data did not decode to a PEM certificate: {ca_pem[:60]!r}"
    )
    return cluster["endpoint"], ca_pem


def _adopt_or_create_nodegroup(ctx):
    """Ensure the shared managed node group is ACTIVE. Teardown only if we created it."""
    c = ctx.client("eks")
    node_role_arn, node_role_created = _ensure_role(
        ctx, _NODE_ROLE, "ec2.amazonaws.com", _NODE_POLICIES
    )
    try:
        _call_tolerating_role_propagation(
            lambda: c.create_nodegroup(
                clusterName=_SHARED_CLUSTER,
                nodegroupName=_SHARED_NODEGROUP,
                subnets=_fixture_subnets(ctx),
                nodeRole=node_role_arn,
                scalingConfig={"minSize": 2, "maxSize": 2, "desiredSize": 2},
                instanceTypes=[_NODE_TYPE],
                amiType="AL2023_x86_64_STANDARD",
                capacityType="ON_DEMAND",
                diskSize=20,
                tags=dict(_FIXTURE_TAGS),
            ),
            node_role_created,
        )
        ctx.on_cleanup(
            lambda: _teardown_nodegroup(c, _SHARED_CLUSTER, _SHARED_NODEGROUP)
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceInUseException":
            raise
    status = _wait_for(
        lambda: _nodegroup_status(c, _SHARED_CLUSTER, _SHARED_NODEGROUP),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"nodegroup {_SHARED_NODEGROUP} ACTIVE",
    )
    assert status == "ACTIVE", (
        f"shared node group landed in {status!r}: "
        f"{c.describe_nodegroup(clusterName=_SHARED_CLUSTER, nodegroupName=_SHARED_NODEGROUP)['nodegroup'].get('health')!r}"
    )


def _k8s_token(ctx, cluster_name, *, ttl_s=900):
    """Mint the EKS Kubernetes bearer token for the CURRENT caller.

    The API server authenticates with the aws-iam-authenticator scheme: the token is
    "k8s-aws-v1." + unpadded base64url of a PRESIGNED sts:GetCallerIdentity URL carrying the
    cluster name as a SIGNED x-k8s-aws-id header. Minted fresh per request (presigning is local
    and costs no round trip) so a long poll can never outlive the token's TTL.
    """
    # A client of its own per cluster, so the signed x-k8s-aws-id header never reaches other calls.
    sts = ctx.client(
        "sts",
        endpoint_url=ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com"),
        config=Config(user_agent_extra=f"k8s-aws-id/{cluster_name}"),
    )
    sts.meta.events.register(
        "before-sign.sts.GetCallerIdentity",
        lambda request, **kwargs: request.headers.add_header("x-k8s-aws-id", cluster_name),
        unique_id=f"k8s-aws-id/{cluster_name}",
    )
    url = sts.generate_presigned_url(
        "get_caller_identity", Params={}, ExpiresIn=ttl_s, HttpMethod="GET"
    )
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode("utf-8")).decode(
        "utf-8"
    ).rstrip("=")


def _k8s(ctx, conn, method, path, *, body=None, timeout_s=60):
    """Request the cluster's Kubernetes API server; returns (status, raw bytes).

    TLS trusts ONLY the CA DescribeCluster advertised, so a server that does not present that
    chain fails the handshake instead of being silently accepted.
    """
    base, ca_pem = conn
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.load_verify_locations(cadata=ca_pem)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {_k8s_token(ctx, _SHARED_CLUSTER)}",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = _routed_request(ctx,
        base.rstrip("/") + path, method=method, data=data, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ssl_ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _k8s_json(ctx, conn, method, path, *, body=None, expect=(200, 201)):
    status, raw = _k8s(ctx, conn, method, path, body=body)
    assert status in expect, (
        f"{method} {path} on the Kubernetes API returned {status}, expected one of {expect}: "
        f"{raw[:400]!r}"
    )
    return json.loads(raw)


def _delete_namespace(ctx, conn, ns):
    """Deleting the namespace reclaims every object in it (Deployment, Service, pods)."""
    _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}", timeout_s=90)


def _between(text, begin, end):
    """The bytes a pod printed between two markers, parsed structurally rather than by index
    arithmetic so a retry line before the marker cannot leak into the payload."""
    assert begin in text and end in text, (
        f"pod output is missing its {begin!r}/{end!r} markers: {text!r}"
    )
    return text.split(begin, 1)[1].split(end, 1)[0]


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """A Deployment applied through the Kubernetes API reaches its full ready-replica count on
    the managed node group's nodes, its Endpoints match the pods' IPs, and an in-cluster HTTP GET
    of the ClusterIP Service returns the exact body the workload serves."""
    conn = _adopt_or_create_cluster(ctx)
    _adopt_or_create_nodegroup(ctx)
    c = ctx.client("eks")

    ns = ctx.unique_name("sim2real-dp-")[:63].lower()
    app = "sim2real-web"
    svc = "sim2real-web"

    _k8s_json(
        ctx, conn, "POST", "/api/v1/namespaces",
        body={"apiVersion": "v1", "kind": "Namespace",
              "metadata": {"name": ns, "labels": {"sim2real": "ga-depth-eks"}}},
    )
    ctx.on_cleanup(lambda: _delete_namespace(ctx, conn, ns))

    _k8s_json(
        ctx, conn, "POST", f"/apis/apps/v1/namespaces/{ns}/deployments",
        body={
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": app},
            "spec": {
                "replicas": 2,
                "selector": {"matchLabels": {"app": app}},
                "template": {
                    "metadata": {"labels": {"app": app}},
                    "spec": {"containers": [{
                        "name": "web",
                        "image": _IMAGE,
                        "command": ["sh", "-c",
                                    "mkdir -p /www && printf '%s' \"$BODY\" > /www/index.html"
                                    " && exec httpd -f -p 8080 -h /www"],
                        "env": [{"name": "BODY", "value": _BODY}],
                        "ports": [{"containerPort": 8080}],
                    }]},
                },
            },
        },
    )

    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/services",
        body={
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": svc},
            "spec": {"type": "ClusterIP", "selector": {"app": app},
                     "ports": [{"port": 8080, "targetPort": 8080}]},
        },
    )

    # (1) The Deployment reaches its FULL ready-replica count. readyReplicas counts pods whose
    #     container passed its readiness gate, which no control-plane response can fake.
    dep = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/apis/apps/v1/namespaces/{ns}/deployments/{app}"),
        lambda d: d.get("status", {}).get("readyReplicas") == 2,
        timeout_s=_ROLLOUT_TIMEOUT_S,
        interval_s=6,
        desc=f"deployment {app} readyReplicas==2",
    )
    assert dep["status"]["availableReplicas"] == 2, (
        f"the Deployment reported readyReplicas==2 but availableReplicas="
        f"{dep['status'].get('availableReplicas')!r}: {dep['status']!r}"
    )

    pods = _k8s_json(
        ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods?labelSelector=app%3D{app}"
    )["items"]
    assert [p["status"]["phase"] for p in pods] == ["Running", "Running"], (
        f"expected two Running pods, got "
        f"{[(p['metadata']['name'], p['status']['phase']) for p in pods]!r}"
    )

    # (2) The pods landed on real nodes that the shared managed node group owns -- the EKS
    #     control plane is the authority for which nodes those are, so this ties the Kubernetes
    #     placement back to the EKS API's own view of its compute.
    ng_nodes = {
        n["metadata"]["name"]
        for n in _k8s_json(
            ctx, conn, "GET",
            "/api/v1/nodes?labelSelector=eks.amazonaws.com%2Fnodegroup%3D" + _SHARED_NODEGROUP,
        )["items"]
    }
    placed = {p["spec"].get("nodeName") for p in pods}
    assert placed <= ng_nodes and None not in placed, (
        f"pods were placed on {sorted(str(p) for p in placed)!r}, which is not a subset of the "
        f"nodes the {_SHARED_NODEGROUP!r} node group owns ({sorted(ng_nodes)!r})"
    )

    # (3) The Service's Endpoints really name those pods' CNI addresses. A Service with a
    #     plausible ClusterIP and an empty or invented backend set fails here.
    pod_ips = sorted(p["status"]["podIP"] for p in pods)
    endpoints = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/endpoints/{svc}"),
        lambda e: sorted(
            a["ip"] for s in e.get("subsets", []) for a in s.get("addresses", [])
        ) == pod_ips,
        timeout_s=120,
        interval_s=5,
        desc=f"endpoints for {svc} == pod IPs {pod_ips!r}",
    )
    assert sorted(
        a["ip"] for s in endpoints["subsets"] for a in s["addresses"]
    ) == pod_ips, f"{endpoints!r} vs pod ips {pod_ips!r}"

    # (4) THE OBSERVATION: a second pod resolves the Service by DNS name and reads the body the
    #     workload serves. The retry loop is bounded and its exhaustion is a FAILURE (exit 7),
    #     never a skip -- "provisioned but unconnectable" is a fidelity defect, not an
    #     environment limit.
    client = "sim2real-client"
    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods",
        body={
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": client},
            "spec": {
                "restartPolicy": "Never",
                "containers": [{
                    "name": "client", "image": _IMAGE,
                    "command": ["sh", "-c",
                                f"for i in $(seq 1 40); do "
                                f"if out=$(wget -qO- http://{svc}.{ns}.svc.cluster.local:8080/ "
                                f"2>/dev/null); then "
                                f"printf 'BEGINX%sENDX' \"$out\"; exit 0; "
                                f"fi; sleep 3; done; exit 7"],
                }],
            },
        },
    )
    pod = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{client}"),
        lambda p: p["status"]["phase"] in ("Succeeded", "Failed"),
        timeout_s=_ROLLOUT_TIMEOUT_S,
        interval_s=5,
        desc=f"client pod {client} terminal",
    )
    status, log = _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{client}/log")
    assert status == 200, f"could not read client pod logs: {status} {log[:300]!r}"
    text = log.decode("utf-8", "replace")
    exit_code = pod["status"]["containerStatuses"][0]["state"]["terminated"]["exitCode"]
    assert exit_code == 0, (
        f"the in-cluster client exited {exit_code!r} (7 means it never reached the Service "
        f"within its retry budget); phase={pod['status']['phase']!r} log={text!r}"
    )
    assert _between(text, "BEGINX", "ENDX") == _BODY, (
        f"the in-cluster GET of http://{svc}.{ns}.svc.cluster.local:8080/ returned "
        f"{_between(text, 'BEGINX', 'ENDX')!r}, want {_BODY!r} (full log {text!r})"
    )

    # (5) The EKS API and the cluster agree the node group is still the compute behind all of
    #     this, which is what makes the placement assertion in (2) meaningful.
    ng = c.describe_nodegroup(
        clusterName=_SHARED_CLUSTER, nodegroupName=_SHARED_NODEGROUP
    )["nodegroup"]
    assert ng["status"] == "ACTIVE", f"{ng['status']!r} after the workload ran: {ng!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
