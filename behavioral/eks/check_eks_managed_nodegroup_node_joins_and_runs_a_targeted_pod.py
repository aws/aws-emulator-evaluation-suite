"""eks-managed-nodegroup-node-joins-and-runs-a-targeted-pod."""
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


CHECK = "eks-managed-nodegroup-node-joins-and-runs-a-targeted-pod"
GROUP = 'data-plane'
SERVICES = ['eks']

# The shared cluster fixture. Adopted under a deterministic name; teardown is registered ONLY by the
# check that actually created it.
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
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "ga-depth-eks"}

_CLUSTER_TIMEOUT_S = 1500
_DELETE_RETRY_TIMEOUT_S = 900
_NODEGROUP_TIMEOUT_S = 900
_POD_TIMEOUT_S = 420

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_SENTINEL = "sim2real-eks-node-sentinel-4b1e"


# ===== helpers =====


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
    """Create-or-reuse the fixture's IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="sim2real ga-depth eks shared fixture",
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


def _call_tolerating_role_propagation(fn, *, timeout_s=90, interval_s=10):
    """Issue an EKS create call that validates a just-created IAM role's trust policy.

    IAM is eventually consistent and EKS validates roleArn synchronously, so the very first
    attempt can spuriously fail with InvalidParameterException even though the role and its
    policy are already correct -- retry the call itself (bounded), never a blind pre-sleep.
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
    """Default-VPC subnets in EKS-supported AZs that actually offer the node instance type."""
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
        if z["ZoneName"] in offered and z["ZoneId"] not in _BAD_AZS
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
    """Drain dependents then delete the control plane, polling it to actually gone."""
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
    """Return (endpoint, ca_pem) for the shared ACTIVE cluster; teardown only if we made it."""
    c = ctx.client("eks")
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
    status = _wait_for(
        lambda: _nodegroup_status(c, _SHARED_CLUSTER, _SHARED_NODEGROUP),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"nodegroup {_SHARED_NODEGROUP} ACTIVE",
    )
    assert status == "ACTIVE", f"shared node group landed in {status!r}"


def _k8s_token(ctx, cluster_name, *, ttl_s=900):
    """Mint the EKS Kubernetes bearer token for the CURRENT caller (k8s-aws-v1 scheme)."""
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
    """Request the cluster's Kubernetes API server, trusting ONLY the advertised CA."""
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
    _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}", timeout_s=90)


def _asg_instance_ids(ctx, asg_name):
    """Every instance the node group's Auto Scaling group owns, fully paginated."""
    asg = ctx.client("autoscaling")
    ids = set()
    token = None
    while True:
        kwargs = {"AutoScalingGroupNames": [asg_name], "MaxRecords": 100}
        if token:
            kwargs["NextToken"] = token
        page = asg.describe_auto_scaling_groups(**kwargs)
        for group in page.get("AutoScalingGroups", []):
            ids.update(i["InstanceId"] for i in group.get("Instances", []))
        token = page.get("NextToken")
        if not token:
            return ids


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """A managed node group's Ready nodes have exactly the providerIDs of the EC2 instances its
    Auto Scaling group owns (both directions) and its declared instance type, and a pod pinned to
    one node by nodeSelector runs there and prints a sentinel read back from its logs."""
    conn = _adopt_or_create_cluster(ctx)
    _adopt_or_create_nodegroup(ctx)
    c = ctx.client("eks")

    ng = c.describe_nodegroup(
        clusterName=_SHARED_CLUSTER, nodegroupName=_SHARED_NODEGROUP
    )["nodegroup"]
    asgs = [g["name"] for g in ng["resources"]["autoScalingGroups"]]
    assert len(asgs) == 1, (
        f"expected exactly one Auto Scaling group behind the node group, got {asgs!r}"
    )
    want_instances = _asg_instance_ids(ctx, asgs[0])
    assert len(want_instances) == ng["scalingConfig"]["desiredSize"], (
        f"the ASG {asgs[0]!r} holds {sorted(want_instances)!r}, but DescribeNodegroup declares "
        f"desiredSize={ng['scalingConfig']['desiredSize']!r}"
    )

    # (1) Every one of those instances registered as a Ready Kubernetes node, and no others did.
    nodes = _wait_for(
        lambda: _k8s_json(
            ctx, conn, "GET",
            "/api/v1/nodes?labelSelector=eks.amazonaws.com%2Fnodegroup%3D" + _SHARED_NODEGROUP,
        )["items"],
        lambda items: len(items) == len(want_instances) and all(
            any(cond["type"] == "Ready" and cond["status"] == "True"
                for cond in n["status"]["conditions"])
            for n in items
        ),
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=15,
        desc=f"{len(want_instances)} Ready nodes labelled for {_SHARED_NODEGROUP}",
    )
    joined = {n["spec"]["providerID"].rsplit("/", 1)[-1] for n in nodes}
    assert joined == want_instances, (
        f"the nodes registered with the cluster name instances {sorted(joined)!r} but the node "
        f"group's ASG owns {sorted(want_instances)!r} -- an ACTIVE node group whose instances "
        f"never joined is exactly what DescribeNodegroup cannot distinguish"
    )
    for n in nodes:
        ready = [c2["status"] for c2 in n["status"]["conditions"] if c2["type"] == "Ready"]
        assert ready == ["True"], (
            f"node {n['metadata']['name']!r} Ready condition is {ready!r}: "
            f"{n['status']['conditions']!r}"
        )
        assert n["metadata"]["labels"]["node.kubernetes.io/instance-type"] == _NODE_TYPE, (
            f"the kubelet on {n['metadata']['name']!r} reports instance type "
            f"{n['metadata']['labels'].get('node.kubernetes.io/instance-type')!r}, but "
            f"CreateNodegroup asked for {ng['instanceTypes']!r}"
        )

    target = sorted(n["metadata"]["name"] for n in nodes)[0]

    # (2) The scheduler honours a nodeSelector naming that node, and the container really runs.
    ns = ctx.unique_name("sim2real-ng-")[:63].lower()
    pod = "sim2real-pinned"
    _k8s_json(
        ctx, conn, "POST", "/api/v1/namespaces",
        body={"apiVersion": "v1", "kind": "Namespace",
              "metadata": {"name": ns, "labels": {"sim2real": "ga-depth-eks"}}},
    )
    ctx.on_cleanup(lambda: _delete_namespace(ctx, conn, ns))

    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods",
        body={
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": pod},
            "spec": {
                "restartPolicy": "Never",
                "nodeSelector": {"kubernetes.io/hostname": target},
                "containers": [{
                    "name": "sentinel", "image": _IMAGE,
                    "command": ["sh", "-c", f"printf '%s' '{_SENTINEL}'"],
                }],
            },
        },
    )
    placed = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}"),
        lambda p: p["status"]["phase"] in ("Succeeded", "Failed"),
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=f"pod {pod} terminal",
    )
    assert placed["status"]["phase"] == "Succeeded", (
        f"the pinned pod ended {placed['status']['phase']!r}: {placed['status']!r}"
    )
    assert placed["spec"]["nodeName"] == target, (
        f"the scheduler placed the pod on {placed['spec'].get('nodeName')!r} despite a "
        f"nodeSelector naming {target!r}"
    )
    status, log = _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}/log")
    assert status == 200, f"could not read the pinned pod's logs: {status} {log[:300]!r}"
    assert log.decode("utf-8", "replace") == _SENTINEL, (
        f"the container on {target!r} printed {log[:200]!r}, want {_SENTINEL!r} -- an EKS "
        f"emulator can record a scheduled pod without ever executing its command"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
