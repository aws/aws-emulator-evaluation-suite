"""eks-delete-cluster-with-a-live-node-is-rejected."""
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


CHECK = "eks-delete-cluster-with-a-live-node-is-rejected"
GROUP = 'lifecycle'
SERVICES = ['eks']

# Unlike the rest of this suite this check CANNOT adopt the shared cluster fixture, because its
# positive control deletes the cluster. It therefore owns everything it creates and pays the full
# provisioning cost on every run (about 465 s control plane + 123 s node group on AWS).
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
_NODE_READY_TIMEOUT_S = 600



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


def _retry_on_role_propagation(fn, *, desc, timeout_s=120, interval_s=10):
    """Retry fn() while EKS reports the just-created IAM role as invalid.

    Measured on real AWS: CreateCluster/CreateNodegroup validate roleArn synchronously against
    IAM, which is eventually consistent, so a role created moments earlier can still be refused
    with InvalidParameterException naming the role. That is retried within a bounded deadline
    rather than assumed away with a fixed sleep.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code != "InvalidParameterException" or "role" not in message.lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{desc} was still refused with InvalidParameterException after "
                    f"{timeout_s}s waiting for IAM role propagation: {exc}"
                ) from exc
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
    """Drain dependents then delete the control plane, polling it to actually gone.

    Status-aware on purpose: this check's own positive control already issues the DeleteCluster
    that succeeds, so by the time cleanup runs the cluster is usually DELETING. Calling
    DeleteCluster again on a DELETING cluster is refused, so only the gone-poll runs then.
    """
    status = _cluster_status(c, name)
    if status == "GONE":
        return
    if status != "DELETING":
        _drain_and_delete(c, name)
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s == "GONE",
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} fully deleted",
    )


def _drain_and_delete(c, name):
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


def _provision_cluster(ctx):
    """Create a cluster owned solely by this check and return (name, (endpoint, ca_pem))."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-dep-")[:100]
    role_arn = _ensure_role(ctx, _CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    subnet_ids = _fixture_subnets(ctx)
    _retry_on_role_propagation(
        lambda: c.create_cluster(
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
            tags=dict(_FIXTURE_TAGS),
        ),
        desc=f"create_cluster {name}",
    )
    # Registered BEFORE the first wait, so a timeout cannot leak a billable control plane.
    ctx.on_cleanup(lambda: _teardown_cluster(c, name))
    cluster = _wait_for(
        lambda: c.describe_cluster(name=name)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", (
        f"cluster {name} landed in {cluster['status']!r}; health={cluster.get('health')!r}"
    )
    ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    assert ca_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"certificateAuthority.data did not decode to a PEM certificate: {ca_pem[:60]!r}"
    )
    return name, (cluster["endpoint"], ca_pem)


def _provision_nodegroup(ctx, cluster):
    """Create a ONE-node managed node group on *cluster* and wait for it to be ACTIVE."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-ng-")[:63]
    node_role_arn = _ensure_role(ctx, _NODE_ROLE, "ec2.amazonaws.com", _NODE_POLICIES)
    subnet_ids = _fixture_subnets(ctx)
    _retry_on_role_propagation(
        lambda: c.create_nodegroup(
            clusterName=cluster,
            nodegroupName=name,
            subnets=subnet_ids,
            nodeRole=node_role_arn,
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            instanceTypes=[_NODE_TYPE],
            amiType="AL2023_x86_64_STANDARD",
            capacityType="ON_DEMAND",
            diskSize=20,
            tags=dict(_FIXTURE_TAGS),
        ),
        desc=f"create_nodegroup {name}",
    )
    # LIFO: registered after the cluster's teardown, so it runs BEFORE it -- DeleteCluster is
    # refused while the node group exists, which is the very thing this check is about.
    ctx.on_cleanup(lambda: _teardown_nodegroup(c, cluster, name))
    status = _wait_for(
        lambda: _nodegroup_status(c, cluster, name),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"nodegroup {name} ACTIVE",
    )
    assert status == "ACTIVE", (
        f"node group {name} landed in {status!r}: "
        f"{c.describe_nodegroup(clusterName=cluster, nodegroupName=name)['nodegroup'].get('health')!r}"
    )
    return name


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


def _k8s(ctx, cluster, conn, method, path, *, timeout_s=60):
    """Request the cluster's Kubernetes API server, trusting ONLY the advertised CA."""
    base, ca_pem = conn
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.load_verify_locations(cadata=ca_pem)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {_k8s_token(ctx, cluster)}",
    }
    req = _routed_request(ctx, base.rstrip("/") + path, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ssl_ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _k8s_json(ctx, cluster, conn, method, path, *, expect=(200, 201)):
    status, raw = _k8s(ctx, cluster, conn, method, path)
    assert status in expect, (
        f"{method} {path} on the Kubernetes API returned {status}, expected one of {expect}: "
        f"{raw[:400]!r}"
    )
    return json.loads(raw)



def _error(fn):
    """Call fn; return the botocore error (Code, Message). Raises if the call SUCCEEDS, because an
    unexpected success is the strongest signal available and must never be reported as an
    error-code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call was expected to be refused but it was accepted")


def _ready_node_names(ctx, cluster, conn, nodegroup):
    """The names of Ready Kubernetes nodes the node group owns, read from the API server."""
    nodes = _k8s_json(
        ctx, cluster, conn, "GET",
        "/api/v1/nodes?labelSelector=eks.amazonaws.com%2Fnodegroup%3D" + nodegroup,
    )["items"]
    return sorted(
        n["metadata"]["name"]
        for n in nodes
        if any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"])
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """DeleteCluster with a dependent node group is refused with ResourceInUseException and
    nothing is torn down: cluster and node group stay ACTIVE and the same node is still Ready to
    the cluster's API server, and the identical DeleteCluster succeeds once the node group is gone."""
    c = ctx.client("eks")
    cluster, conn = _provision_cluster(ctx)
    nodegroup = _provision_nodegroup(ctx, cluster)

    assert nodegroup in c.list_nodegroups(clusterName=cluster)["nodegroups"], (
        f"{nodegroup!r} is missing from ListNodegroups: "
        f"{c.list_nodegroups(clusterName=cluster)['nodegroups']!r}"
    )

    # (1) THE BARRIER: the node has really joined, so a later read cannot confuse "not ready yet"
    #     with "the refused delete killed it".
    before_nodes = _wait_for(
        lambda: _ready_node_names(ctx, cluster, conn, nodegroup),
        lambda names: len(names) == 1,
        timeout_s=_NODE_READY_TIMEOUT_S,
        interval_s=15,
        desc=f"one Ready node in {nodegroup}",
    )

    # (2) Break exactly one thing: ask to delete a cluster that still has a dependent.
    code, message = _error(lambda: c.delete_cluster(name=cluster))
    assert code == "ResourceInUseException", (
        f"DeleteCluster with a live node group was refused with {code!r}, not "
        f"ResourceInUseException"
    )
    assert message == "Cluster has nodegroups attached", f"unexpected DeleteCluster message {message!r}"

    # (3) THE EFFECT IS ABSENT, on both control-plane records...
    cluster_state = c.describe_cluster(name=cluster)["cluster"]
    assert cluster_state["status"] == "ACTIVE", (
        f"a refused DeleteCluster still moved the cluster to {cluster_state['status']!r}"
    )
    nodegroup_state = c.describe_nodegroup(
        clusterName=cluster, nodegroupName=nodegroup
    )["nodegroup"]
    assert nodegroup_state["status"] == "ACTIVE", (
        f"a refused DeleteCluster still moved the node group to {nodegroup_state['status']!r}"
    )

    # (4) ... and in the cluster itself: the SAME node is still Ready to the API server, which is
    #     the observation no EKS API response can provide.
    after_nodes = _ready_node_names(ctx, cluster, conn, nodegroup)
    assert after_nodes == before_nodes, (
        f"after the refused DeleteCluster the Kubernetes API server reports Ready nodes "
        f"{after_nodes!r}, not the {before_nodes!r} it reported before -- the refusal was not "
        f"free of side effects"
    )
    version = _k8s_json(ctx, cluster, conn, "GET", "/version")
    assert f"{version['major']}.{version['minor'].rstrip('+')}" == cluster_state["version"], (
        f"the API server serves Kubernetes "
        f"{version['major']}.{version['minor']} while DescribeCluster advertises "
        f"{cluster_state['version']!r} after the refused delete"
    )

    # (5) POSITIVE CONTROL: remove the dependency and the identical call is accepted.
    c.delete_nodegroup(clusterName=cluster, nodegroupName=nodegroup)
    _wait_for(
        lambda: _nodegroup_status(c, cluster, nodegroup),
        lambda s: s == "GONE",
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"nodegroup {nodegroup} deleted",
    )
    accepted = c.delete_cluster(name=cluster)["cluster"]
    assert accepted["status"] == "DELETING", (
        f"once the node group was gone the identical DeleteCluster returned "
        f"{accepted['status']!r}, not DELETING"
    )
    assert accepted["name"] == cluster, f"{accepted!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
