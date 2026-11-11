"""eks-pinned-addon-version-is-the-image-running-in-the-cluster."""
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

CHECK = "eks-pinned-addon-version-is-the-image-running-in-the-cluster"
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
_BAD_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "ga-depth-eks"}

_CLUSTER_TIMEOUT_S = 1500
_DELETE_RETRY_TIMEOUT_S = 900
_NODEGROUP_TIMEOUT_S = 900
_POD_TIMEOUT_S = 420

_ADDON = "kube-proxy"
_ADDON_TIMEOUT_S = 600
_ROLLOUT_TIMEOUT_S = 420


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


def _retry_iam_lag(ctx, fn, timeout_s=90.0):
    """Retry a create EKS refuses with InvalidParameterException while a just-created role
    has not yet propagated through IAM; any other error, or the deadline, raises."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
    subnets = _fixture_subnets(ctx)
    try:
        _retry_iam_lag(ctx, lambda: c.create_cluster(
            name=_SHARED_CLUSTER,
            roleArn=role_arn,
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
    subnets = _fixture_subnets(ctx)
    node_role_arn = _ensure_role(ctx, _NODE_ROLE, "ec2.amazonaws.com", _NODE_POLICIES)
    try:
        _retry_iam_lag(ctx, lambda: c.create_nodegroup(
            clusterName=_SHARED_CLUSTER,
            nodegroupName=_SHARED_NODEGROUP,
            subnets=subnets,
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


def _k8s(ctx, conn, method, path, *, body=None, content_type="application/json",
         timeout_s=60):
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
        headers["Content-Type"] = content_type
    req = urllib.request.Request(
        base.rstrip("/") + path, method=method, data=data, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ssl_ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _k8s_json(ctx, conn, method, path, *, body=None,
              content_type="application/json", expect=(200, 201)):
    status, raw = _k8s(ctx, conn, method, path, body=body, content_type=content_type)
    assert status in expect, (
        f"{method} {path} on the Kubernetes API returned {status}, expected one of {expect}: "
        f"{raw[:400]!r}"
    )
    return json.loads(raw)


def _addon_status(c, cluster, addon):
    try:
        return c.describe_addon(clusterName=cluster, addonName=addon)["addon"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _daemonset(ctx, conn):
    return _k8s_json(
        ctx, conn, "GET", f"/apis/apps/v1/namespaces/kube-system/daemonsets/{_ADDON}"
    )


def _ds_image(ds):
    """The image of the DaemonSet container that carries the addon's own name, selected by name
    rather than by list position so an injected sidecar cannot shift the field under test."""
    containers = {c["name"]: c["image"] for c in ds["spec"]["template"]["spec"]["containers"]}
    assert _ADDON in containers, (
        f"the {_ADDON} DaemonSet has no container named {_ADDON!r}: {sorted(containers)!r}"
    )
    return containers[_ADDON]


def _restore_addon(ctx, conn, c, previous_image):
    """Undo: hand kube-proxy back to the cluster's own management and restore the image that was
    running before this check pinned one.

    preserve=True is deliberate and load-bearing: preserve=False would DELETE the kube-proxy
    DaemonSet, which would break networking on the shared cluster for every other check. The
    strategic-merge PATCH then puts the original image back so a second run of this check still
    observes a real version CHANGE rather than a no-op.
    """
    try:
        c.delete_addon(clusterName=_SHARED_CLUSTER, addonName=_ADDON, preserve=True)
        _wait_for(
            lambda: _addon_status(c, _SHARED_CLUSTER, _ADDON),
            lambda s: s == "GONE",
            timeout_s=_ADDON_TIMEOUT_S,
            interval_s=10,
            desc=f"addon {_ADDON} deregistered",
        )
    finally:
        _k8s(
            ctx, conn, "PATCH",
            f"/apis/apps/v1/namespaces/kube-system/daemonsets/{_ADDON}",
            body={"spec": {"template": {"spec": {"containers": [
                {"name": _ADDON, "image": previous_image}]}}}},
            content_type="application/strategic-merge-patch+json",
        )


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """CreateAddon pinning a kube-proxy version from the compatibility catalogue changes the
    in-cluster DaemonSet's image tag from its prior value to exactly that version, and the
    DaemonSet converges with every node running the new pod."""
    conn = _adopt_or_create_cluster(ctx)
    _adopt_or_create_nodegroup(ctx)
    c = ctx.client("eks")

    cluster_version = c.describe_cluster(name=_SHARED_CLUSTER)["cluster"]["version"]
    catalogue = c.describe_addon_versions(
        addonName=_ADDON, kubernetesVersion=cluster_version
    )["addons"]
    assert [a["addonName"] for a in catalogue] == [_ADDON], (
        f"DescribeAddonVersions filtered on {_ADDON!r} returned "
        f"{[a['addonName'] for a in catalogue]!r}"
    )
    compatible, defaults = [], []
    for version in catalogue[0]["addonVersions"]:
        for compat in version["compatibilities"]:
            if compat["clusterVersion"] != cluster_version:
                continue
            compatible.append(version["addonVersion"])
            if compat["defaultVersion"]:
                defaults.append(version["addonVersion"])
    assert len(defaults) == 1, (
        f"the catalogue declares {defaults!r} as default for Kubernetes {cluster_version!r}; "
        f"exactly one default is the invariant"
    )
    assert len(compatible) >= 2, (
        f"only {compatible!r} is compatible with Kubernetes {cluster_version!r}, so there is no "
        f"second version to pin and observe a change to"
    )

    before = _daemonset(ctx, conn)
    previous_image = _ds_image(before)
    pinned = next(v for v in compatible if not previous_image.endswith(":" + v))
    assert pinned != previous_image.rsplit(":", 1)[-1], (
        f"chose {pinned!r} but that is already what {previous_image!r} runs"
    )

    c.create_addon(
        clusterName=_SHARED_CLUSTER,
        addonName=_ADDON,
        addonVersion=pinned,
        resolveConflicts="OVERWRITE",
        tags=dict(_FIXTURE_TAGS),
    )
    ctx.on_cleanup(lambda: _restore_addon(ctx, conn, c, previous_image))

    status = _wait_for(
        lambda: _addon_status(c, _SHARED_CLUSTER, _ADDON),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_ADDON_TIMEOUT_S,
        interval_s=10,
        desc=f"addon {_ADDON} ACTIVE",
    )
    addon = c.describe_addon(clusterName=_SHARED_CLUSTER, addonName=_ADDON)["addon"]
    assert status == "ACTIVE", f"addon {_ADDON!r} landed in {status!r}: {addon.get('health')!r}"
    assert addon["addonVersion"] == pinned, (
        f"DescribeAddon reports {addon['addonVersion']!r}, but CreateAddon pinned {pinned!r}"
    )

    # (1) THE OBSERVATION: the cluster's own DaemonSet now runs the pinned image, and it MOVED.
    after = _wait_for(
        lambda: _daemonset(ctx, conn),
        lambda ds: _ds_image(ds).endswith(":" + pinned),
        timeout_s=_ROLLOUT_TIMEOUT_S,
        interval_s=10,
        desc=f"{_ADDON} DaemonSet image tagged {pinned!r}",
    )
    running_image = _ds_image(after)
    assert running_image.endswith(":" + pinned), (
        f"the in-cluster {_ADDON} DaemonSet runs {running_image!r}, which is not the "
        f"{pinned!r} DescribeAddon claims"
    )
    assert running_image != previous_image, (
        f"the DaemonSet image did not change: it was already {previous_image!r} before "
        f"CreateAddon pinned {pinned!r}, so nothing about this proves the addon was applied"
    )

    # (2) ... and the rollout actually converged on every node the node group owns.
    node_count = len(
        _k8s_json(
            ctx, conn, "GET",
            "/api/v1/nodes?labelSelector=eks.amazonaws.com%2Fnodegroup%3D" + _SHARED_NODEGROUP,
        )["items"]
    )
    converged = _wait_for(
        lambda: _daemonset(ctx, conn)["status"],
        lambda st: st.get("numberReady") == st.get("desiredNumberScheduled")
        and st.get("updatedNumberScheduled") == st.get("desiredNumberScheduled"),
        timeout_s=_ROLLOUT_TIMEOUT_S,
        interval_s=10,
        desc=f"{_ADDON} DaemonSet fully rolled out",
    )
    assert converged["numberReady"] == converged["desiredNumberScheduled"], (
        f"{_ADDON} DaemonSet did not converge: {converged!r}"
    )
    assert converged["desiredNumberScheduled"] == node_count, (
        f"{_ADDON} wants {converged['desiredNumberScheduled']!r} pods but the node group has "
        f"{node_count!r} nodes: {converged!r}"
    )
    assert converged["numberMisscheduled"] == 0, f"{converged!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
