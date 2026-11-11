"""addon-configuration-values-reach-the-in-cluster-workload."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "addon-configuration-values-reach-the-in-cluster-workload"
GROUP = "data-plane"
SERVICES = ["eks"]

# The shared cluster fixture.
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
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "ga-depth-eks"}
_BAD_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}

_ADDON = "metrics-server"
_ADDON_DEPLOYMENT = "/apis/apps/v1/namespaces/kube-system/deployments/metrics-server"
_CLUSTER_TIMEOUT_S = 1500
_NODEGROUP_TIMEOUT_S = 900
_ADDON_TIMEOUT_S = 600


def _wait_for(fn, pred, *, timeout_s, interval_s, desc):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _ensure_role(ctx, name, service, managed_policies=()):
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": ["sts:AssumeRole"]}
        ],
    }
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="sim2real ga-depth eks shared fixture",
        )["Role"]["Arn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("LimitExceeded", "EntityAlreadyExists"):
                raise
    return arn


def _fixture_subnets(ctx):
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
        f"no available AZ in {ctx.region} offers {_NODE_TYPE!r}; offerings were {sorted(offered)!r}"
    )
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZone"] in usable:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= 2, (
        f"EKS needs subnets in >=2 supported AZs; the run's shared network offers {sorted(by_az)!r}"
    )
    return [by_az[az] for az in sorted(by_az)][:3]


def _nodegroup_status(c, cluster, ng):
    try:
        return c.describe_nodegroup(clusterName=cluster, nodegroupName=ng)["nodegroup"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _adopt_or_create_cluster(ctx):
    c = ctx.client("eks")
    try:
        c.create_cluster(
            name=_SHARED_CLUSTER,
            roleArn=_ensure_role(ctx, _CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY]),
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
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceInUseException":
            raise
    cluster = _wait_for(
        lambda: c.describe_cluster(name=_SHARED_CLUSTER)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"shared cluster {_SHARED_CLUSTER} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", (
        f"shared cluster landed in {cluster['status']!r}; health={cluster.get('health')!r}"
    )
    ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    assert ca_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"certificateAuthority.data did not decode to a PEM certificate: {ca_pem[:60]!r}"
    )
    return (ctx.endpoint_url(cluster["endpoint"]), ca_pem), cluster


def _adopt_or_create_nodegroup(ctx):
    """The shared node group — metrics-server needs somewhere to actually run."""
    c = ctx.client("eks")
    try:
        c.create_nodegroup(
            clusterName=_SHARED_CLUSTER,
            nodegroupName=_SHARED_NODEGROUP,
            subnets=_fixture_subnets(ctx),
            nodeRole=_ensure_role(ctx, _NODE_ROLE, "ec2.amazonaws.com", _NODE_POLICIES),
            scalingConfig={"minSize": 2, "maxSize": 2, "desiredSize": 2},
            instanceTypes=[_NODE_TYPE],
            amiType="AL2023_x86_64_STANDARD",
            capacityType="ON_DEMAND",
            diskSize=20,
            tags=dict(_FIXTURE_TAGS),
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
    assert status == "ACTIVE", f"shared node group landed in {status!r}, expected ACTIVE"


def _k8s_token(ctx, cluster_name):
    """The aws-iam-authenticator bearer token for this check's own caller.

    Signed through ctx.client("sts")'s OWN request signer rather than by registering a botocore
    event: ctx hands back a CACHED client, botocore appends repeated headers, and SigV4
    canonicalises `x-k8s-aws-id: <c>,<c>` — which the API server's single-header replay then fails
    to match. The STS endpoint is the one the target's customer configures (ctx.service_url).
    """
    sts = ctx.client("sts")
    base = ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com")
    request_dict = {
        "method": "GET",
        "url": f"{base}/?Action=GetCallerIdentity&Version=2011-06-15",
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_name},
        "context": {},
    }
    signed = sts._request_signer.generate_presigned_url(
        request_dict, region_name=ctx.region, expires_in=300, operation_name="GetCallerIdentity"
    )
    return "k8s-aws-v1." + base64.urlsafe_b64encode(signed.encode()).decode().rstrip("=")


def _k8s(ctx, conn, method, path, *, body=None, timeout_s=45):
    base, ca_pem = conn
    ssl_ctx = ssl.create_default_context(cadata=ca_pem)
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("Authorization", "Bearer " + _k8s_token(ctx, _SHARED_CLUSTER))
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ssl_ctx) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, raw


def _k8s_expect(ctx, conn, method, path, *, body=None, expect=(200, 201)):
    status, parsed = _k8s(ctx, conn, method, path, body=body)
    assert status in expect, (
        f"{method} {path} returned {status}, expected one of {expect}: {str(parsed)[:300]}"
    )
    return parsed


def _addon_deployment_or_none(ctx, conn):
    """The addon's kube-system Deployment, or None while the addon controller has not written it.

    Polling through this rather than through _k8s_expect matters: the object appears
    ASYNCHRONOUSLY after CreateAddon, and asserting 200 on the first poll would fail the check on
    the ordinary case instead of waiting for it.
    """
    status, parsed = _k8s(ctx, conn, "GET", _ADDON_DEPLOYMENT)
    if status == 404:
        return None
    assert status == 200, (
        f"GET {_ADDON_DEPLOYMENT} returned {status}, expected 200 or 404: {str(parsed)[:300]}"
    )
    return parsed


def _ready_node_count(ctx, conn):
    """How many nodes the CLUSTER ITSELF reports Ready — the ceiling on any replica count."""
    nodes = _k8s_expect(ctx, conn, "GET", "/api/v1/nodes")["items"]
    ready = 0
    for node in nodes:
        for cond in node["status"]["conditions"]:
            if cond["type"] == "Ready" and cond["status"] == "True":
                ready += 1
                break
    return ready


def _replica_property(schema):
    """The addon schema's OWN integer replica-count property and its default.

    Discovered from the target's reported configuration schema rather than named as a literal, so
    the assertion survives a rename between `replicas` and `replicaCount` and so the value chosen
    below can be checked against the schema's own default rather than a guess.
    """
    props = schema.get("properties", {})
    candidates = {
        name: spec
        for name, spec in props.items()
        if "replica" in name.lower()
        and spec.get("type") == "integer"
        and isinstance(spec.get("default"), int)
    }
    assert len(candidates) == 1, (
        f"expected exactly ONE integer replica-count property with a default in the {_ADDON} "
        f"configuration schema; found {sorted(candidates)!r} among top-level properties "
        f"{sorted(props)!r}"
    )
    name = next(iter(candidates))
    return name, candidates[name]["default"]


def _addon_status(c, cluster, name):
    try:
        return c.describe_addon(clusterName=cluster, addonName=name)["addon"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """An EKS addon's configurationValues reconfigure the in-cluster workload: the replica count becomes
    the kube-system Deployment's spec.replicas and converges to that many Ready pods, UpdateAddon moves
    it, and deleting the addon removes the Deployment.
    """
    c = ctx.client("eks")
    conn, cluster = _adopt_or_create_cluster(ctx)
    _adopt_or_create_nodegroup(ctx)
    k8s_version = cluster["version"]

    # --- the version comes from the compatibility catalogue for THIS cluster, never a literal ---
    versions = c.describe_addon_versions(addonName=_ADDON, kubernetesVersion=k8s_version)["addons"]
    assert versions, (
        f"DescribeAddonVersions reports no {_ADDON!r} addon for Kubernetes {k8s_version!r}; the "
        "compatibility catalogue is the only source for a version here and it is empty"
    )
    compatible = [
        v["addonVersion"]
        for v in versions[0]["addonVersions"]
        if any(
            k8s_version == comp.get("clusterVersion")
            for comp in v.get("compatibilities", [])
        )
    ]
    assert compatible, (
        f"no {_ADDON!r} version in the catalogue declares compatibility with cluster version "
        f"{k8s_version!r}: {[v['addonVersion'] for v in versions[0]['addonVersions']]!r}"
    )
    addon_version = compatible[0]

    schema = json.loads(
        c.describe_addon_configuration(addonName=_ADDON, addonVersion=addon_version)[
            "configurationSchema"
        ]
    )
    prop, default_replicas = _replica_property(schema)

    # --- the value is derived from two things the TARGET reported: the schema's own default and
    #     the cluster's own Ready node count. metrics-server's manifest carries pod anti-affinity,
    #     so more replicas than nodes would strand one Pending and take the addon to DEGRADED.
    ready_nodes = _ready_node_count(ctx, conn)
    assert ready_nodes >= 2, (
        f"the shared fixture must present at least 2 Ready nodes for a two-replica addon to "
        f"converge; the cluster reports {ready_nodes}"
    )
    chosen = 1 if default_replicas != 1 else min(2, ready_nodes)
    assert chosen != default_replicas, (
        f"the replica count under test must differ from the schema's own default so a target that "
        f"installs with chart defaults fails; both are {chosen}"
    )
    assert 1 <= chosen <= ready_nodes, (
        f"the chosen replica count {chosen} must be between 1 and the cluster's Ready node count "
        f"{ready_nodes}"
    )

    # --- pre-state: the addon must not already be installed, or "it MOVED" is unprovable ---
    pre = _addon_status(c, _SHARED_CLUSTER, _ADDON)
    assert pre == "GONE", (
        f"addon {_ADDON!r} is already installed on the shared cluster with status {pre!r}; this "
        "check installs it and must own its lifecycle (see DRAFT H6 on the singleton hazard)"
    )
    pre_status, _pre_body = _k8s(ctx, conn, "GET", _ADDON_DEPLOYMENT)
    assert pre_status == 404, (
        f"kube-system/metrics-server already exists in the cluster ({pre_status}) before CreateAddon; "
        "the 'it MOVED' assertions below would be unattributable"
    )

    c.create_addon(
        clusterName=_SHARED_CLUSTER,
        addonName=_ADDON,
        addonVersion=addon_version,
        configurationValues=json.dumps({prop: chosen}),
        resolveConflicts="OVERWRITE",
        tags=dict(_FIXTURE_TAGS),
    )
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: c.delete_addon(
        clusterName=_SHARED_CLUSTER, addonName=_ADDON, preserve=False
    )))
    status = _wait_for(
        lambda: _addon_status(c, _SHARED_CLUSTER, _ADDON),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_ADDON_TIMEOUT_S,
        interval_s=15,
        desc=f"addon {_ADDON} to leave CREATING",
    )
    assert status == "ACTIVE", (
        f"addon {_ADDON} landed in {status!r} at {prop}={chosen}, expected ACTIVE; health="
        f"{c.describe_addon(clusterName=_SHARED_CLUSTER, addonName=_ADDON)['addon'].get('health')!r}"
    )

    # === the terminal read: a Kubernetes object, through a different operation than the mutation
    deployment = _wait_for(
        lambda: _addon_deployment_or_none(ctx, conn),
        lambda d: d is not None and d["status"].get("readyReplicas") == chosen,
        timeout_s=_ADDON_TIMEOUT_S,
        interval_s=10,
        desc=(
            f"the kube-system/metrics-server Deployment to report {chosen} readyReplicas, the value "
            f"configurationValues named for the schema's own {prop!r} property"
        ),
    )
    assert deployment["spec"]["replicas"] == chosen, (
        f"configurationValues asked for {prop}={chosen}, but the Deployment the addon controller "
        f"wrote declares spec.replicas={deployment['spec']['replicas']!r}"
    )

    # === it MOVES: UpdateAddon to the schema default, and demand the cluster follow ===
    c.update_addon(
        clusterName=_SHARED_CLUSTER,
        addonName=_ADDON,
        configurationValues=json.dumps({prop: default_replicas}),
        resolveConflicts="OVERWRITE",
    )
    status = _wait_for(
        lambda: _addon_status(c, _SHARED_CLUSTER, _ADDON),
        lambda s: s in ("ACTIVE", "UPDATE_FAILED", "DEGRADED"),
        timeout_s=_ADDON_TIMEOUT_S,
        interval_s=15,
        desc=f"addon {_ADDON} to leave UPDATING after a configurationValues change",
    )
    assert status == "ACTIVE", (
        f"addon {_ADDON} landed in {status!r} after the configuration update, expected ACTIVE"
    )
    updated = _wait_for(
        lambda: _addon_deployment_or_none(ctx, conn),
        lambda d: d is not None and d["spec"]["replicas"] == default_replicas,
        timeout_s=_ADDON_TIMEOUT_S,
        interval_s=10,
        desc=(
            f"the Deployment's spec.replicas to MOVE from {chosen} to {default_replicas} because "
            "UpdateAddon changed configurationValues — a target that writes the workload once and "
            "never reconciles again cannot satisfy this"
        ),
    )
    assert updated["spec"]["replicas"] != chosen, (
        f"spec.replicas is still {chosen}, so the configuration update did not reach the cluster"
    )

    # === B9: the delete proves the workload is gone AND the record is unusable ===
    c.delete_addon(clusterName=_SHARED_CLUSTER, addonName=_ADDON, preserve=False)
    _wait_for(
        lambda: _addon_status(c, _SHARED_CLUSTER, _ADDON),
        lambda s: s == "GONE",
        timeout_s=_ADDON_TIMEOUT_S,
        interval_s=15,
        desc=f"addon {_ADDON} to be fully deleted from the EKS control plane",
    )
    gone_status, gone_body = _wait_for(
        lambda: _k8s(ctx, conn, "GET", _ADDON_DEPLOYMENT),
        lambda pair: pair[0] == 404,
        timeout_s=_ADDON_TIMEOUT_S,
        interval_s=10,
        desc=(
            "DeleteAddon(preserve=false) to remove the kube-system/metrics-server Deployment from "
            "the cluster, not merely the addon record from the control plane"
        ),
    )
    assert gone_status == 404, (
        f"the Deployment must be gone from the cluster after DeleteAddon(preserve=false); GET "
        f"returned {gone_status} {str(gone_body)[:300]}"
    )
    # ... and a MUTATION on the dead addon also fails, with the specific not-found code.
    code = _error_code(
        lambda: c.update_addon(
            clusterName=_SHARED_CLUSTER,
            addonName=_ADDON,
            configurationValues=json.dumps({prop: chosen}),
            resolveConflicts="OVERWRITE",
        ),
        f"UpdateAddon on the deleted addon {_ADDON}",
    )
    assert code == "ResourceNotFoundException", (
        f"UpdateAddon on a deleted addon must be ResourceNotFoundException; got {code!r}"
    )


def _error_code(fn, desc):
    """The ClientError code raised by *fn*. RAISES if *fn* unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(
        f"{desc} was expected to be REFUSED but it SUCCEEDED, returning {result!r}"
    )


def _swallow_not_found(fn):
    """Cleanup-only: deleting something the body already deleted is not a failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
