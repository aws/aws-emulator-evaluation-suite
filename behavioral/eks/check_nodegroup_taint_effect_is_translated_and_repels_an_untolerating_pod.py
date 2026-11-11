"""nodegroup-taint-effect-is-translated-and-repels-an-untolerating-pod."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "nodegroup-taint-effect-is-translated-and-repels-an-untolerating-pod"
GROUP = "data-plane"
SERVICES = ["eks"]

_SHARED_CLUSTER = "sim2real-ga-eks-shr"
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
_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

_CLUSTER_TIMEOUT_S = 1500
_NODEGROUP_TIMEOUT_S = 900
_NODEGROUP_DELETE_S = 900
_UPDATE_TIMEOUT_S = 600
_POD_TIMEOUT_S = 420
_NODE_JOIN_S = 600
_DELETE_RETRY_TIMEOUT_S = 900
_EVENT_LAG_S = 60

# The translation under test. A RULE, so the assertion is `k8s == _K8S_EFFECT[api]` rather than two
# unrelated literals -- an emulator that copies the API enum verbatim fails it.
_K8S_EFFECT = {
    "NO_SCHEDULE": "NoSchedule",
    "PREFER_NO_SCHEDULE": "PreferNoSchedule",
    "NO_EXECUTE": "NoExecute",
}
_API_EFFECT = "NO_SCHEDULE"
_NG_LABEL = "eks.amazonaws.com/nodegroup"


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


def _hold_while(fn, pred, *, hold_s, interval_s, desc):
    """Assert *pred* holds on every observation for *hold_s*, RAISING the instant it does not.

    This is a calibrated hold window: the caller passes a window derived from the positive
    control's OWN measured latency on the same wiring, and *pred* asserts the twin control group is
    still working at every observation — so a target that is merely slower, or that has stopped
    scheduling anything at all, cannot be scored as having correctly repelled the pod.
    """
    deadline = time.monotonic() + hold_s
    observations = 0
    while time.monotonic() < deadline:
        val = fn()
        observations += 1
        assert pred(val), f"{desc} stopped holding during the {hold_s:.0f}s window; observed {val!r}"
        time.sleep(interval_s)
    # Guards against the degenerate case where the window collapses and the loop body never runs,
    # which would make this a hold with ZERO assertions.
    assert observations >= 3, (
        f"the {hold_s:.0f}s hold window for {desc} produced only {observations} observations; a "
        "window that cannot be observed at least three times is not a barrier"
    )


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
        ctx.on_cleanup(lambda: _teardown_cluster(ctx, _SHARED_CLUSTER))
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
    return cluster["endpoint"], ca_pem


def _nodegroup_status(c, cluster, ng):
    try:
        return c.describe_nodegroup(clusterName=cluster, nodegroupName=ng)["nodegroup"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
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


def _delete_nodegroup(ctx, ng):
    c = ctx.client("eks")
    _delete_with_retry(
        lambda: c.delete_nodegroup(clusterName=_SHARED_CLUSTER, nodegroupName=ng),
        f"delete nodegroup {ng}",
    )
    _wait_for(
        lambda: _nodegroup_status(c, _SHARED_CLUSTER, ng),
        lambda s: s == "GONE",
        timeout_s=_NODEGROUP_DELETE_S,
        interval_s=20,
        desc=f"nodegroup {ng} fully deleted",
    )


def _teardown_cluster(ctx, name):
    """Drain dependents then delete the shared cluster -- ONLY called by whoever created it.

    Same obligation as every other check sharing _SHARED_CLUSTER: the creator, and only the creator,
    tears it down, so a concurrent sibling that merely adopted it is never disrupted mid-run.
    """
    c = ctx.client("eks")
    try:
        for ng in c.list_nodegroups(clusterName=name).get("nodegroups", []):
            _delete_with_retry(
                lambda ng=ng: c.delete_nodegroup(clusterName=name, nodegroupName=ng),
                f"delete nodegroup {ng}",
            )
            _wait_for(
                lambda ng=ng: _nodegroup_status(c, name, ng),
                lambda s: s == "GONE",
                timeout_s=_NODEGROUP_TIMEOUT_S,
                interval_s=20,
                desc=f"nodegroup {ng} deleted",
            )
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
    req = _routed_request(ctx, base.rstrip("/") + path, data=data, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("Authorization", "Bearer " + _k8s_token(ctx, _SHARED_CLUSTER))
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ssl_ctx) as resp:
            raw = resp.read()
            return resp.status, raw
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _k8s_json(ctx, conn, method, path, *, body=None, expect=(200, 201)):
    status, raw = _k8s(ctx, conn, method, path, body=body)
    assert status in expect, (
        f"{method} {path} returned {status}, expected one of {expect}: {raw[:300]!r}"
    )
    return json.loads(raw)


def _pod_manifest(name, nodegroup, taint_key, taint_value, sentinel, *, tolerate):
    """Two pods identical in every respect EXCEPT the toleration — that is the ONE broken thing."""
    spec = {
        "restartPolicy": "Never",
        "nodeSelector": {_NG_LABEL: nodegroup},
        "containers": [
            {
                "name": "probe",
                "image": _IMAGE,
                "command": ["sh", "-c", f"echo {sentinel}"],
            }
        ],
    }
    if tolerate:
        spec["tolerations"] = [
            {
                "key": taint_key,
                "operator": "Equal",
                "value": taint_value,
                "effect": _K8S_EFFECT[_API_EFFECT],
            }
        ]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": {"sim2real": "ga-depth-eks"}},
        "spec": spec,
    }


def _scheduled_condition(pod):
    for cond in pod.get("status", {}).get("conditions", []):
        if cond.get("type") == "PodScheduled":
            return cond
    return None


def _failed_scheduling_events(ctx, conn, ns, pod_name):
    """Every (reason, message) pair recorded against *pod_name*, for diagnosis and for the check."""
    events = _k8s_json(
        ctx, conn, "GET",
        f"/api/v1/namespaces/{ns}/events?fieldSelector=involvedObject.name%3D{pod_name}",
    )
    return [(item.get("reason"), item.get("message", "")) for item in events.get("items", [])]


_TAINT_MARKER = "untolerated taint"


def _failed_scheduling_mentions(ctx, conn, ns, pod_name, needle):
    """True iff some FailedScheduling Event for *pod_name* mentions *needle*.

    -- it does NOT name the specific taint key or value, so *needle* is `_TAINT_MARKER`, not the
    taint key. An emulator that fabricates a taint-shaped Pending state from some unrelated cause
    (no capacity, a nodeSelector miss, an unpulled image) still has to reproduce this specific
    reason text, not just any FailedScheduling event.
    """
    for reason, message in _failed_scheduling_events(ctx, conn, ns, pod_name):
        if reason == "FailedScheduling" and needle in message:
            return True
    return False


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A node group's taint reaches its Node with the Kubernetes effect matching DescribeNodegroup's, a
    pod without the toleration stays Pending (Unschedulable) while its tolerating twin runs, and
    removing the taint through UpdateNodegroupConfig lets the same pending pod schedule and succeed."""
    c = ctx.client("eks")
    conn = _adopt_or_create_cluster(ctx)

    ng = ctx.unique_name("sim2real-taint-ng-")[:63]
    taint_key = "sim2real.io/" + ctx.unique_name("t-")[:20]
    taint_value = ctx.unique_name("v-")[:20]
    c.create_nodegroup(
        clusterName=_SHARED_CLUSTER,
        nodegroupName=ng,
        subnets=_fixture_subnets(ctx),
        nodeRole=_ensure_role(ctx, _NODE_ROLE, "ec2.amazonaws.com", _NODE_POLICIES),
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
        instanceTypes=[_NODE_TYPE],
        # Bottlerocket boots and joins dramatically faster than AL2023.
        amiType="BOTTLEROCKET_x86_64",
        capacityType="ON_DEMAND",
        taints=[{"key": taint_key, "value": taint_value, "effect": _API_EFFECT}],
        tags=dict(_FIXTURE_TAGS),
    )
    ctx.on_cleanup(lambda: _delete_nodegroup(ctx, ng))
    status = _wait_for(
        lambda: _nodegroup_status(c, _SHARED_CLUSTER, ng),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"tainted nodegroup {ng} to leave CREATING",
    )
    assert status == "ACTIVE", f"tainted nodegroup {ng} landed in {status!r}, expected ACTIVE"

    api_taints = c.describe_nodegroup(clusterName=_SHARED_CLUSTER, nodegroupName=ng)["nodegroup"][
        "taints"
    ]
    assert api_taints == [{"key": taint_key, "value": taint_value, "effect": _API_EFFECT}], (
        f"DescribeNodegroup must report the taint exactly as sent, in the API's own enum; it "
        f"reports {api_taints!r}"
    )

    # === the translation, asserted as a RULE over what the two servers each reported ===
    node = _wait_for(
        lambda: _node_of_group(ctx, conn, ng),
        lambda n: n is not None,
        timeout_s=_NODE_JOIN_S,
        interval_s=15,
        desc=f"a Ready Node labelled {_NG_LABEL}={ng} to register with the cluster",
    )
    node_name = node["metadata"]["name"]
    matching = [
        t
        for t in node["spec"].get("taints", [])
        if t.get("key") == taint_key and t.get("value") == taint_value
    ]
    assert len(matching) == 1, (
        f"the Node {node_name} produced by nodegroup {ng} must carry exactly one taint with key "
        f"{taint_key!r} value {taint_value!r}; its spec.taints is {node['spec'].get('taints')!r}"
    )
    assert matching[0]["effect"] == _K8S_EFFECT[_API_EFFECT], (
        f"the EKS API reports effect {_API_EFFECT!r} and Kubernetes must spell the SAME effect "
        f"{_K8S_EFFECT[_API_EFFECT]!r} on the Node; spec.taints says {matching[0]['effect']!r}. "
        "Copying the API enum verbatim into the Node object is the failure this catches"
    )

    ns = ctx.unique_name("sim2real-taint-")[:63].lower()
    _k8s_json(
        ctx, conn, "POST", "/api/v1/namespaces",
        body={
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": ns, "labels": {"sim2real": "ga-depth-eks"}},
        },
    )
    ctx.on_cleanup(lambda: _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}"))

    # === beat 1: the positive control — WITH the toleration — and the latency it measures ===
    sentinel_ok = ctx.unique_name("ok-")
    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods",
        body=_pod_manifest("sim2real-tolerating", ng, taint_key, taint_value, sentinel_ok, tolerate=True),
    )
    started = time.monotonic()
    tolerating = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/sim2real-tolerating"),
        lambda p: p["status"]["phase"] in ("Succeeded", "Failed"),
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc="the tolerating pod to reach a terminal phase on the tainted node",
    )
    schedule_latency = max(time.monotonic() - started, 1.0)
    assert tolerating["status"]["phase"] == "Succeeded", (
        f"the tolerating pod ended {tolerating['status']['phase']!r}: {tolerating['status']!r}"
    )
    assert tolerating["spec"].get("nodeName") == node_name, (
        f"the tolerating pod must have run on the tainted node {node_name!r}; it reports nodeName="
        f"{tolerating['spec'].get('nodeName')!r}"
    )
    log_status, log = _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/sim2real-tolerating/log")
    assert log_status == 200 and sentinel_ok in log.decode("utf-8", "replace"), (
        f"the tolerating pod's log must contain the sentinel {sentinel_ok!r}; got {log_status} "
        f"{log[:200]!r}"
    )

    # === beats 2-4: break exactly one thing — drop the toleration ===
    sentinel_blocked = ctx.unique_name("blocked-")
    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods",
        body=_pod_manifest(
            "sim2real-untolerating", ng, taint_key, taint_value, sentinel_blocked, tolerate=False
        ),
    )
    pending = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/sim2real-untolerating"),
        lambda p: _scheduled_condition(p) is not None,
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc="the untolerating pod to acquire a PodScheduled condition the scheduler wrote",
    )
    cond = _scheduled_condition(pending)
    assert cond["status"] == "False" and cond.get("reason") == "Unschedulable", (
        f"the untolerating pod must be PodScheduled=False reason=Unschedulable; the condition is "
        f"{cond!r}"
    )
    # The scheduler writes the pod's PodScheduled condition and records the FailedScheduling
    # Event through two independent API calls, so the event can lag the condition by a beat;
    # _EVENT_LAG_S bounds that lag rather than asserting the two are atomic.
    mentioned = False
    deadline = time.monotonic() + _EVENT_LAG_S
    while True:
        mentioned = _failed_scheduling_mentions(ctx, conn, ns, "sim2real-untolerating", _TAINT_MARKER)
        if mentioned or time.monotonic() >= deadline:
            break
        time.sleep(5)
    if not mentioned:
        seen = _failed_scheduling_events(ctx, conn, ns, "sim2real-untolerating")
        fs = [m for r, m in seen if r == "FailedScheduling"] or [f"{r}:{m}" for r, m in seen]
    assert mentioned, (
        f"no FailedScheduling event cites {_TAINT_MARKER!r} after {_EVENT_LAG_S}s; seen={fs!r}"
    )

    # The absence is held for >=3x the tolerating pod's OWN measured latency on this wiring, and
    # the twin control is a SECOND tolerating pod running in the same window -- a target that has
    # simply stopped scheduling anything fails the control rather than passing the negative.
    sentinel_twin = ctx.unique_name("twin-")
    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods",
        body=_pod_manifest("sim2real-twin", ng, taint_key, taint_value, sentinel_twin, tolerate=True),
    )
    _hold_while(
        lambda: _blocked_state(ctx, conn, ns),
        lambda st: st[0] == "Pending" and st[1] is None,
        hold_s=max(3 * schedule_latency, 30),
        interval_s=10,
        desc=(
            f"the untolerating pod staying Pending with no nodeName for 3x the "
            f"{schedule_latency:.0f}s the tolerating pod took"
        ),
    )
    twin = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/sim2real-twin"),
        lambda p: p["status"]["phase"] in ("Succeeded", "Failed"),
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc="the twin control pod (tolerating, same node group, same window) to reach a terminal phase",
    )
    assert twin["status"]["phase"] == "Succeeded", (
        f"the twin control pod must have run while the untolerating pod was stuck; it ended "
        f"{twin['status']['phase']!r}: {twin['status']!r} — the negative above is therefore not "
        "attributable to the taint"
    )

    # === beats 5+6: restore — remove the taint and demand the UNCHANGED pending pod get scheduled
    c.update_nodegroup_config(
        clusterName=_SHARED_CLUSTER,
        nodegroupName=ng,
        taints={"removeTaints": [{"key": taint_key, "value": taint_value, "effect": _API_EFFECT}]},
    )
    _wait_for(
        lambda: _nodegroup_status(c, _SHARED_CLUSTER, ng),
        lambda s: s in ("ACTIVE", "UPDATE_FAILED", "DEGRADED"),
        timeout_s=_UPDATE_TIMEOUT_S,
        interval_s=15,
        desc=f"nodegroup {ng} to leave UPDATING after removeTaints",
    )
    assert _nodegroup_status(c, _SHARED_CLUSTER, ng) == "ACTIVE", (
        f"nodegroup {ng} did not return to ACTIVE after removeTaints"
    )
    cleared = _wait_for(
        lambda: _node_of_group(ctx, conn, ng),
        lambda n: n is not None
        and not [t for t in n["spec"].get("taints", []) if t.get("key") == taint_key],
        timeout_s=_UPDATE_TIMEOUT_S,
        interval_s=15,
        desc=(
            f"removeTaints to reach the live Node, clearing {taint_key!r} from its spec.taints "
            "(a control-plane record alone is not the contract)"
        ),
    )
    assert cleared["metadata"]["name"] == node_name, (
        f"removeTaints must not have replaced the node: it was {node_name!r} and is now "
        f"{cleared['metadata']['name']!r}"
    )
    restored = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/sim2real-untolerating"),
        lambda p: p["status"]["phase"] in ("Succeeded", "Failed"),
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=(
            "the SAME untolerating pod -- unchanged -- to be scheduled once the taint is gone; this "
            "is the restore beat and nothing about the pod was touched"
        ),
    )
    assert restored["status"]["phase"] == "Succeeded", (
        f"once the taint is removed the previously unschedulable pod must run; it ended "
        f"{restored['status']['phase']!r}: {restored['status']!r}"
    )
    assert restored["spec"].get("nodeName") == node_name, (
        f"the restored pod must have landed on the same node {node_name!r}; it reports "
        f"{restored['spec'].get('nodeName')!r}"
    )
    log_status, log = _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/sim2real-untolerating/log")
    assert log_status == 200 and sentinel_blocked in log.decode("utf-8", "replace"), (
        f"the restored pod's log must contain its sentinel {sentinel_blocked!r}; got {log_status} "
        f"{log[:200]!r}"
    )

    # Inline teardown: DeleteNodegroup drains and terminates an EC2 instance, which cannot fit the
    # 60s cleanup budget -- a cut-off teardown would PASS while leaking a running node.
    _delete_nodegroup(ctx, ng)
    assert _nodegroup_status(c, _SHARED_CLUSTER, ng) == "GONE", (
        f"nodegroup {ng} was still describable after an asserted inline delete"
    )


def _node_of_group(ctx, conn, ng):
    """The single Ready Node belonging to node group *ng*, or None while it has not joined."""
    nodes = _k8s_json(
        ctx, conn, "GET", f"/api/v1/nodes?labelSelector={_NG_LABEL}%3D{ng}"
    )["items"]
    for node in nodes:
        for cond in node["status"]["conditions"]:
            if cond["type"] == "Ready" and cond["status"] == "True":
                return node
    return None


def _blocked_state(ctx, conn, ns):
    """(phase, nodeName) of the untolerating pod — the two independent observables of its absence."""
    pod = _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/sim2real-untolerating")
    return pod["status"]["phase"], pod["spec"].get("nodeName")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
