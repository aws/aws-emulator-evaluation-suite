"""eks-ebs-csi-volume-data-survives-a-pod-reschedule."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "eks-ebs-csi-volume-data-survives-a-pod-reschedule"
GROUP = 'data-plane'
SERVICES = ['eks']

# A shared cluster adopted under a deterministic name; teardown is registered only by the check
# that actually created it.
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
_POD_TIMEOUT_S = 600

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_PAYLOAD = "sim2real-eks-ebs-payload-6e04"
_AGENT_ADDON = "eks-pod-identity-agent"
_CSI_ADDON = "aws-ebs-csi-driver"
_CSI_SERVICE_ACCOUNT = "ebs-csi-controller-sa"
_EBS_CSI_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
_WRITER = "sim2real-writer"
_READER = "sim2real-reader"
_PVC = "sim2real-data"
_ADDON_TIMEOUT_S = 900
_PROPAGATION_TIMEOUT_S = 180
_VOLUME_TIMEOUT_S = 600
_ADMISSION_TIMEOUT_S = 300


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for(fn, pred, *, timeout_s, interval_s, desc, ctx=None):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{desc}: the run budget ended first; not graded")
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


def _retry_while_role_propagates(fn, desc):
    """Retry ``fn`` while EKS refuses a just-created roleArn as not-yet-visible.

    IAM exposes no condition to poll, so a just-created role reads as InvalidParameterException.
    """
    deadline = time.monotonic() + _PROPAGATION_TIMEOUT_S
    while True:
        try:
            return fn()
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "InvalidParameterException"
                or time.monotonic() >= deadline
            ):
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

    DeleteCluster on an ACTIVE cluster with no dependents can still be refused with
    ResourceInUseException ("update in progress") while ListUpdates is empty, so the delete retries.
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
        interval_s=2,
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
        interval_s=2,
        desc=f"cluster {name} fully deleted",
    )


def _adopt_or_create_cluster(ctx):
    """Return (endpoint, ca_pem) for the shared ACTIVE cluster; teardown only if we made it."""
    c = ctx.client("eks")
    role_arn = _ensure_role(ctx, _CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    subnets = _fixture_subnets(ctx)
    try:
        _retry_while_role_propagates(
            lambda: c.create_cluster(
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
            ),
            f"create cluster {_SHARED_CLUSTER}",
        )
        ctx.on_cleanup(lambda: _teardown_cluster(c, _SHARED_CLUSTER))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceInUseException":
            raise
    cluster = _wait_for(
        lambda: c.describe_cluster(name=_SHARED_CLUSTER)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _CLUSTER_TIMEOUT_S),
        interval_s=2,
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
    node_role = _ensure_role(ctx, _NODE_ROLE, "ec2.amazonaws.com", _NODE_POLICIES)
    subnets = _fixture_subnets(ctx)
    try:
        _retry_while_role_propagates(
            lambda: c.create_nodegroup(
                clusterName=_SHARED_CLUSTER,
                nodegroupName=_SHARED_NODEGROUP,
                subnets=subnets,
                nodeRole=node_role,
                scalingConfig={"minSize": 2, "maxSize": 2, "desiredSize": 2},
                instanceTypes=[_NODE_TYPE],
                amiType="AL2023_x86_64_STANDARD",
                capacityType="ON_DEMAND",
                diskSize=20,
                tags=dict(_FIXTURE_TAGS),
            ),
            f"create nodegroup {_SHARED_NODEGROUP}",
        )
        ctx.on_cleanup(lambda: _teardown_nodegroup(c, _SHARED_CLUSTER, _SHARED_NODEGROUP))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceInUseException":
            raise
    status = _wait_for(
        lambda: _nodegroup_status(c, _SHARED_CLUSTER, _SHARED_NODEGROUP),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _NODEGROUP_TIMEOUT_S),
        interval_s=2,
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


def _pods_trust():
    """The EKS Pod Identity trust policy; sts:TagSession is required alongside sts:AssumeRole
    because the service tags the session with the cluster, namespace and service account."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "pods.eks.amazonaws.com"},
                    "Action": ["sts:AssumeRole", "sts:TagSession"],
                }
            ],
        }
    )


def _addon_status(c, cluster, addon):
    try:
        return c.describe_addon(clusterName=cluster, addonName=addon)["addon"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _associate_when_role_is_visible(c, namespace, service_account, role_arn):
    """CreatePodIdentityAssociation with a bounded retry over the IAM propagation window.

    EKS validates roleArn synchronously, and IAM exposes no propagation condition to poll.
    """
    deadline = time.monotonic() + _PROPAGATION_TIMEOUT_S
    while True:
        try:
            return c.create_pod_identity_association(
                clusterName=_SHARED_CLUSTER, namespace=namespace,
                serviceAccount=service_account, roleArn=role_arn,
                tags=dict(_FIXTURE_TAGS),
            )["association"]
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "InvalidParameterException"
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(2)


def _adopt_or_create_agent_addon(ctx):
    """The pod-identity agent is a prerequisite for wiring the CSI driver to an IAM role."""
    c = ctx.client("eks")
    try:
        c.create_addon(
            clusterName=_SHARED_CLUSTER, addonName=_AGENT_ADDON,
            resolveConflicts="OVERWRITE", tags=dict(_FIXTURE_TAGS),
        )
        ctx.on_cleanup(lambda: _gone_ok(lambda: c.delete_addon(
            clusterName=_SHARED_CLUSTER, addonName=_AGENT_ADDON, preserve=False)))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceInUseException":
            raise
    status = _wait_for(
        lambda: _addon_status(c, _SHARED_CLUSTER, _AGENT_ADDON),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _ADDON_TIMEOUT_S), interval_s=2, desc=f"addon {_AGENT_ADDON} ACTIVE",
    )
    assert status == "ACTIVE", f"addon {_AGENT_ADDON!r} landed in {status!r}"


def _drop_addon(c, addon):
    try:
        c.delete_addon(clusterName=_SHARED_CLUSTER, addonName=addon, preserve=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _wait_for(
        lambda: _addon_status(c, _SHARED_CLUSTER, addon),
        lambda s: s == "GONE",
        timeout_s=_ADDON_TIMEOUT_S, interval_s=2, desc=f"addon {addon} deleted",
    )


def _delete_role_managed(iam, name):
    for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
        iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
    iam.delete_role(RoleName=name)


def _volume_state(ec2, volume_id):
    try:
        return ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidVolume.NotFound":
            return "GONE"
        raise


def _pod_gone(ctx, conn, ns, pod):
    return _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}")[0] == 404


def _drop_pod(ctx, conn, ns, pod, timeout_s=_POD_TIMEOUT_S, budget_ctx=None):
    _k8s(ctx, conn, "DELETE",
         f"/api/v1/namespaces/{ns}/pods/{pod}?gracePeriodSeconds=0", timeout_s=90)
    _wait_for(lambda: _pod_gone(ctx, conn, ns, pod), lambda gone: gone,
              timeout_s=timeout_s, interval_s=2, desc=f"pod {pod} gone", ctx=budget_ctx)


def _teardown_volume(ctx, conn, ns, volume_id):
    """Release the claim and VERIFY the EBS volume really went away.

    Drains the pods, deletes the PVC, polls the volume to gone, and deletes it directly if the
    CSI driver's reclaim never happens.
    """
    ec2 = ctx.client("ec2")
    for pod in (_READER, _WRITER):
        try:
            _drop_pod(ctx, conn, ns, pod)
        except AssertionError:
            pass
    _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}/persistentvolumeclaims/{_PVC}",
         timeout_s=90)
    deadline = time.monotonic() + _VOLUME_TIMEOUT_S
    while _volume_state(ec2, volume_id) not in ("GONE", "deleting", "deleted"):
        if time.monotonic() >= deadline:
            ec2.delete_volume(VolumeId=volume_id)
            return
        time.sleep(2)


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """Bytes a writer pod puts on an EBS CSI-provisioned PVC are read back by a second pod after the
    writer is deleted, and the EBS volume carries the PersistentVolume name as a tag.

    Reference: https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html
    """
    conn = _adopt_or_create_cluster(ctx)
    _adopt_or_create_nodegroup(ctx)
    _adopt_or_create_agent_addon(ctx)
    c = ctx.client("eks")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-eks-csi-")[:64]
    iam.create_role(
        RoleName=role_name,
        Description="sim2real ga-depth eks ebs csi controller",
        AssumeRolePolicyDocument=_pods_trust(),
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": "ga-depth-eks"}],
    )
    ctx.on_cleanup(lambda: _delete_role_managed(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EBS_CSI_POLICY)
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"

    # The association is created BEFORE the addon: the pod-identity webhook starts injecting
    # credentials seconds after CreatePodIdentityAssociation, and only at pod admission, so a CSI
    # controller pod admitted earlier would never receive credentials.
    assoc = _associate_when_role_is_visible(c, "kube-system", _CSI_SERVICE_ACCOUNT, role_arn)
    # Registered from the identifier in THIS response, never re-derived from a List* call.
    ctx.on_cleanup(lambda: c.delete_pod_identity_association(
        clusterName=_SHARED_CLUSTER, associationId=assoc["associationId"]))

    c.create_addon(
        clusterName=_SHARED_CLUSTER,
        addonName=_CSI_ADDON,
        resolveConflicts="OVERWRITE",
        tags=dict(_FIXTURE_TAGS),
    )
    ctx.on_cleanup(lambda: _drop_addon(c, _CSI_ADDON))
    addon_status = _wait_for(
        lambda: _addon_status(c, _SHARED_CLUSTER, _CSI_ADDON),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _ADDON_TIMEOUT_S), interval_s=2, desc=f"addon {_CSI_ADDON} ACTIVE",
    )
    addon = c.describe_addon(clusterName=_SHARED_CLUSTER, addonName=_CSI_ADDON)["addon"]
    assert addon_status == "ACTIVE", (
        f"the EBS CSI driver addon landed in {addon_status!r}: {addon.get('health')!r}"
    )

    # The controller Deployment reaching ready is the observable proof that the driver's pods were
    # admitted WITH injected credentials -- without them they crash-loop and the PVC never binds.
    controller = _wait_for(
        lambda: _k8s_json(
            ctx, conn, "GET",
            "/apis/apps/v1/namespaces/kube-system/deployments/ebs-csi-controller",
        ),
        lambda d: d["status"].get("readyReplicas", 0) >= 1,
        ctx=ctx,
        timeout_s=_budget_s(ctx, _ADDON_TIMEOUT_S), interval_s=2, desc="ebs-csi-controller ready",
    )
    assert controller["status"]["readyReplicas"] >= 1, (
        f"the EBS CSI controller never became ready: {controller['status']!r}"
    )
    # Read the LIVE controller pods, not the Deployment's pod template: the pod-identity webhook
    # mutates a Pod at ADMISSION and never touches the Deployment that created it, so the template
    # is the wrong object to look at. The selector comes from the Deployment itself rather than a
    # hardcoded label, so a relabelled addon release cannot silently make this vacuous.
    selector = urllib.parse.quote(
        ",".join(f"{k}={v}" for k, v in sorted(controller["spec"]["selector"]["matchLabels"].items()))
    )
    running = _wait_for(
        lambda: [
            pod for pod in _k8s_json(
                ctx, conn, "GET",
                f"/api/v1/namespaces/kube-system/pods?labelSelector={selector}",
            )["items"]
            if pod["status"]["phase"] == "Running"
        ],
        lambda pods: bool(pods),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _ADDON_TIMEOUT_S), interval_s=2, desc="an ebs-csi-controller pod Running",
    )
    controller_env = {
        e["name"]
        for pod in running
        for container in pod["spec"]["containers"]
        for e in container.get("env") or []
    }
    assert "AWS_CONTAINER_CREDENTIALS_FULL_URI" in controller_env, (
        f"the running CSI controller pods carry no injected pod-identity credential environment, "
        f"so the driver cannot call EC2 to provision a volume: {sorted(controller_env)!r}"
    )

    ns = ctx.unique_name("sim2real-ebs-")[:63].lower()
    _k8s_json(
        ctx, conn, "POST", "/api/v1/namespaces",
        body={"apiVersion": "v1", "kind": "Namespace",
              "metadata": {"name": ns, "labels": {"sim2real": "ga-depth-eks"}}},
    )
    ctx.on_cleanup(lambda: _delete_namespace(ctx, conn, ns))

    storage_class = ctx.unique_name("sim2real-gp3-")[:63].lower()
    _k8s_json(
        ctx, conn, "POST", "/apis/storage.k8s.io/v1/storageclasses",
        body={
            "apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
            "metadata": {"name": storage_class},
            "provisioner": "ebs.csi.aws.com",
            "parameters": {"type": "gp3"},
            "reclaimPolicy": "Delete",
            # WaitForFirstConsumer is required, not stylistic: the volume must be created in the
            # AZ of the node the writer actually lands on, or it can never be attached.
            "volumeBindingMode": "WaitForFirstConsumer",
        },
    )
    ctx.on_cleanup(lambda: _k8s(ctx, conn, "DELETE",
                                f"/apis/storage.k8s.io/v1/storageclasses/{storage_class}"))

    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/persistentvolumeclaims",
        body={
            "apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": _PVC},
            "spec": {"accessModes": ["ReadWriteOnce"],
                     "storageClassName": storage_class,
                     "resources": {"requests": {"storage": "1Gi"}}},
        },
    )

    def _volume_pod(name, script):
        return {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name},
            "spec": {
                "restartPolicy": "Never",
                "containers": [{
                    "name": "io", "image": "public.ecr.aws/docker/library/busybox:1.36",
                    "command": ["sh", "-c", script],
                    "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                }],
                "volumes": [{"name": "data",
                             "persistentVolumeClaim": {"claimName": _PVC}}],
            },
        }

    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods",
        body=_volume_pod(
            _WRITER,
            f"printf '%s:%s' '{_PAYLOAD}' \"$(hostname)\" > /data/payload && sync"
            " && cat /data/payload",
        ),
    )
    writer = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{_WRITER}"),
        lambda p: p["status"]["phase"] in ("Succeeded", "Failed"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _POD_TIMEOUT_S), interval_s=2, desc=f"writer pod {_WRITER} terminal",
    )
    assert writer["status"]["phase"] == "Succeeded", (
        f"the writer pod ended {writer['status']['phase']!r}; a PVC that never binds leaves it "
        f"Pending forever, which means the CSI driver has no working credentials: "
        f"{writer['status']!r}"
    )
    status, raw = _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{_WRITER}/log")
    assert status == 200, f"could not read the writer's logs: {status} {raw[:300]!r}"
    written = raw.decode("utf-8", "replace")
    assert written == f"{_PAYLOAD}:{_WRITER}", (
        f"the writer reported {written!r} on /data/payload, expected "
        f"{_PAYLOAD + ':' + _WRITER!r}"
    )

    # (1) The claim really bound to a dynamically provisioned volume.
    claim = _k8s_json(
        ctx, conn, "GET", f"/api/v1/namespaces/{ns}/persistentvolumeclaims/{_PVC}"
    )
    assert claim["status"]["phase"] == "Bound", f"{claim['status']!r}"
    pv_name = claim["spec"]["volumeName"]
    pv = _k8s_json(ctx, conn, "GET", f"/api/v1/persistentvolumes/{pv_name}")
    assert pv["spec"]["csi"]["driver"] == "ebs.csi.aws.com", f"{pv['spec']!r}"
    volume_id = pv["spec"]["csi"]["volumeHandle"]
    # Registered from the identifier in the PV the driver itself wrote, the moment it is known.
    ctx.on_cleanup(lambda: _teardown_volume(ctx, conn, ns, volume_id))

    # (2) The driver really created an EBS volume in AWS and tagged it with the PV's name.
    volume = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    assert volume["Size"] == 1, f"the PVC asked for 1Gi, the volume is {volume['Size']!r}GiB"
    assert volume["VolumeType"] == "gp3", (
        f"the StorageClass asked for gp3, the volume is {volume['VolumeType']!r}"
    )
    tags = {t["Key"]: t["Value"] for t in volume.get("Tags", [])}
    assert tags.get("kubernetes.io/created-for/pv/name") == pv_name, (
        f"the EBS volume {volume_id!r} is not tagged with the PersistentVolume name {pv_name!r}: "
        f"{tags!r}"
    )
    assert tags.get("kubernetes.io/created-for/pvc/name") == _PVC, f"{tags!r}"

    # (3) THE OBSERVATION: the writer is gone, and a different pod reads the writer's bytes back.
    _drop_pod(ctx, conn, ns, _WRITER, timeout_s=_budget_s(ctx, _POD_TIMEOUT_S), budget_ctx=ctx)
    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods",
        body=_volume_pod(_READER, "cat /data/payload"),
    )
    reader = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{_READER}"),
        lambda p: p["status"]["phase"] in ("Succeeded", "Failed"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _POD_TIMEOUT_S), interval_s=2, desc=f"reader pod {_READER} terminal",
    )
    assert reader["status"]["phase"] == "Succeeded", (
        f"the reader pod ended {reader['status']['phase']!r} -- a volume that cannot be "
        f"re-attached after the writer is deleted fails here: {reader['status']!r}"
    )
    assert reader["spec"]["nodeName"], f"the reader was never scheduled: {reader['spec']!r}"
    status, raw = _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{_READER}/log")
    assert status == 200, f"could not read the reader's logs: {status} {raw[:300]!r}"
    read_back = raw.decode("utf-8", "replace")
    assert read_back == written, (
        f"the reader saw {read_back!r} on the same PVC, the writer wrote {written!r} -- the bytes "
        f"did not survive the reschedule"
    )
    assert read_back.endswith(":" + _WRITER), (
        f"the payload names {read_back.rsplit(':', 1)[-1]!r} as its author, so the reader did not "
        f"read the writer's bytes: {read_back!r}"
    )

    # (4) The volume is still the same AWS volume both pods used.
    assert _volume_state(ec2, volume_id) == "in-use", (
        f"the EBS volume {volume_id!r} is {_volume_state(ec2, volume_id)!r} while the reader is "
        f"bound to it"
    )


def _gone_ok(fn):
    """Run a teardown call; a resource the check already deleted in band is done, not a leak."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
