"""eks-pod-identity-credentials-are-scoped-and-an-unallowed-bucket-is-denied."""
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


CHECK = "eks-pod-identity-credentials-are-scoped-and-an-unallowed-bucket-is-denied"
GROUP = 'data-plane'
SERVICES = ['eks']

# Shared cluster adopted under a deterministic name; only the creating check tears it down.
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

# Absorbs a slow control-plane create when the shared cluster has to be built.
_CLUSTER_TIMEOUT_S = 1500
_DELETE_RETRY_TIMEOUT_S = 900
_NODEGROUP_TIMEOUT_S = 900
# Covers a ~400MB aws-cli image pull on a cold node.
_POD_TIMEOUT_S = 600

_IMAGE = "public.ecr.aws/aws-cli/aws-cli:latest"
_PAYLOAD_ALLOWED = "sim2real-eks-pi-allowed-9d21"
_PAYLOAD_DENIED = "sim2real-eks-pi-denied-3ac8"
_KEY = "payload.txt"
_AGENT_ADDON = "eks-pod-identity-agent"
_ADDON_TIMEOUT_S = 600
_ADMISSION_TIMEOUT_S = 300
_CREDENTIAL_URI_VAR = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
_CREDENTIAL_TOKEN_VAR = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"
_TOKEN_VOLUME = "eks-pod-identity-token"


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


def _retry_iam_lag(fn, *, timeout_s=90.0, interval_s=10.0):
    """Retry a call EKS refused with InvalidParameterException because a role created moments
    ago has not yet propagated through IAM -- a bounded retry on the actual synchronous
    validation, not a fixed sleep sized to outrun it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or (
                time.monotonic() >= deadline
            ):
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

    DeleteCluster on an ACTIVE cluster with no dependents can still fail with ResourceInUseException
    ("update in progress") while ListUpdates is empty, so the delete itself must be retried.
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
    try:
        _retry_iam_lag(lambda: c.create_cluster(
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
    try:
        _retry_iam_lag(lambda: c.create_nodegroup(
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


def _sections(text):
    """Split the pod's log into the labelled sections its script printed.

    Parsed structurally off the markers rather than by line offset, so a retry line or a stray
    warning cannot shift the fields the assertions read.
    """
    out = {}
    for chunk in text.split("<<<")[1:]:
        label, _, rest = chunk.partition("\n")
        payload, _, tail = rest.partition(">>>RC=")
        out[label.strip()] = (payload, tail.split("\n", 1)[0].strip())
    return out


def _pods_trust():
    """The EKS Pod Identity trust policy. sts:TagSession is REQUIRED alongside sts:AssumeRole:
    the pod-identity service tags the session with the cluster, namespace and service account, so
    a trust policy carrying only sts:AssumeRole makes the vend fail."""
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


def _adopt_or_create_addon(ctx, addon):
    """Ensure an EKS-managed addon is ACTIVE; teardown only if this call created it."""
    c = ctx.client("eks")
    try:
        c.create_addon(
            clusterName=_SHARED_CLUSTER,
            addonName=addon,
            resolveConflicts="OVERWRITE",
            tags=dict(_FIXTURE_TAGS),
        )
        ctx.on_cleanup(
            lambda: _gone_ok(lambda: c.delete_addon(clusterName=_SHARED_CLUSTER, addonName=addon, preserve=False))
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceInUseException":
            raise
    status = _wait_for(
        lambda: _addon_status(c, _SHARED_CLUSTER, addon),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_ADDON_TIMEOUT_S,
        interval_s=10,
        desc=f"addon {addon} ACTIVE",
    )
    assert status == "ACTIVE", (
        f"addon {addon!r} landed in {status!r}: "
        f"{c.describe_addon(clusterName=_SHARED_CLUSTER, addonName=addon)['addon'].get('health')!r}"
    )


def _pod_gone(ctx, conn, ns, pod):
    return _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}")[0] == 404


def _create_pod_once_identity_is_injected(ctx, conn, ns, pod, manifest):
    """Create the pod and return the admitted spec, retrying until the pod-identity webhook injected
    the credential environment.

    The webhook starts injecting seconds after CreatePodIdentityAssociation returns, and injection
    happens only at admission, so a pod admitted too early never gets credentials.
    """
    deadline = time.monotonic() + _ADMISSION_TIMEOUT_S
    while True:
        admitted = _k8s_json(ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods", body=manifest)
        injected = {e["name"] for e in admitted["spec"]["containers"][0].get("env") or []}
        if _CREDENTIAL_URI_VAR in injected:
            return admitted
        assert time.monotonic() < deadline, (
            f"the pod-identity webhook never injected {_CREDENTIAL_URI_VAR!r} into {pod!r} within "
            f"{_ADMISSION_TIMEOUT_S}s of the association being created; the admitted env was "
            f"{sorted(injected)!r}"
        )
        _k8s(ctx, conn, "DELETE",
             f"/api/v1/namespaces/{ns}/pods/{pod}?gracePeriodSeconds=0", timeout_s=90)
        _wait_for(lambda: _pod_gone(ctx, conn, ns, pod), lambda gone: gone,
                  timeout_s=_ADMISSION_TIMEOUT_S, interval_s=3,
                  desc=f"pod {pod} gone before retrying admission")
        time.sleep(5)

def _make_bucket(ctx, prefix, payload):
    """Create a bucket, put the payload, and register a cleanup that EMPTIES it first -- an S3
    bucket with any object in it cannot be deleted."""
    s3 = ctx.client("s3")
    name = ctx.unique_name(prefix)[:63].lower()
    s3.create_bucket(
        Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _drop_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real", "Value": "ga-depth-eks"}]},
    )
    s3.put_object(Bucket=name, Key=_KEY, Body=payload.encode("utf-8"))
    return name


def _drop_bucket(s3, name):
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=name):
        stale = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
        ]
        if stale:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": stale}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _delete_role_with_inline(iam, name):
    for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=name, PolicyName=pol)
    iam.delete_role(RoleName=name)

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
    """A Pod Identity pod runs as the associated role, reads the allowed bucket's exact bytes, and
    gets AccessDenied on a bucket the role's policy does not cover, with none of its bytes leaked.

    Reference: https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
    """
    c = ctx.client("eks")
    iam = ctx.client("iam")
    conn = _adopt_or_create_cluster(ctx)
    _adopt_or_create_nodegroup(ctx)
    _adopt_or_create_addon(ctx, _AGENT_ADDON)
    account = ctx.client("sts").get_caller_identity()["Account"]

    allowed_bucket = _make_bucket(ctx, "sim2real-eks-pi-ok-", _PAYLOAD_ALLOWED)
    denied_bucket = _make_bucket(ctx, "sim2real-eks-pi-no-", _PAYLOAD_DENIED)

    role_name = ctx.unique_name("sim2real-eks-pi-")[:64]
    iam.create_role(
        RoleName=role_name,
        Description="sim2real ga-depth eks pod identity subject",
        AssumeRolePolicyDocument=_pods_trust(),
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": "ga-depth-eks"}],
    )
    ctx.on_cleanup(lambda: _delete_role_with_inline(iam, role_name))
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-one-bucket",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{allowed_bucket}/*",
            }],
        }),
    )

    ns = ctx.unique_name("sim2real-pi-")[:63].lower()
    sa = "sim2real-pod-identity"
    assoc = c.create_pod_identity_association(
        clusterName=_SHARED_CLUSTER, namespace=ns, serviceAccount=sa, roleArn=role_arn,
        tags=dict(_FIXTURE_TAGS),
    )["association"]
    # Registered from the identifier in THIS response, never re-derived from a List* call, which
    # lags creation.
    ctx.on_cleanup(lambda: c.delete_pod_identity_association(
        clusterName=_SHARED_CLUSTER, associationId=assoc["associationId"]))
    recorded = c.describe_pod_identity_association(
        clusterName=_SHARED_CLUSTER, associationId=assoc["associationId"]
    )["association"]
    assert (recorded["roleArn"], recorded["namespace"], recorded["serviceAccount"]) == (
        role_arn, ns, sa
    ), f"EKS recorded a different association than it was asked for: {recorded!r}"

    _k8s_json(
        ctx, conn, "POST", "/api/v1/namespaces",
        body={"apiVersion": "v1", "kind": "Namespace",
              "metadata": {"name": ns, "labels": {"sim2real": "ga-depth-eks"}}},
    )
    ctx.on_cleanup(lambda: _delete_namespace(ctx, conn, ns))
    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/serviceaccounts",
        body={"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": sa}},
    )

    # IAM is eventually consistent with nothing to poll, so the pod retries first use, bounded.
    script = (
        "for i in $(seq 1 40); do aws sts get-caller-identity >/dev/null 2>&1 && break;"
        " sleep 4; done\n"
        "echo '<<<IDENT'; aws sts get-caller-identity 2>&1; echo \">>>RC=$?\"\n"
        "for i in $(seq 1 40); do aws s3api get-object --bucket \"$BUCKET_OK\" --key \"$KEY\""
        " /tmp/ok >/dev/null 2>&1 && break; sleep 4; done\n"
        "echo '<<<ALLOWED'; aws s3api get-object --bucket \"$BUCKET_OK\" --key \"$KEY\""
        " /tmp/ok >/dev/null 2>&1; RC=$?; cat /tmp/ok 2>/dev/null; echo \">>>RC=$RC\"\n"
        "echo '<<<DENIED'; aws s3api get-object --bucket \"$BUCKET_NO\" --key \"$KEY\""
        " /tmp/no 2>&1 >/dev/null; echo \">>>RC=$?\"\n"
    )
    pod = "sim2real-pod-identity"
    admitted = _create_pod_once_identity_is_injected(
        ctx, conn, ns, pod,
        {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": pod},
            "spec": {
                "restartPolicy": "Never",
                "serviceAccountName": sa,
                "containers": [{
                    "name": "cli", "image": _IMAGE,
                    "command": ["/bin/sh", "-c", script],
                    "env": [
                        {"name": "AWS_REGION", "value": ctx.region},
                        {"name": "AWS_DEFAULT_REGION", "value": ctx.region},
                        {"name": "BUCKET_OK", "value": allowed_bucket},
                        {"name": "BUCKET_NO", "value": denied_bucket},
                        {"name": "KEY", "value": _KEY},
                    ],
                }],
            },
        },
    )

    # (0) The webhook really mutated the pod: the link-local credential endpoint and the projected
    #     pod-identity token are both present.
    env = {e["name"]: e["value"] for e in admitted["spec"]["containers"][0]["env"]}
    assert env[_CREDENTIAL_URI_VAR] == "http://169.254.170.23/v1/credentials", (
        f"the injected credential endpoint is {env.get(_CREDENTIAL_URI_VAR)!r}, not the "
        f"pod-identity agent's link-local address"
    )
    assert env[_CREDENTIAL_TOKEN_VAR].endswith("/" + _TOKEN_VOLUME), (
        f"the injected token path is {env.get(_CREDENTIAL_TOKEN_VAR)!r}"
    )
    audiences = [
        source["serviceAccountToken"]["audience"]
        for volume in admitted["spec"]["volumes"] if volume["name"] == _TOKEN_VOLUME
        for source in volume["projected"]["sources"]
    ]
    assert audiences == ["pods.eks.amazonaws.com"], (
        f"the projected {_TOKEN_VOLUME!r} volume has audiences {audiences!r}; the pod-identity "
        f"agent exchanges a token scoped to pods.eks.amazonaws.com for the role's credentials. "
        f"volumes={admitted['spec']['volumes']!r}"
    )

    finished = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}"),
        lambda p: p["status"]["phase"] in ("Succeeded", "Failed"),
        timeout_s=_POD_TIMEOUT_S,
        interval_s=8,
        desc=f"pod {pod} terminal",
    )
    assert finished["status"]["phase"] == "Succeeded", (
        f"the pod-identity pod ended {finished['status']['phase']!r}: {finished['status']!r}"
    )
    status, log = _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}/log")
    assert status == 200, f"could not read the pod's logs: {status} {log[:300]!r}"
    text = log.decode("utf-8", "replace")
    sec = _sections(text)
    assert set(sec) == {"IDENT", "ALLOWED", "DENIED"}, (
        f"the pod produced sections {sorted(sec)!r}; full log {text!r}"
    )

    # (1) The credential in the container really is the associated role's, vended by the agent.
    assert sec["IDENT"][1] == "0", (
        f"the pod could not call sts:GetCallerIdentity at all (rc={sec['IDENT'][1]!r}), so no "
        f"credential reached it: {sec['IDENT'][0]!r}"
    )
    caller = json.loads(sec["IDENT"][0])
    expected_prefix = f"arn:aws:sts::{account}:assumed-role/{role_name}/"
    assert caller["Arn"].startswith(expected_prefix), (
        f"the pod is running as {caller['Arn']!r}, not a session of the associated role "
        f"{expected_prefix!r}"
    )
    assert caller["Account"] == account, f"{caller!r}"

    # (2) POSITIVE CONTROL: the bucket the policy allows returns its bytes, byte for byte.
    assert sec["ALLOWED"][1] == "0", (
        f"GetObject on the ALLOWED bucket {allowed_bucket!r} exited {sec['ALLOWED'][1]!r}: "
        f"{sec['ALLOWED'][0]!r}"
    )
    assert sec["ALLOWED"][0] == _PAYLOAD_ALLOWED, (
        f"the pod read {sec['ALLOWED'][0]!r} from {allowed_bucket!r}, want {_PAYLOAD_ALLOWED!r}"
    )

    # (3) The ONE thing broken -- the resource ARN the role's policy names -- and nothing else.
    assert sec["DENIED"][1] != "0", (
        f"the pod read a bucket its role does not allow: exit {sec['DENIED'][1]!r} on "
        f"{denied_bucket!r}"
    )
    assert "(AccessDenied)" in sec["DENIED"][0], (
        f"the refusal on {denied_bucket!r} did not carry the AccessDenied error code: "
        f"{sec['DENIED'][0]!r}"
    )

    # (4) THE EFFECT IS ABSENT: the denied object's distinctive payload appears nowhere, so no
    #     partial read got through.
    assert _PAYLOAD_DENIED not in text, (
        f"the denied bucket's payload {_PAYLOAD_DENIED!r} appears in the pod's output despite "
        f"the AccessDenied: {text!r}"
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
