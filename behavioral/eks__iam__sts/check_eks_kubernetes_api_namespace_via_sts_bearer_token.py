"""eks-kubernetes-api-namespace-via-sts-bearer-token."""

from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "eks-kubernetes-api-namespace-via-sts-bearer-token"

GROUP = "container-k8s-api"

SERVICES = ["eks", "iam", "sts"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An EKS cluster's Kubernetes API accepts an STS bearer token: the creator's access entry exists,
    SelfSubjectReview names the caller ARN, a namespace is created (201, then 409 on replay) and
    read back Active, and unauthenticated requests, even GET /version, are refused with 401.
    """
    eks = ctx.client("eks")
    identity = ctx.client("sts").get_caller_identity()
    caller_arn = identity["Arn"]
    account_id = identity["Account"]

    subnets = _eks_subnets(ctx)
    role_arn = _eks_cluster_role(ctx)
    name = ctx.unique_name(_XSVC_PREFIX + "eks-")
    # A freshly attached AmazonEKSClusterPolicy can lag behind IAM's own
    # list_attached_role_policies read: CreateCluster calls sts:AssumeRole on the role from
    # the EKS service side, which observes propagation on its own schedule. Retry the create
    # itself through that window rather than guessing how long it takes.
    _create_cluster_with_retry(
        ctx,
        eks,
        name=name,
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
        tags=dict(_MANAGED_TAGS),
    )

    def _drop_cluster():
        # A leaked control plane bills by the hour forever: delete, then WAIT for it to be
        # gone so the cluster role teardown registered earlier cannot orphan it.
        _teardown(lambda: eks.delete_cluster(name=name), "ResourceNotFoundException")
        deadline = time.monotonic() + 1500
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(2)
        raise RuntimeError(f"EKS cluster {name} still exists 1500 s after DeleteCluster")

    ctx.on_cleanup(_drop_cluster)

    cluster = _poll_until(
        lambda: (_safe(lambda: eks.describe_cluster(name=name)) or {}).get("cluster", {}),
        lambda c: c.get("status") in ("ACTIVE", "FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 1800),
        interval_s=2,
        description=f"EKS cluster {name} reaches ACTIVE",
    )
    assert cluster.get("status") == "ACTIVE", f"cluster landed in {cluster.get('status')!r}"
    assert not (p := ctx.published_url_mismatch(cluster["endpoint"])), p
    assert cluster["certificateAuthority"]["data"], "cluster advertises no CA certificate"
    assert cluster["accessConfig"]["authenticationMode"] == "API_AND_CONFIG_MAP", cluster[
        "accessConfig"
    ]

    # --- The control-plane half of the boundary: bootstrapClusterCreatorAdminPermissions is
    # not a flag that is stored and forgotten, it CREATES an access entry for the calling IAM
    # principal, and that entry is the only reason the Kubernetes write below is allowed. An
    # emulator that accepts the flag without materialising the entry is caught here.
    entries = eks.list_access_entries(clusterName=name)["accessEntries"]
    assert caller_arn in entries, (
        "bootstrapClusterCreatorAdminPermissions did not create an access entry for the "
        f"creating principal {caller_arn}: {entries!r}"
    )
    entry = eks.describe_access_entry(clusterName=name, principalArn=caller_arn)["accessEntry"]
    assert entry["type"] == "STANDARD", entry
    # The Kubernetes username is the IAM ARN verbatim -- the same string the API server reports
    # for us in the SelfSubjectReview further down.
    assert entry["username"] == caller_arn, entry
    assert entry.get("kubernetesGroups") == [], (
        f"cluster-creator access entry carries kubernetesGroups it was never given: {entry!r}"
    )
    assert entry["clusterName"] == name, entry
    associated = eks.list_associated_access_policies(clusterName=name, principalArn=caller_arn)[
        "associatedAccessPolicies"
    ]
    admin = [a for a in associated if a["policyArn"].endswith("/AmazonEKSClusterAdminPolicy")]
    assert len(admin) == 1, (
        f"expected exactly one AmazonEKSClusterAdminPolicy association, got {associated!r}"
    )
    assert admin[0]["policyArn"] == (
        "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    ), admin
    # Cluster scope, not namespace scope -- and the namespace list is present-but-empty, which
    # is how EKS encodes "everywhere".
    assert admin[0]["accessScope"]["type"] == "cluster", admin
    assert admin[0]["accessScope"].get("namespaces") == [], admin

    # --- The API server is reachable AND our STS identity is accepted.
    status, version = _poll_until(
        lambda: _k8s_request(ctx, cluster, "GET", "/version"),
        lambda r: r[0] == 200,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 600),
        interval_s=2,
        description="GET /version on the cluster's Kubernetes API with an STS token",
    )
    assert status == 200, (status, version)
    assert isinstance(version, dict) and version.get("gitVersion"), version

    # ...and /version is 200 *because of the token*: EKS turns anonymous authentication off
    # entirely, so the endpoint everyone treats as public is refused without one. This is what
    # makes the authenticated 200 above evidence of anything at all.
    anon_version_status, anon_version_body = _k8s_request(
        ctx, cluster, "GET", "/version", authenticate=False
    )
    assert anon_version_status == 401, (
        "unauthenticated GET /version was not refused with 401 (EKS disables anonymous auth): "
        f"{anon_version_status} {anon_version_body!r}"
    )

    # --- The replayed presigned URL resolves to OUR IAM principal, and the API server says so
    # in Kubernetes' own terms. This is the eks+iam+sts join stated as one assertion.
    review_status, review = _k8s_request(
        ctx,
        cluster,
        "POST",
        "/apis/authentication.k8s.io/v1/selfsubjectreviews",
        {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"},
    )
    assert review_status == 201, (review_status, review)
    user_info = review["status"]["userInfo"]
    assert user_info["username"] == caller_arn, user_info
    assert user_info["uid"].startswith(f"aws-iam-authenticator:{account_id}:"), user_info
    assert "system:authenticated" in user_info["groups"], user_info
    extra = user_info["extra"]
    assert extra["arn"] == [caller_arn], extra
    assert extra["canonicalArn"] == [caller_arn], extra
    # The uid is not an opaque blob: its last segment is the IAM principal id, so the two
    # fields must agree.
    assert user_info["uid"] == f"aws-iam-authenticator:{account_id}:{extra['principalId'][0]}", (
        user_info
    )

    # --- A real Kubernetes write through that boundary.
    namespace = "sim2real-xsvc-" + ctx.unique_name("")[:8]
    def _drop_namespace():
        status, detail = _k8s_request(ctx, cluster, "DELETE", f"/api/v1/namespaces/{namespace}")
        if status not in (200, 202, 404):
            raise RuntimeError(f"DELETE namespace {namespace} failed: {status} {detail!r}")

    ctx.on_cleanup(_drop_namespace)
    body = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": namespace, "labels": {"sim2real": "true"}},
    }
    # A 401 from the API server is an AUTHENTICATION verdict: it means the presigned URL replay
    # against STS did not succeed, which real AWS does transiently (an authorisation problem
    # would be 403). The access entry above is already proven to exist, so retry the write for a
    # bounded window on 401/transport failures only -- 201 is still what is asserted.
    status, created = _poll_until(
        lambda: _k8s_request(ctx, cluster, "POST", "/api/v1/namespaces", body),
        lambda r: r[0] is not None and r[0] != 401,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 180),
        interval_s=2,
        description="POST /api/v1/namespaces getting past the STS-replay authentication step",
    )
    assert status == 201, f"namespace create was not 201: {status} {created!r}"
    assert created["metadata"]["name"] == namespace, created
    assert created["metadata"].get("uid"), created
    # Kubernetes stamps its own label on every namespace it accepts, alongside ours.
    assert created["metadata"]["labels"]["kubernetes.io/metadata.name"] == namespace, created
    assert created["spec"]["finalizers"] == ["kubernetes"], created
    assert created["status"]["phase"] == "Active", created

    # The write really landed in the cluster's own store, so replaying it collides at the
    # Kubernetes level (409/AlreadyExists), not at the AWS level.
    dup_status, dup = _k8s_request(ctx, cluster, "POST", "/api/v1/namespaces", body)
    assert dup_status == 409, f"re-creating the namespace was not refused with 409: {dup_status} {dup!r}"
    assert dup["kind"] == "Status", dup
    assert dup["status"] == "Failure", dup
    assert dup["reason"] == "AlreadyExists", dup
    assert dup["message"] == f'namespaces "{namespace}" already exists', dup
    assert dup["details"]["name"] == namespace, dup

    status, fetched = _poll_until(
        lambda: _k8s_request(ctx, cluster, "GET", f"/api/v1/namespaces/{namespace}"),
        lambda r: r[0] == 200 and (r[1] or {}).get("status", {}).get("phase") == "Active",
        ctx=ctx,
        timeout_s=_budget_s(ctx, 180),
        interval_s=2,
        description=f"namespace {namespace} readable and Active",
    )
    assert status == 200, (status, fetched)
    assert fetched["status"]["phase"] == "Active", fetched
    assert fetched["metadata"]["labels"]["sim2real"] == "true", fetched

    # --- The token is what authorised it: the same request without one is refused.
    anon_status, anon_body = _k8s_request(
        ctx,
        cluster,
        "GET",
        f"/api/v1/namespaces/{namespace}",
        authenticate=False,
    )
    assert anon_status == 401, (
        "an unauthenticated Kubernetes request was not refused with 401: "
        f"{anon_status} {anon_body!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _teardown(fn, *gone_codes):
    """Run one teardown call; only the given not-found codes count as already gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone_codes:
            raise


def _safe(fn):
    """Run fn() and return its result, or None if it raised (probe helper)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"

# Zone IDs EKS does not support for control-plane subnets.
_EKS_UNSUPPORTED_ZONE_IDS = frozenset({"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"})

_K8S_TOKEN_PREFIX = "k8s-aws-v1."


def _eks_subnets(ctx) -> list[str]:
    """Two DEFAULT-VPC subnets in two distinct EKS-supported AZs: a public-subnet-only
    control plane needs no NAT gateway, which is the expensive thing this archetype must
    never leak."""
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get(
        "Subnets", []
    )
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = sn["AvailabilityZone"]
        if sn["AvailabilityZoneId"] in _EKS_UNSUPPORTED_ZONE_IDS:
            continue
        by_az.setdefault(az, sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need network subnets in >=2 EKS-supported AZs, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:2]


def _eks_cluster_role(ctx) -> str:
    """A role EKS can assume, carrying the AWS-managed AmazonEKSClusterPolicy, polled until the
    attachment reads back."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_XSVC_PREFIX + "eks-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "eks.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _drop():
        _teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_EKS_CLUSTER_POLICY), "NoSuchEntity")
        _teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity")

    ctx.on_cleanup(_drop)
    iam.attach_role_policy(RoleName=name, PolicyArn=_EKS_CLUSTER_POLICY)
    _poll_until(
        lambda: _safe(lambda: iam.list_attached_role_policies(RoleName=name)),
        lambda r: any(
            p["PolicyArn"] == _EKS_CLUSTER_POLICY for p in (r or {}).get("AttachedPolicies", [])
        ),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description=f"AmazonEKSClusterPolicy attached to {name}",
    )
    return arn


def _create_cluster_with_retry(ctx, eks, **kwargs):
    """CreateCluster, retried (bounded) while EKS's own sts:AssumeRole of a just-attached role has
    not yet propagated."""
    last_exc: Exception | None = None
    deadline = time.monotonic() + _budget_s(ctx, 100.0)
    while True:
        try:
            return eks.create_cluster(**kwargs)
        except Exception as exc:  # noqa: BLE001 - retrying through IAM propagation lag
            last_exc = exc
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"create_cluster through IAM propagation lag (last {last_exc}): the run "
                           "budget ended first; not graded")
    raise AssertionError(f"create_cluster kept failing (likely IAM propagation lag): {last_exc}")


def _k8s_bearer_token(ctx, cluster_name: str) -> str:
    """k8s-aws-v1.<base64url of a presigned STS GetCallerIdentity URL whose SIGNED headers
    include x-k8s-aws-id: <cluster>>, as kubectl/aws-iam-authenticator send; the API server
    replays the URL against STS and maps the caller ARN to a Kubernetes subject."""
    sts = ctx.client("sts", endpoint_url=ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com"))

    def _capture(params=None, context=None, **_kwargs):
        if params is not None and context is not None and "ClusterName" in params:
            context["eks_cluster"] = params.pop("ClusterName")

    def _inject(request=None, **_kwargs):
        name = (getattr(request, "context", None) or {}).get("eks_cluster")
        if name:
            # ctx.client() returns a cached client and botocore headers append on assignment;
            # a doubled header is signed as "<c>,<c>" and the API server's STS replay gets 401.
            if "x-k8s-aws-id" in request.headers:
                del request.headers["x-k8s-aws-id"]
            request.headers["x-k8s-aws-id"] = name

    sts.meta.events.register("provide-client-params.sts.GetCallerIdentity", _capture)
    sts.meta.events.register("before-sign.sts.GetCallerIdentity", _inject)
    try:
        url = sts.generate_presigned_url(
            "get_caller_identity",
            Params={"ClusterName": cluster_name},
            ExpiresIn=60,
            HttpMethod="GET",
        )
    finally:
        sts.meta.events.unregister("provide-client-params.sts.GetCallerIdentity", _capture)
        sts.meta.events.unregister("before-sign.sts.GetCallerIdentity", _inject)
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    return _K8S_TOKEN_PREFIX + encoded


def _k8s_request(ctx, cluster: dict, method: str, path: str, body=None, authenticate=True):
    """(status, parsed json | text) from the cluster's own API server, TLS-validated against its CA.
    HTTP error statuses are returned, not raised; a transport failure returns (None, reason) so
    the caller can poll while the endpoint's DNS propagates."""
    endpoint = cluster["endpoint"].rstrip("/")
    ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    ssl_context = ssl.create_default_context(cadata=ca_pem)
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = _routed_request(ctx, endpoint + path, data=data, method=method)
    req.add_header("Accept", "application/json")
    if authenticate:
        req.add_header("Authorization", "Bearer " + _k8s_bearer_token(ctx, cluster["name"]))
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_context) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, raw
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # transport-level, the caller polls
        return None, f"{type(exc).__name__}: {exc}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
