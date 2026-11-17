"""eks-configmap-stale-version-conflict-and-rbac-group-update-forbidden."""

from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.config import Config
from botocore.exceptions import ClientError

CHECK = "eks-configmap-stale-version-conflict-and-rbac-group-update-forbidden"

GROUP = "container-k8s-api"

SERVICES = ["eks", "iam", "sts"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A ConfigMap update carrying a stale resourceVersion is refused 409 and changes nothing, and a
    principal mapped by an access entry to a group bound to a get-only Role reads it but is refused
    its update with the API server's exact Forbidden sentence; a deleted namespace reads 404."""
    eks = ctx.client("eks")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name(_PREFIX + "eks-")
    role_arn = _eks_cluster_role(ctx)
    _create_cluster_with_retry(
        ctx,
        eks,
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": _eks_subnets(ctx), "endpointPublicAccess": True,
                            "endpointPrivateAccess": False},
        accessConfig={"authenticationMode": "API", "bootstrapClusterCreatorAdminPermissions": True},
        tags=dict(_MANAGED_TAGS),
    )

    def _drop_cluster():
        # A leaked control plane bills by the hour: delete, then wait until it is gone. DeleteCluster
        # answers ResourceInUseException while an access entry is still being removed; retry it.
        deadline = time.monotonic() + 1500
        while True:
            try:
                eks.delete_cluster(name=name)
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(10)
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(5)
        raise RuntimeError(f"EKS cluster {name} still exists 1500 s after DeleteCluster")

    ctx.on_cleanup(_drop_cluster)

    # A role the account may assume, mapped below to a Kubernetes user and group of our own.
    reader_role = ctx.unique_name(_PREFIX + "eks-cmr-")
    reader_arn = iam.create_role(
        RoleName=reader_role,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "sts:AssumeRole"}]}),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=reader_role), "NoSuchEntity"))

    cluster = _poll_until(
        lambda: (_transient(lambda: eks.describe_cluster(name=name)) or {}).get("cluster", {}),
        lambda c: c.get("status") in ("ACTIVE", "FAILED"),
        ctx=ctx, timeout_s=_budget_s(ctx, 1800), interval_s=10,
        description=f"EKS cluster {name} reaches ACTIVE",
    )
    assert cluster.get("status") == "ACTIVE", f"cluster landed in {cluster.get('status')!r}"
    assert not (p := ctx.published_url_mismatch(cluster["endpoint"])), p

    user, group = "sim2real-cm-reader", "sim2real-cm-readers"
    _create_access_entry(ctx, eks, name, reader_arn, user, group)
    ctx.on_cleanup(lambda: _teardown(
        lambda: eks.delete_access_entry(clusterName=name, principalArn=reader_arn), "ResourceNotFoundException"))
    entry = eks.describe_access_entry(clusterName=name, principalArn=reader_arn)["accessEntry"]
    assert entry["username"] == user and entry["kubernetesGroups"] == [group], (
        f"the access entry did not keep the username and group it was given: {entry!r}"
    )

    # --- Namespace and ConfigMap as the cluster creator.
    ns = _PREFIX + ctx.unique_name("")[:8]
    status, created = _poll_until(
        lambda: _k8s(ctx, cluster, "POST", "/api/v1/namespaces",
                     {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}}),
        lambda r: r[0] is not None and r[0] != 401,
        ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=3,
        description="POST /api/v1/namespaces getting past authentication",
    )
    assert status == 201, f"namespace create was not 201: {status} {created!r}"

    def _drop_namespace():
        st, detail = _k8s(ctx, cluster, "DELETE", f"/api/v1/namespaces/{ns}")
        if st not in (200, 202, 404, 409):  # 409: the namespace is already terminating
            raise RuntimeError(f"DELETE namespace {ns} failed: {st} {detail!r}")

    ctx.on_cleanup(_drop_namespace)
    status, got = _k8s(ctx, cluster, "GET", f"/api/v1/namespaces/{ns}")
    assert status == 200 and got["status"]["phase"] == "Active", f"namespace read back {status} {got!r}"

    cm = "sim2real-settings"
    cm_path = f"/api/v1/namespaces/{ns}/configmaps/{cm}"
    status, first = _k8s(ctx, cluster, "POST", f"/api/v1/namespaces/{ns}/configmaps", {
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": cm}, "data": {"color": "blue"}})
    assert status == 201, f"ConfigMap create was not 201: {status} {first!r}"
    stale = first["metadata"]["resourceVersion"]

    def _put(color, version, creds=None):
        return _k8s(ctx, cluster, "PUT", cm_path, {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": cm, "namespace": ns, "resourceVersion": version}, "data": {"color": color}},
            creds=creds)

    status, updated = _put("green", stale)
    assert status == 200, f"update at the current resourceVersion was not 200: {status} {updated!r}"
    assert updated["data"] == {"color": "green"}, updated
    assert updated["metadata"]["resourceVersion"] != stale, (
        f"the update kept resourceVersion {stale!r}: {updated['metadata']!r}"
    )

    # --- The stale write: refused by optimistic concurrency, and nothing changes.
    status, conflict = _put("red", stale)
    assert status == 409, f"an update at stale resourceVersion {stale!r} was not refused 409: {status} {conflict!r}"
    assert conflict["reason"] == "Conflict", conflict
    assert conflict["message"] == (
        f'Operation cannot be fulfilled on configmaps "{cm}": the object has been modified; '
        "please apply your changes to the latest version and try again"
    ), conflict
    status, now = _k8s(ctx, cluster, "GET", cm_path)
    assert status == 200 and now["data"] == {"color": "green"}, f"the refused write changed the ConfigMap: {now!r}"

    # --- RBAC: a get-only Role in the namespace, bound to the access entry's group.
    status, role = _k8s(ctx, cluster, "POST", f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles", {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "cm-reader"},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]})
    assert status == 201, f"Role create was not 201: {status} {role!r}"
    status, binding = _k8s(ctx, cluster, "POST",
                           f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings", {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "cm-readers"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "cm-reader"},
        "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": group}]})
    assert status == 201, f"RoleBinding create was not 201: {status} {binding!r}"

    creds = _assume(ctx, reader_arn)
    status, seen = _poll_until(
        lambda: _k8s(ctx, cluster, "GET", cm_path, creds=creds),
        lambda r: r[0] not in (None, 401, 403),
        ctx=ctx, timeout_s=_budget_s(ctx, 180), interval_s=3,
        description="the mapped principal's GET of the ConfigMap getting past its new access entry",
    )
    assert status == 200 and seen["data"] == {"color": "green"}, f"the granted get answered {status} {seen!r}"

    status, refused = _put("purple", seen["metadata"]["resourceVersion"], creds=creds)
    assert status == 403, f"the mapped principal's update was not refused 403: {status} {refused!r}"
    assert refused["reason"] == "Forbidden", refused
    assert refused["message"] == (
        f'configmaps "{cm}" is forbidden: User "{user}" cannot update resource "configmaps" in API group "" '
        f'in the namespace "{ns}"'
    ), refused
    status, now = _k8s(ctx, cluster, "GET", cm_path)
    assert status == 200 and now["data"] == {"color": "green"}, f"the forbidden update changed the ConfigMap: {now!r}"

    # --- Delete the ConfigMap, then the namespace: both read back not found.
    status, deleted = _k8s(ctx, cluster, "DELETE", cm_path)
    assert status == 200, f"ConfigMap delete was not 200: {status} {deleted!r}"
    status, gone = _k8s(ctx, cluster, "GET", cm_path)
    assert status == 404 and gone["message"] == f'configmaps "{cm}" not found', f"deleted ConfigMap read {status} {gone!r}"
    status, terminating = _k8s(ctx, cluster, "DELETE", f"/api/v1/namespaces/{ns}")
    assert status == 200, f"namespace delete was not 200: {status} {terminating!r}"
    status, ns_gone = _poll_until(
        lambda: _k8s(ctx, cluster, "GET", f"/api/v1/namespaces/{ns}"),
        lambda r: r[0] == 404,
        ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=3,
        description=f"namespace {ns} finishes terminating",
    )
    assert ns_gone["reason"] == "NotFound" and ns_gone["message"] == f'namespaces "{ns}" not found', ns_gone


# ===== helpers =====
_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
# Zone IDs EKS does not support for control-plane subnets.
_EKS_UNSUPPORTED_ZONE_IDS = frozenset({"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"})


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _teardown(fn, *gone_codes):
    """Run one teardown call; only the given not-found codes count as already gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone_codes:
            raise


#: Error codes a read may answer for a moment and then not; any other error is the answer.
_TRANSIENT_CODES = frozenset({"ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded",
                              "ServiceUnavailableException", "ServerException", "InternalFailure"})


def _transient(fn):
    """fn(), or None when it answers a transient error; every other error propagates."""
    try:
        return fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _TRANSIENT_CODES:
            raise
        return None


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result) holds; return the result (raises on timeout)."""
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


def _eks_subnets(ctx) -> list[str]:
    """Two network subnets in two distinct EKS-supported zones."""
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get(
        "Subnets", [])
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZoneId"] in _EKS_UNSUPPORTED_ZONE_IDS:
            continue
        by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need network subnets in >=2 EKS-supported AZs, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:2]


def _eks_cluster_role(ctx) -> str:
    """A role EKS can assume, carrying AmazonEKSClusterPolicy, polled until the attachment reads back."""
    iam = ctx.client("iam")
    role = ctx.unique_name(_PREFIX + "eks-role-")
    arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _drop():
        _teardown(lambda: iam.detach_role_policy(RoleName=role, PolicyArn=_EKS_CLUSTER_POLICY), "NoSuchEntity")
        _teardown(lambda: iam.delete_role(RoleName=role), "NoSuchEntity")

    ctx.on_cleanup(_drop)
    iam.attach_role_policy(RoleName=role, PolicyArn=_EKS_CLUSTER_POLICY)
    _poll_until(
        lambda: _safe(lambda: iam.list_attached_role_policies(RoleName=role)),
        lambda r: any(p["PolicyArn"] == _EKS_CLUSTER_POLICY for p in (r or {}).get("AttachedPolicies", [])),
        ctx=ctx, timeout_s=_budget_s(ctx, 90.0), interval_s=3,
        description=f"AmazonEKSClusterPolicy attached to {role}",
    )
    return arn


def _create_cluster_with_retry(ctx, eks, **kwargs):
    """CreateCluster, retried (bounded) while EKS cannot yet assume a just-created role."""
    deadline = time.monotonic() + _budget_s(ctx, 100.0)
    while True:
        try:
            return eks.create_cluster(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(3)


def _create_access_entry(ctx, eks, cluster, principal_arn, username, group):
    """CreateAccessEntry, retried (bounded) while a just-created role is refused as an invalid principal."""
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            return eks.create_access_entry(clusterName=cluster, principalArn=principal_arn, type="STANDARD",
                                           username=username, kubernetesGroups=[group])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _assume(ctx, role_arn):
    """AssumeRole, retried (bounded): a new role's trust reaches STS after IAM answers it."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-cm-reader")["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() >= deadline:
                raise
        time.sleep(3)


def _k8s_token(ctx, cluster_name, creds=None):
    """k8s-aws-v1.<base64url of a presigned STS GetCallerIdentity URL signing x-k8s-aws-id>, signed as
    *creds* (default: the check's own caller)."""
    override = None
    if creds is not None:
        override = {"aws_access_key_id": creds["AccessKeyId"], "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"]}
    sts = ctx.client("sts", endpoint_url=ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com"),
                     # ctx.client caches per config: a per-cluster user agent keeps the
                     # x-k8s-aws-id hook below off every other STS client.
                     config=Config(user_agent_extra=f"k8s-aws-id/{cluster_name}"), creds=override)
    sts.meta.events.register(
        "before-sign.sts.GetCallerIdentity",
        lambda request, **kwargs: request.headers.add_header("x-k8s-aws-id", cluster_name),
        unique_id=f"k8s-aws-id/{cluster_name}",
    )
    url = sts.generate_presigned_url("get_caller_identity", Params={}, ExpiresIn=60, HttpMethod="GET")
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


def _k8s(ctx, cluster: dict, method: str, path: str, body=None, creds=None):
    """(status, parsed json | text) from the cluster's API server, TLS-validated against its own CA.
    An HTTP error status is returned, not raised; a transport failure returns (None, reason)."""
    ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    ssl_context = ssl.create_default_context(cadata=ca_pem)
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Accept": "application/json", "Authorization": "Bearer " + _k8s_token(ctx, cluster["name"], creds)}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = _routed_request(ctx, cluster["endpoint"].rstrip("/") + path, data=data, headers=headers, method=method)
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
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # transport-level; the caller polls
        return None, f"{type(exc).__name__}: {exc}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
