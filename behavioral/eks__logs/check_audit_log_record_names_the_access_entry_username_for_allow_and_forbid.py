"""audit-log-record-names-the-access-entry-username-for-allow-and-forbid."""
from __future__ import annotations

import base64
import datetime as dt
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


CHECK = "audit-log-record-names-the-access-entry-username-for-allow-and-forbid"
GROUP = "control-plane-logging"
SERVICES = ["eks", "logs"]

_CLUSTER_TIMEOUT_S = 900
_DELETE_TIMEOUT_S = 600
_AUDIT_DELIVERY_S = 900
_PROPAGATION_TIMEOUT_S = 300
_AUTH_FLIP_S = 420
_CLOCK_SLACK_S = 60

_AE_GROUP = "sim2real-audit-writers"
_FIXTURE_TAGS = {"sim2real": "eks-audit"}
# Zone IDs EKS does not support for control-plane subnets.
_EKS_UNSUPPORTED_ZONE_IDS = frozenset({"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"})
_AUDIT_STREAM_PREFIX = "kube-apiserver-audit"
_DECISION_KEY = "authorization.k8s.io/decision"


def _wait_for(fn, pred, *, timeout_s, interval_s, desc, ctx=None):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{desc}: the run budget ended first; not graded")
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _eks_subnets(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZoneId"] not in _EKS_UNSUPPORTED_ZONE_IDS:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= 2, (
        f"EKS needs subnets in >=2 supported AZs; the run's shared network of {ctx.region} offers "
        f"{sorted(by_az)!r}"
    )
    return [by_az[az] for az in sorted(by_az)][:2]


def _create_role(ctx, prefix, trust, managed=()):
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    for policy_arn in managed:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=p))
    return name, arn


def _cluster_status(eks, name):
    try:
        return eks.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _delete_cluster(ctx, name, timeout_s=_DELETE_TIMEOUT_S, budget_ctx=None):
    eks = ctx.client("eks")
    try:
        eks.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _wait_for(
        lambda: _cluster_status(eks, name),
        lambda s: s == "GONE",
        timeout_s=timeout_s,
        interval_s=2,
        desc=f"cluster {name} fully deleted",
        ctx=budget_ctx,
    )


def _try_create_cluster(eks, name, role_arn, subnets):
    try:
        eks.create_cluster(
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
            # ONLY audit: its records are the ones that carry an authorization decision.
            logging={"clusterLogging": [{"types": ["audit"], "enabled": True}]},
            tags=dict(_FIXTURE_TAGS),
        )
        return True
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceInUseException":
            return True
        if code == "InvalidParameterException":
            return False  # the freshly created cluster role is not visible to EKS yet
        raise


def _create_cluster(ctx):
    eks = ctx.client("eks")
    _name, role_arn = _create_role(
        ctx,
        "sim2real-audit-clus-",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "eks.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        managed=("arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",),
    )
    name = ctx.unique_name("sim2real-audit-")[:100]
    subnets = _eks_subnets(ctx)
    _wait_for(
        lambda: _try_create_cluster(eks, name, role_arn, subnets),
        lambda ok: ok,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 180),
        interval_s=2,
        desc=f"CreateCluster {name} to stop failing on the freshly created cluster role",
    )
    ctx.on_cleanup(lambda: _delete_cluster(ctx, name))
    cluster = _wait_for(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _CLUSTER_TIMEOUT_S),
        interval_s=2,
        desc=f"cluster {name} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", (
        f"cluster {name} landed in {cluster['status']!r}, expected ACTIVE; health="
        f"{cluster.get('health')!r}"
    )
    enabled = [
        e for e in cluster["logging"]["clusterLogging"] if e["enabled"] and "audit" in e["types"]
    ]
    assert enabled, (
        "DescribeCluster must report audit logging enabled before any delivery claim is made; "
        f"logging is {cluster['logging']!r}"
    )
    return cluster


def _k8s_token(ctx, cluster_name, creds=None):
    """The aws-iam-authenticator bearer token for *creds* (default: this check's own caller).

    Signed via the client's own signer, not a botocore event on the shared client: repeated
    `x-k8s-aws-id` headers break the API server's SigV4 replay."""
    sts = ctx.client("sts") if creds is None else ctx.client("sts", creds=creds)
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


def _k8s(ctx, cluster, method, path, *, body=None, creds=None, timeout_s=45):
    ssl_ctx = ssl.create_default_context(
        cadata=base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    )
    data = None if body is None else json.dumps(body).encode()
    req = _routed_request(ctx, cluster["endpoint"].rstrip("/") + path, data=data, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("Authorization", "Bearer " + _k8s_token(ctx, cluster["name"], creds))
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


def _k8s_expect(ctx, cluster, method, path, *, body=None, creds=None, expect=(200, 201)):
    status, parsed = _k8s(ctx, cluster, method, path, body=body, creds=creds)
    assert status in expect, (
        f"{method} {path} returned {status}, expected one of {expect}: {str(parsed)[:300]}"
    )
    return parsed


def _assume(ctx, role_arn):
    def _attempt():
        try:
            raw = ctx.client("sts").assume_role(RoleArn=role_arn, RoleSessionName="sim2real-audit")[
                "Credentials"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDenied", "MalformedPolicyDocument"):
                return None
            raise
        return {
            "aws_access_key_id": raw["AccessKeyId"],
            "aws_secret_access_key": raw["SecretAccessKey"],
            "aws_session_token": raw["SessionToken"],
        }

    return _wait_for(
        _attempt,
        lambda c: c is not None,
        ctx=ctx,
        timeout_s=_budget_s(ctx, _PROPAGATION_TIMEOUT_S),
        interval_s=2,
        desc=f"the freshly created role {role_arn} to become assumable (IAM propagation)",
    )


def _create_access_entry(ctx, eks, cluster, role_arn, username):
    def _attempt():
        try:
            return eks.create_access_entry(
                clusterName=cluster,
                principalArn=role_arn,
                type="STANDARD",
                username=username,
                kubernetesGroups=[_AE_GROUP],
                tags=dict(_FIXTURE_TAGS),
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException":
                return None  # EKS cannot see the fresh IAM role yet
            raise

    return _wait_for(
        _attempt,
        lambda r: r is not None,
        ctx=ctx,
        timeout_s=_budget_s(ctx, _PROPAGATION_TIMEOUT_S),
        interval_s=2,
        desc=f"EKS to accept principalArn {role_arn} for an access entry named {username}",
    )


def _rbac_create_configmaps(ctx, cluster, ns):
    """A namespaced Role letting _AE_GROUP create/list configmaps in *ns*, and only there.

    `list` is required: the propagation barrier GETs the COLLECTION endpoint, which RBAC authorizes
    as `list`, not `get`."""
    _k8s_expect(
        ctx, cluster, "POST", f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles",
        body={
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "sim2real-cm-writer"},
            "rules": [
                {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create", "list"]}
            ],
        },
    )
    _k8s_expect(
        ctx, cluster, "POST", f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings",
        body={
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "sim2real-cm-writer-binding"},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "sim2real-cm-writer",
            },
            "subjects": [
                {"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": _AE_GROUP}
            ],
        },
    )


def _audit_record(logs, group, cw_needle, since, match):
    """The single audit event *match* accepts among those containing *cw_needle*, or None while it
    has not arrived. `startTime` bounds the scan: an unbounded FilterLogEvents scan can return an
    empty page that is indistinguishable from "not delivered yet"."""
    since_ms = int(since.timestamp() * 1000)
    try:
        page = logs.filter_log_events(
            logGroupName=group,
            logStreamNamePrefix=_AUDIT_STREAM_PREFIX,
            filterPattern=f'"{cw_needle}"',
            startTime=since_ms,
            limit=50,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None  # the group or the audit streams have not been created yet
        raise
    records = []
    for event in page.get("events", []):
        try:
            parsed = json.loads(event["message"])
        except ValueError:
            continue
        if parsed.get("kind") == "Event" and match(parsed):
            records.append(parsed)
    if not records:
        return None
    assert len(records) == 1, (
        f"expected exactly ONE audit record matching {cw_needle!r}; found {len(records)} — "
        f"the filter is not discriminating: {[r.get('auditID') for r in records]!r}"
    )
    return records[0]


def _parse_rfc3339(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


@tags(
    "axis:happy-path",
    "cap:c7",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An access-entry principal's allowed ConfigMap create and its RBAC-denied twin both land as
    audit records naming the chosen Kubernetes username (not the IAM ARN), 201/allow vs 403/forbid;
    the denied object never exists and both timestamps fall inside the check's own clock window.

    Reference: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
    Reference: https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    eks = ctx.client("eks")
    logs = ctx.client("logs")

    cluster = _create_cluster(ctx)
    log_group = f"/aws/eks/{cluster['name']}/cluster"
    # EKS creates this group and DeleteCluster does not remove it, so this check owns it.
    ctx.on_cleanup(lambda: _swallow_not_found_logs(lambda: logs.delete_log_group(
        logGroupName=log_group
    )))

    ns_allow = ctx.unique_name("sim2real-audit-ok-")[:63].lower()
    ns_deny = ctx.unique_name("sim2real-audit-no-")[:63].lower()
    for ns in (ns_allow, ns_deny):
        _k8s_expect(
            ctx, cluster, "POST", "/api/v1/namespaces",
            body={
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": ns, "labels": dict(_FIXTURE_TAGS)},
            },
        )
    _rbac_create_configmaps(ctx, cluster, ns_allow)  # ... and deliberately NOT in ns_deny

    _role_name, role_arn = _create_role(
        ctx,
        "sim2real-audit-p-",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    )
    creds = _assume(ctx, role_arn)

    # The username is CHOSEN here, so no default can guess it.
    username = ctx.unique_name("sim2real-audit-user-")[:60]
    _create_access_entry(ctx, eks, cluster["name"], role_arn, username)
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: eks.delete_access_entry(
                clusterName=cluster["name"], principalArn=role_arn
            )
        )
    )

    allow_name = ctx.unique_name("sim2real-cm-ok-")[:63].lower()
    deny_name = ctx.unique_name("sim2real-cm-no-")[:63].lower()

    # --- barrier: the mapping must demonstrably work before either record is expected ---
    _wait_for(
        lambda: _k8s(
            ctx, cluster, "GET", f"/api/v1/namespaces/{ns_allow}/configmaps", creds=creds
        )[0],
        lambda s: s == 200,
        ctx=ctx,
        timeout_s=_budget_s(ctx, _AUTH_FLIP_S),
        interval_s=2,
        desc=(
            f"the access entry to map {username} into {_AE_GROUP} so it can read configmaps in "
            f"{ns_allow} (mapping propagation, not the behaviour under test)"
        ),
    )

    # --- the two requests, bracketed by this check's own clock (with slack for clock skew) ---
    t0 = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=_CLOCK_SLACK_S)
    _k8s_expect(
        ctx, cluster, "POST", f"/api/v1/namespaces/{ns_allow}/configmaps",
        body={
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": allow_name},
            "data": {"sim2real": "audit"},
        },
        creds=creds,
        expect=(201,),
    )
    deny_status, deny_body = _k8s(
        ctx, cluster, "POST", f"/api/v1/namespaces/{ns_deny}/configmaps",
        body={
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": deny_name},
            "data": {"sim2real": "audit"},
        },
        creds=creds,
    )
    t1 = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=_CLOCK_SLACK_S)
    assert deny_status == 403, (
        f"creating a configmap in {ns_deny}, where {username} has no RBAC, must be 403; got "
        f"{deny_status} {str(deny_body)[:300]}"
    )

    # --- effect-absent at the destination it was refused ---
    absent_status, absent_body = _k8s(
        ctx, cluster, "GET", f"/api/v1/namespaces/{ns_deny}/configmaps/{deny_name}"
    )
    assert absent_status == 404, (
        f"the refused ConfigMap {deny_name!r} must not exist in {ns_deny}; a read as the cluster "
        f"admin returned {absent_status} {str(absent_body)[:300]}"
    )

    # === terminal read at the CONSUMER: the delivered record's own content ===
    allowed = _wait_for(
        lambda: _audit_record(
            logs, log_group, allow_name, t0,
            lambda r: r.get("verb") == "create" and (r.get("objectRef") or {}).get("name") == allow_name,
        ),
        lambda r: r is not None,
        ctx=ctx,
        timeout_s=_budget_s(ctx, _AUDIT_DELIVERY_S),
        interval_s=2,
        desc=(
            f"the audit record for the allowed ConfigMap create ({allow_name}) to be delivered "
            f"into {log_group}; this arrival is the positive control that bounds the forbid leg "
            "below"
        ),
    )
    assert allowed["user"]["username"] == username, (
        f"the audit record must name the ACCESS ENTRY's Kubernetes username {username!r}, not the "
        f"IAM caller; it says user.username={allowed['user']['username']!r}"
    )
    assert allowed["verb"] == "create", (
        f"the audit record's verb must be 'create'; it is {allowed['verb']!r}"
    )
    ref = allowed["objectRef"]
    assert (ref["resource"], ref["namespace"], ref["name"]) == ("configmaps", ns_allow, allow_name), (
        "the audit record's objectRef must name the exact resource, namespace and object created; "
        f"it says {(ref.get('resource'), ref.get('namespace'), ref.get('name'))!r}, expected "
        f"{('configmaps', ns_allow, allow_name)!r}"
    )
    assert allowed["responseStatus"]["code"] == 201, (
        f"the audit record for a successful create must carry responseStatus.code 201; it carries "
        f"{allowed['responseStatus']['code']!r}"
    )
    assert allowed["annotations"][_DECISION_KEY] == "allow", (
        f"the audit record must carry {_DECISION_KEY}='allow'; its annotations are "
        f"{allowed['annotations']!r}"
    )
    received = _parse_rfc3339(allowed["requestReceivedTimestamp"])
    assert t0 <= received <= t1, (
        f"requestReceivedTimestamp {received.isoformat()} is outside the window this check measured "
        f"with its own clock [{t0.isoformat()}, {t1.isoformat()}] — a record stamped on read, or "
        "backdated, fails here"
    )

    # A denied create is refused before its body is decoded, so its objectRef never carries a
    # `name`. The namespace is the only needle guaranteed to appear verbatim in that record's text,
    # and `match` disambiguates it from the cluster-admin's own absence-check GET.
    forbidden = _wait_for(
        lambda: _audit_record(
            logs, log_group, ns_deny, t0,
            lambda r: (
                r.get("verb") == "create"
                and (r.get("objectRef") or {}).get("namespace") == ns_deny
                and (r.get("objectRef") or {}).get("resource") == "configmaps"
                and (r.get("user") or {}).get("username") == username
            ),
        ),
        lambda r: r is not None,
        ctx=ctx,
        timeout_s=_budget_s(ctx, _AUDIT_DELIVERY_S),
        interval_s=2,
        desc=(
            f"the audit record for the FORBIDDEN ConfigMap create in {ns_deny} to be delivered "
            "into the same group — the allowed record already arrived, so the pipeline is proven "
            "and an absence here is the target's, not the wiring's"
        ),
    )
    assert forbidden["user"]["username"] == username, (
        f"the forbidden request's audit record must name the same username {username!r}; it says "
        f"{forbidden['user']['username']!r}"
    )
    assert forbidden["responseStatus"]["code"] == 403, (
        f"the forbidden request's audit record must carry responseStatus.code 403; it carries "
        f"{forbidden['responseStatus']['code']!r}"
    )
    assert forbidden["annotations"][_DECISION_KEY] == "forbid", (
        f"the forbidden request's audit record must carry {_DECISION_KEY}='forbid'; its annotations "
        f"are {forbidden['annotations']!r}"
    )
    forbidden_ref = forbidden["objectRef"]
    assert forbidden_ref.get("resource") == "configmaps" and forbidden_ref.get("namespace") == ns_deny, (
        "the forbidden record's objectRef must name the resource type and namespace the request "
        f"targeted; it says {(forbidden_ref.get('resource'), forbidden_ref.get('namespace'))!r}"
    )
    assert "name" not in forbidden_ref, (
        "an RBAC-denied create is refused before the API server decodes the request body, so the "
        "object name it lives in must never reach the audit record's objectRef — measured on real "
        f"AWS; it says name={forbidden_ref.get('name')!r}, which would mean a name that was never "
        "extracted leaked into the audit trail anyway"
    )
    assert allowed["auditID"] != forbidden["auditID"], (
        f"the two records must be distinct audit events; both report auditID "
        f"{allowed['auditID']!r}"
    )

    _delete_cluster(ctx, cluster["name"], timeout_s=_budget_s(ctx, _DELETE_TIMEOUT_S), budget_ctx=ctx)
    assert _cluster_status(eks, cluster["name"]) == "GONE", (
        f"cluster {cluster['name']} was still describable after an asserted inline delete"
    )


def _swallow_not_found(fn):
    """Cleanup-only: deleting something the body already deleted is not a failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _swallow_not_found_logs(fn):
    """Cleanup-only, CloudWatch Logs spelling of the same not-found code."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
