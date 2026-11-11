"""namespace-scoped-access-policy-confines-reads-to-its-namespace."""
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


CHECK = "namespace-scoped-access-policy-confines-reads-to-its-namespace"
GROUP = "access-control"
SERVICES = ["eks"]

# The shared cluster fixture. Adopted, or created and then torn down by its creator only.
_SHARED_CLUSTER = "sim2real-ga-eks-shr"
_CLUSTER_ROLE = "sim2real-ga-eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "ga-depth-eks"}
_BAD_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}

_VIEW_POLICY = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
_CLUSTER_TIMEOUT_S = 1500
_AUTH_FLIP_S = 420
_PROPAGATION_TIMEOUT_S = 300
_NODEGROUP_TIMEOUT_S = 900
_DELETE_RETRY_TIMEOUT_S = 900
_SESSION = "sim2real-nsscope"


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
    """Create-or-adopt the shared fixture's cluster role and return its ARN."""
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": ["sts:AssumeRole"],
            }
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
            # Attaching an already-attached managed policy is a no-op on real AWS; anything else
            # is a real failure and must surface.
            if exc.response["Error"]["Code"] not in ("LimitExceeded", "EntityAlreadyExists"):
                raise
    return arn


def _fixture_subnets(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZone"] not in _BAD_AZS:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= 2, (
        f"EKS needs subnets in >=2 supported AZs; the run's shared network of {ctx.region} offers "
        f"{sorted(by_az)!r}"
    )
    return [by_az[az] for az in sorted(by_az)][:3]


def _adopt_or_create_cluster(ctx):
    """Return the shared ACTIVE cluster. NO node group: this check needs no compute at all."""
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
        f"shared cluster landed in {cluster['status']!r}, expected ACTIVE; health="
        f"{cluster.get('health')!r}"
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


def _k8s_token(ctx, cluster_name, creds=None):
    """The aws-iam-authenticator bearer token for *creds* (default: this check's own caller).

    The API server replays a presigned sts:GetCallerIdentity URL to learn WHICH AWS principal is
    calling, so signing that URL with a second principal's credentials is the only way to make a
    request the API server attributes to that principal. Signed through the client's OWN request
    signer rather than by registering a botocore event: ctx.client hands back a CACHED client,
    botocore appends repeated headers, and SigV4 canonicalises `x-k8s-aws-id: <c>,<c>`, which the
    API server's single-header replay then fails to match. The STS endpoint is the one the
    target's customer configures (ctx.service_url).
    """
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


def _k8s(ctx, conn, method, path, *, body=None, creds=None, timeout_s=45):
    """(status, parsed body) from the cluster's own Kubernetes API server over real TLS."""
    base, ca_pem = conn
    ssl_ctx = ssl.create_default_context(cadata=ca_pem)
    data = None if body is None else json.dumps(body).encode()
    req = _routed_request(ctx, base.rstrip("/") + path, data=data, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("Authorization", "Bearer " + _k8s_token(ctx, _SHARED_CLUSTER, creds))
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


def _k8s_expect(ctx, conn, method, path, *, body=None, creds=None, expect=(200, 201)):
    status, parsed = _k8s(ctx, conn, method, path, body=body, creds=creds)
    assert status in expect, (
        f"{method} {path} returned {status}, expected one of {expect}: {str(parsed)[:300]}"
    )
    return parsed


def _ssar(ctx, conn, creds, namespace, verb, resource):
    """The API server's OWN authorization verdict for the CALLING identity.

    A different operation from both the mutation (AssociateAccessPolicy) and the GET whose status
    it corroborates, rendered by the component that actually decides — which is what makes it the
    terminal read.
    """
    review = _k8s_expect(
        ctx, conn, "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        body={
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": {
                "resourceAttributes": {
                    "namespace": namespace,
                    "verb": verb,
                    "group": "",
                    "resource": resource,
                }
            },
        },
        creds=creds,
        expect=(200, 201),
    )
    allowed = review["status"]["allowed"]
    assert isinstance(allowed, bool), (
        f"SelfSubjectAccessReview must answer with a boolean status.allowed; got {allowed!r} in "
        f"{review['status']!r}"
    )
    return allowed


def _assume(ctx, role_arn):
    """Assume *role_arn*, bounded, because a fresh role's trust policy is eventually consistent."""

    def _attempt():
        try:
            raw = ctx.client("sts").assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)[
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
        timeout_s=_PROPAGATION_TIMEOUT_S,
        interval_s=10,
        desc=f"the freshly created role {role_arn} to become assumable (IAM propagation)",
    )


def _create_access_entry(c, cluster, role_arn):
    """CreateAccessEntry, bounded, over the window where EKS cannot see the fresh IAM role.

    EKS validates principalArn synchronously against IAM and answers InvalidParameterException
    "invalid principal" for a role created seconds earlier — shape-identical to a genuinely
    malformed ARN, with no condition to poll. Exhausting the window FAILS the check.
    """

    def _attempt():
        try:
            return c.create_access_entry(
                clusterName=cluster, principalArn=role_arn, type="STANDARD",
                tags=dict(_FIXTURE_TAGS),
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException":
                return None
            raise

    return _wait_for(
        _attempt,
        lambda r: r is not None,
        timeout_s=_PROPAGATION_TIMEOUT_S,
        interval_s=10,
        desc=f"EKS to accept the freshly created principalArn {role_arn} for an access entry",
    )


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An EKS access policy's namespace scope confines the grant: AmazonEKSViewPolicy scoped to one
    namespace lists pods there and is refused 403 in another, SelfSubjectAccessReview agrees, and
    re-associating the same policy at cluster scope makes the refused read succeed.
    """
    eks = ctx.client("eks")
    conn = _adopt_or_create_cluster(ctx)

    ns_in = ctx.unique_name("sim2real-scope-in-")[:63].lower()
    ns_out = ctx.unique_name("sim2real-scope-out-")[:63].lower()
    for ns in (ns_in, ns_out):
        _k8s_expect(
            ctx, conn, "POST", "/api/v1/namespaces",
            body={
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": ns, "labels": {"sim2real": "ga-depth-eks"}},
            },
        )
        ctx.on_cleanup(lambda n=ns: _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{n}"))

    account = ctx.client("sts").get_caller_identity()["Account"]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-scope-p-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    creds = _assume(ctx, role_arn)

    _create_access_entry(eks, _SHARED_CLUSTER, role_arn)
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: eks.delete_access_entry(
                clusterName=_SHARED_CLUSTER, principalArn=role_arn
            )
        )
    )

    pods_in = f"/api/v1/namespaces/{ns_in}/pods"
    pods_out = f"/api/v1/namespaces/{ns_out}/pods"

    # === The positive control — the grant, scoped to ns_in only ===
    eks.associate_access_policy(
        clusterName=_SHARED_CLUSTER,
        principalArn=role_arn,
        policyArn=_VIEW_POLICY,
        accessScope={"type": "namespace", "namespaces": [ns_in]},
    )
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: eks.disassociate_access_policy(
                clusterName=_SHARED_CLUSTER, principalArn=role_arn, policyArn=_VIEW_POLICY
            )
        )
    )
    associated = eks.list_associated_access_policies(
        clusterName=_SHARED_CLUSTER, principalArn=role_arn
    )["associatedAccessPolicies"]
    scopes = [(a["policyArn"], a["accessScope"]) for a in associated]
    assert (
        _VIEW_POLICY,
        {"type": "namespace", "namespaces": [ns_in]},
    ) in scopes, (
        f"ListAssociatedAccessPolicies must report {_VIEW_POLICY} scoped to namespace [{ns_in!r}]; "
        f"it reports {scopes!r}"
    )

    started = time.monotonic()
    _wait_for(
        lambda: _k8s(ctx, conn, "GET", pods_in, creds=creds)[0],
        lambda s: s == 200,
        timeout_s=_AUTH_FLIP_S,
        interval_s=10,
        desc=(
            f"the namespace-scoped view policy to authorize listing pods in {ns_in} (this is the "
            "grant propagating, and it must work before the refusal below can be attributed to the "
            "scope rather than to the grant not having landed)"
        ),
    )
    flip_latency = max(time.monotonic() - started, 1.0)

    # === Break exactly one thing — the namespace in the path ===
    verdicts = _wait_for(
        lambda: _both_and_review(ctx, conn, creds, pods_in, pods_out, ns_in, ns_out),
        lambda v: v == (200, 403, True, False),
        timeout_s=max(3 * flip_latency, 90),
        interval_s=10,
        desc=(
            f"the namespace scope to confine the grant: pods in {ns_in} allowed and pods in "
            f"{ns_out} forbidden, agreed by both the real request and the API server's own "
            f"authorizer (held for 3x the {flip_latency:.0f}s the grant itself took, so a "
            "correct-but-slower target is not scored as having confined the grant)"
        ),
    )
    assert verdicts == (200, 403, True, False), (
        f"expected (GET {ns_in}, GET {ns_out}, SSAR {ns_in}, SSAR {ns_out}) == (200, 403, True, "
        f"False); got {verdicts!r}"
    )

    # The 403 names the principal, so it is an authorization verdict about THIS identity and not a
    # generic refusal. Read from the Kubernetes Status object the API server returned.
    status_out, body_out = _k8s(ctx, conn, "GET", pods_out, creds=creds)
    assert status_out == 403, f"expected 403 listing pods in {ns_out}; got {status_out}"
    assert body_out.get("reason") == "Forbidden", (
        f"the refusal must be an authorization verdict (reason Forbidden), not an authentication "
        f"one; the Status object says reason={body_out.get('reason')!r}: {str(body_out)[:300]}"
    )
    assert role_name in json.dumps(body_out), (
        f"the Forbidden Status must name the refused principal (role {role_name!r}) so the verdict "
        f"is attributable; it says {str(body_out)[:300]}"
    )

    # SelfSubjectRulesReview cannot corroborate the decision in either namespace: the webhook
    # authorizer behind EKS access entries does not resolve user rules, so the review comes back
    # incomplete without the access-policy grant, identically in both namespaces.
    _WEBHOOK_INCOMPLETE_REASON = "webhook authorizer does not support user rule resolution"
    rules_out = _k8s_expect(
        ctx, conn, "POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
        body={
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectRulesReview",
            "spec": {"namespace": ns_out},
        },
        creds=creds,
        expect=(200, 201),
    )
    rules_in = _k8s_expect(
        ctx, conn, "POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
        body={
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectRulesReview",
            "spec": {"namespace": ns_in},
        },
        creds=creds,
        expect=(200, 201),
    )
    for ns, review in ((ns_out, rules_out), (ns_in, rules_in)):
        status = review["status"]
        assert status.get("incomplete") is True, (
            f"SelfSubjectRulesReview in {ns} must come back incomplete=true on a cluster whose "
            f"access is enforced by the access-entries webhook authorizer (it cannot enumerate "
            f"that authorizer's rules); got incomplete={status.get('incomplete')!r}: "
            f"{str(status)[:300]}"
        )
        assert status.get("evaluationError") == _WEBHOOK_INCOMPLETE_REASON, (
            f"SelfSubjectRulesReview in {ns} must report the webhook authorizer's specific "
            f"evaluationError {_WEBHOOK_INCOMPLETE_REASON!r}; got "
            f"{status.get('evaluationError')!r}: {str(status)[:300]}"
        )

    # === freeze detector: asking the authorizer must not change its answer ===
    answers = [_ssar(ctx, conn, creds, ns_out, "list", "pods") for _ in range(3)]
    assert answers == [False, False, False], (
        f"three consecutive SelfSubjectAccessReviews for {ns_out} must all answer False — a read "
        f"must not advance state; got {answers!r}"
    )

    # === Restore — the SAME policy ARN at cluster scope, and demand the read back ===
    eks.disassociate_access_policy(
        clusterName=_SHARED_CLUSTER, principalArn=role_arn, policyArn=_VIEW_POLICY
    )
    eks.associate_access_policy(
        clusterName=_SHARED_CLUSTER,
        principalArn=role_arn,
        policyArn=_VIEW_POLICY,
        accessScope={"type": "cluster"},
    )
    _wait_for(
        lambda: _both_and_review(ctx, conn, creds, pods_in, pods_out, ns_in, ns_out),
        lambda v: v == (200, 200, True, True),
        timeout_s=_AUTH_FLIP_S,
        interval_s=10,
        desc=(
            f"widening the identical policy ARN to cluster scope to make the previously refused "
            f"read of pods in {ns_out} succeed, agreed by the authorizer"
        ),
    )


def _both_and_review(ctx, conn, creds, path_in, path_out, ns_in, ns_out):
    """(GET status in, GET status out, SSAR allowed in, SSAR allowed out) in ONE instant.

    Read as a tuple rather than sequentially asserted so a refusal can never be produced by a
    target that has stopped answering this principal entirely: the allowed leg is the twin control
    group and the poll cannot settle without it.
    """
    return (
        _k8s(ctx, conn, "GET", path_in, creds=creds)[0],
        _k8s(ctx, conn, "GET", path_out, creds=creds)[0],
        _ssar(ctx, conn, creds, ns_in, "list", "pods"),
        _ssar(ctx, conn, creds, ns_out, "list", "pods"),
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
