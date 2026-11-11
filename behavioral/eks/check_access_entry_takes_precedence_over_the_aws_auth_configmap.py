"""access-entry-takes-precedence-over-the-aws-auth-configmap."""
# The check runs on its own cluster with no node group: kube-system/aws-auth is a cluster
# singleton, and listing pods in an empty namespace is enough of an authorization probe.
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


CHECK = "access-entry-takes-precedence-over-the-aws-auth-configmap"
GROUP = "access-control"
SERVICES = ["eks"]

_CLUSTER_TIMEOUT_S = 900
_DELETE_TIMEOUT_S = 600
_AUTH_FLIP_S = 420
_ASSUME_BARRIER_S = 180

_CM_USER = "sim2real-cm-user"
_CM_GROUP = "sim2real-cm-viewers"
_AE_USER = "sim2real-ae-user"
_AE_GROUP = "sim2real-ae-viewers"
_FIXTURE_TAGS = {"sim2real": "eks-authmap"}
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


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


def _eks_subnets(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZoneId"] not in _BAD_AZS:
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
        ctx.on_cleanup(
            lambda p=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=p)
        )
    return name, arn


def _cluster_status(eks, name):
    try:
        return eks.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _delete_cluster(ctx, name):
    eks = ctx.client("eks")
    try:
        eks.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _wait_for(
        lambda: _cluster_status(eks, name),
        lambda s: s == "GONE",
        timeout_s=_DELETE_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} fully deleted",
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
            # BOTH sources must be live: the precedence rule this check asserts is defined only
            # for API_AND_CONFIG_MAP.
            accessConfig={
                "authenticationMode": "API_AND_CONFIG_MAP",
                "bootstrapClusterCreatorAdminPermissions": True,
            },
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
    _role_name, role_arn = _create_role(
        ctx,
        "sim2real-authmap-clus-",
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
    name = ctx.unique_name("sim2real-authmap-")[:100]
    subnets = _eks_subnets(ctx)
    _wait_for(
        lambda: _try_create_cluster(eks, name, role_arn, subnets),
        lambda ok: ok,
        timeout_s=180,
        interval_s=10,
        desc=f"CreateCluster {name} to stop failing on the freshly created cluster role",
    )
    ctx.on_cleanup(lambda: _delete_cluster(ctx, name))
    cluster = _wait_for(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", (
        f"cluster {name} landed in {cluster['status']!r}, expected ACTIVE; health="
        f"{cluster.get('health')!r}"
    )
    return cluster


def _k8s_bearer_token(ctx, sts, region, cluster_name):
    """k8s-aws-v1.<base64url of a presigned STS GetCallerIdentity URL signing x-k8s-aws-id>.

    Signed with *sts*'s OWN request signer so the identity is whichever identity *sts* carries —
    which is how the same helper mints a token for the cluster creator and for the second
    principal. Signing through the signer rather than by registering a botocore event avoids
    poisoning ctx's SHARED cached client: botocore appends repeated headers and SigV4 canonicalises
    `x-k8s-aws-id: <c>,<c>`, which the API server's single-header replay then fails to match.
    The STS endpoint is the one the target's customer configures (ctx.service_url).
    """
    base = ctx.service_url(f"https://sts.{region}.amazonaws.com")
    request_dict = {
        "method": "GET",
        "url": f"{base}/?Action=GetCallerIdentity&Version=2011-06-15",
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_name},
        "context": {},
    }
    signed = sts._request_signer.generate_presigned_url(
        request_dict, region_name=region, expires_in=300, operation_name="GetCallerIdentity"
    )
    return "k8s-aws-v1." + base64.urlsafe_b64encode(signed.encode()).decode().rstrip("=")


def _k8s(ctx, sts, region, cluster, method, path, body=None, timeout_s=45):
    """(status, parsed body) from the cluster's own Kubernetes API server, signed as *sts*."""
    ssl_ctx = ssl.create_default_context(
        cadata=base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    )
    data = None if body is None else json.dumps(body).encode()
    req = _routed_request(ctx,
        cluster["endpoint"].rstrip("/") + path, data=data, method=method
    )
    req.add_header("Accept", "application/json")
    req.add_header("Authorization", "Bearer " + _k8s_bearer_token(ctx, sts, region, cluster["name"]))
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


def _k8s_expect(ctx, sts, region, cluster, method, path, body=None, expect=(200, 201)):
    status, parsed = _k8s(ctx, sts, region, cluster, method, path, body=body)
    assert status in expect, (
        f"{method} {path} returned {status}, expected one of {expect}: {str(parsed)[:300]}"
    )
    return parsed


def _self_review(ctx, sts, region, cluster):
    """The API server's OWN account of who this token is, in Kubernetes terms.

    A different operation from every mutation in this check, rendered by the component that
    actually resolves the mapping — which is what makes it the terminal read.
    """
    review = _k8s_expect(ctx,
        sts, region, cluster, "POST",
        "/apis/authentication.k8s.io/v1/selfsubjectreviews",
        body={"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"},
        expect=(200, 201),
    )
    return review["status"]["userInfo"]


def _rbac_grant(ctx, admin, region, cluster, ns, role_name, group, resources):
    """A namespaced Role granting get/list on *resources*, bound to the Kubernetes *group*."""
    _k8s_expect(ctx,
        admin, region, cluster, "POST", f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles",
        body={
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": role_name},
            "rules": [{"apiGroups": [""], "resources": list(resources), "verbs": ["get", "list"]}],
        },
    )
    _k8s_expect(ctx,
        admin, region, cluster, "POST",
        f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings",
        body={
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": role_name + "-binding"},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": role_name,
            },
            "subjects": [
                {"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": group}
            ],
        },
    )


def _put_aws_auth(ctx, admin, region, cluster, map_roles):
    """Create-or-adopt kube-system/aws-auth and set mapRoles, returning the PRIOR value.

    Create-or-adopt because a cluster with no node group may have no aws-auth ConfigMap at all,
    while one that already has it must not be clobbered: the prior value is returned so the caller
    can restore it, and an existing foreign mapping is preserved by appending rather than
    replacing.
    """
    status, existing = _k8s(ctx,
        admin, region, cluster, "GET", "/api/v1/namespaces/kube-system/configmaps/aws-auth"
    )
    prior = None
    if status == 200:
        prior = existing.get("data", {}).get("mapRoles")
        merged = json.loads(prior) if prior else []
        merged.extend(map_roles)
        _k8s_expect(ctx,
            admin, region, cluster, "PUT",
            "/api/v1/namespaces/kube-system/configmaps/aws-auth",
            body={
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "aws-auth", "namespace": "kube-system"},
                "data": dict(existing.get("data", {}), mapRoles=json.dumps(merged)),
            },
            expect=(200,),
        )
    else:
        assert status == 404, (
            f"GET kube-system/aws-auth returned {status}, expected 200 or 404: {str(existing)[:300]}"
        )
        _k8s_expect(ctx,
            admin, region, cluster, "POST", "/api/v1/namespaces/kube-system/configmaps",
            body={
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "aws-auth", "namespace": "kube-system"},
                # JSON is valid YAML, so a JSON array is an acceptable mapRoles value and this
                # check needs no YAML dependency.
                "data": {"mapRoles": json.dumps(map_roles)},
            },
        )
    return prior


def _restore_aws_auth(ctx, admin, region, cluster, prior):
    if prior is None:
        _k8s(ctx,
            admin, region, cluster, "DELETE",
            "/api/v1/namespaces/kube-system/configmaps/aws-auth",
        )
        return
    _k8s(ctx,
        admin, region, cluster, "PUT",
        "/api/v1/namespaces/kube-system/configmaps/aws-auth",
        body={
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "aws-auth", "namespace": "kube-system"},
            "data": {"mapRoles": prior},
        },
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
    """An EKS access entry overrides the aws-auth ConfigMap for the same IAM principal: SelfSubjectReview
    reports the entry's username and group with the ConfigMap's group absent and the pod-list verdicts
    flip (403/200), and deleting the entry falls back to the ConfigMap mapping.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    eks = ctx.client("eks")
    admin_sts = ctx.client("sts")
    region = ctx.region

    cluster = _create_cluster(ctx)
    assert cluster["accessConfig"]["authenticationMode"] == "API_AND_CONFIG_MAP", (
        "the precedence rule under test is defined only for API_AND_CONFIG_MAP, but DescribeCluster "
        f"reports authenticationMode={cluster['accessConfig']['authenticationMode']!r}"
    )

    # --- a SECOND IAM principal, so the two mappings can compete over one identity ---
    principal_name, principal_arn = _create_role(
        ctx,
        "sim2real-authmap-p-",
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
    assumed = _wait_for(
        lambda: _try_assume(admin_sts, principal_arn),
        lambda c: c is not None,
        timeout_s=_ASSUME_BARRIER_S,
        interval_s=5,
        desc=f"the freshly created role {principal_name} to become assumable (IAM propagation)",
    )
    p_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": assumed["AccessKeyId"],
            "aws_secret_access_key": assumed["SecretAccessKey"],
            "aws_session_token": assumed["SessionToken"],
        },
    )

    # --- two namespaces and two disjoint RBAC grants, one per Kubernetes group ---
    ns_pods = ctx.unique_name("sim2real-am-pods-")[:63].lower()
    ns_cms = ctx.unique_name("sim2real-am-cms-")[:63].lower()
    for ns in (ns_pods, ns_cms):
        _k8s_expect(ctx,
            admin_sts, region, cluster, "POST", "/api/v1/namespaces",
            body={
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": ns, "labels": dict(_FIXTURE_TAGS)},
            },
        )
        ctx.on_cleanup(
            lambda n=ns: _unless_cluster_gone(ctx, cluster["name"], lambda: _k8s(ctx, admin_sts, region, cluster, "DELETE", f"/api/v1/namespaces/{n}"))
        )
    _rbac_grant(ctx, admin_sts, region, cluster, ns_pods, "sim2real-pod-reader", _CM_GROUP, ["pods"])
    _rbac_grant(ctx, admin_sts, region, cluster, ns_cms, "sim2real-cm-reader", _AE_GROUP, ["configmaps"])

    pods_path = f"/api/v1/namespaces/{ns_pods}/pods"
    cms_path = f"/api/v1/namespaces/{ns_cms}/configmaps"

    # === leg 1: the ConfigMap path alone, and the latency measurement that bounds the rest ===
    prior = _put_aws_auth(ctx,
        admin_sts, region, cluster,
        [{"rolearn": principal_arn, "username": _CM_USER, "groups": [_CM_GROUP]}],
    )
    ctx.on_cleanup(lambda: _unless_cluster_gone(
        ctx, cluster["name"], lambda: _restore_aws_auth(ctx, admin_sts, region, cluster, prior)))

    started = time.monotonic()
    _wait_for(
        lambda: _k8s(ctx, p_sts, region, cluster, "GET", pods_path)[0],
        lambda s: s == 200,
        timeout_s=_AUTH_FLIP_S,
        interval_s=10,
        desc=(
            f"the aws-auth ConfigMap mapping to authorize {_CM_USER} to list pods in {ns_pods} "
            "(this is the ConfigMap path propagating, and it must work before any access entry "
            "exists or the precedence claim below is untestable)"
        ),
    )
    flip_latency = max(time.monotonic() - started, 1.0)

    info = _self_review(ctx, p_sts, region, cluster)
    assert info["username"] == _CM_USER, (
        f"with only an aws-auth mapping present, the API server must resolve this principal to the "
        f"ConfigMap's username {_CM_USER!r}; SelfSubjectReview reported {info['username']!r}"
    )
    assert _CM_GROUP in info["groups"], (
        f"the ConfigMap mapping's group {_CM_GROUP!r} is missing from userInfo.groups "
        f"{info['groups']!r}"
    )
    assert _AE_GROUP not in info["groups"], (
        f"no access entry exists yet, so {_AE_GROUP!r} must not appear in userInfo.groups "
        f"{info['groups']!r}"
    )
    cms_status, cms_body = _k8s(ctx, p_sts, region, cluster, "GET", cms_path)
    assert cms_status == 403, (
        f"the ConfigMap mapping grants pods in {ns_pods} only, so listing configmaps in {ns_cms} "
        f"must be 403; got {cms_status} {str(cms_body)[:300]}"
    )

    # === leg 2: break exactly one thing — add an access entry for the IDENTICAL principal ARN ===
    eks.create_access_entry(
        clusterName=cluster["name"],
        principalArn=principal_arn,
        type="STANDARD",
        username=_AE_USER,
        kubernetesGroups=[_AE_GROUP],
        tags=dict(_FIXTURE_TAGS),
    )
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: eks.delete_access_entry(
                clusterName=cluster["name"], principalArn=principal_arn
            )
        )
    )
    entry = eks.describe_access_entry(
        clusterName=cluster["name"], principalArn=principal_arn
    )["accessEntry"]
    assert entry["username"] == _AE_USER and entry["kubernetesGroups"] == [_AE_GROUP], (
        f"DescribeAccessEntry must echo username={_AE_USER!r} groups=[{_AE_GROUP!r}]; got "
        f"username={entry['username']!r} groups={entry['kubernetesGroups']!r}"
    )

    info = _wait_for(
        lambda: _self_review(ctx, p_sts, region, cluster),
        lambda i: i["username"] == _AE_USER,
        timeout_s=_AUTH_FLIP_S,
        interval_s=10,
        desc=(
            f"the access entry to take precedence, so SelfSubjectReview reports {_AE_USER!r} "
            f"instead of the ConfigMap's {_CM_USER!r}"
        ),
    )
    # THE assertion: replacement, not union. A merging target keeps _CM_GROUP here.
    assert _AE_GROUP in info["groups"], (
        f"the access entry's group {_AE_GROUP!r} is missing from userInfo.groups {info['groups']!r} "
        "even though the username already flipped to the access entry's"
    )
    assert _CM_GROUP not in info["groups"], (
        f"the access entry must REPLACE the aws-auth mapping, not merge with it, but the "
        f"ConfigMap's group {_CM_GROUP!r} is still in userInfo.groups {info['groups']!r}"
    )
    # ... and the consequence, in both directions, with each read acting as the other's control.
    _wait_for(
        lambda: _both(ctx, p_sts, region, cluster, cms_path, pods_path),
        lambda pair: pair == (200, 403),
        timeout_s=max(3 * flip_latency, 60),
        interval_s=10,
        desc=(
            f"the access entry's grant to settle: configmaps in {ns_cms} allowed and pods in "
            f"{ns_pods} forbidden (held for 3x the {flip_latency:.0f}s the ConfigMap grant itself "
            "took, so a correct-but-slower target is not scored as having withdrawn the group)"
        ),
    )

    # === leg 3: restore — delete the access entry and demand the ConfigMap mapping back ===
    eks.delete_access_entry(clusterName=cluster["name"], principalArn=principal_arn)
    info = _wait_for(
        lambda: _self_review(ctx, p_sts, region, cluster),
        lambda i: i["username"] == _CM_USER,
        timeout_s=_AUTH_FLIP_S,
        interval_s=10,
        desc=(
            f"deleting the access entry to fall BACK to the aws-auth mapping, so SelfSubjectReview "
            f"reports {_CM_USER!r} again"
        ),
    )
    assert _CM_GROUP in info["groups"] and _AE_GROUP not in info["groups"], (
        f"after the access entry is deleted the ConfigMap's group {_CM_GROUP!r} must be back and "
        f"{_AE_GROUP!r} gone; userInfo.groups is {info['groups']!r}"
    )
    _wait_for(
        lambda: _both(ctx, p_sts, region, cluster, pods_path, cms_path),
        lambda pair: pair == (200, 403),
        timeout_s=max(3 * flip_latency, 60),
        interval_s=10,
        desc=(
            f"the identical requests to flip back: pods in {ns_pods} allowed again and configmaps "
            f"in {ns_cms} forbidden again"
        ),
    )

    _delete_cluster(ctx, cluster["name"])
    assert _cluster_status(eks, cluster["name"]) == "GONE", (
        f"cluster {cluster['name']} was still describable after an asserted inline delete"
    )


def _both(ctx, sts, region, cluster, allowed_path, forbidden_path):
    """(status of the read that should be allowed, status of the read that should be forbidden).

    Read as a PAIR in the same instant so a forbidden verdict can never be produced by a target
    that has stopped answering this principal at all — the allowed leg is the twin control group
    and the poll cannot settle without it.
    """
    return (
        _k8s(ctx, sts, region, cluster, "GET", allowed_path)[0],
        _k8s(ctx, sts, region, cluster, "GET", forbidden_path)[0],
    )


def _try_assume(sts, role_arn):
    try:
        return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-authmap")["Credentials"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "MalformedPolicyDocument"):
            return None  # trust policy not yet propagated; the caller's deadline bounds this
        raise


def _swallow_not_found(fn):
    """Cleanup-only: a delete of something the body already deleted is not a failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _unless_cluster_gone(ctx, name, fn):
    """Run a cluster-scoped teardown unless the cluster is already deleted, which took it along."""
    if _cluster_status(ctx.client("eks"), name) != "GONE":
        fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
