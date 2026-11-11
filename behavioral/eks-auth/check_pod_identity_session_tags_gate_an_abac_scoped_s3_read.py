"""pod-identity-session-tags-gate-an-abac-scoped-s3-read."""
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


CHECK = "pod-identity-session-tags-gate-an-abac-scoped-s3-read"
GROUP = "overly-permissive"
SERVICES = ["eks-auth"]

_CLUSTER_TIMEOUT_S = 900
_DELETE_TIMEOUT_S = 600
_POLICY_BARRIER_S = 300
_ASSOCIATION_BARRIER_S = 180

_AUDIENCE = "pods.eks.amazonaws.com"
_ABAC_PREFIX = "abac/"
_PLAIN_PREFIX = "plain/"
_FIXTURE_TAGS = [{"Key": "sim2real", "Value": "eks-auth-abac"}]
# Zone IDs EKS does not place control planes in.
_EKS_UNSUPPORTED_ZONE_IDS = frozenset({"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"})


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


def _error_code(fn, desc):
    """The ClientError (code, message) raised by *fn*. RAISES if *fn* unexpectedly SUCCEEDS.

    Returning a falsy sentinel on success would let an over-permissive target pass acceptance off
    as a code mismatch, so success is a hard failure here.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"{desc} was expected to be REFUSED but it SUCCEEDED, returning {result!r}"
    )


def _eks_subnets(ctx):
    """Default-VPC subnets in two distinct EKS-supported AZs.

    Public subnets only: this check needs no compute at all, so it must never provision the NAT
    gateway a private-subnet cluster would drag in.
    """
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


def _create_role(ctx, prefix, trust):
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _FIXTURE_TAGS],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
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


def _create_cluster(ctx):
    """A dedicated, uniquely named cluster with no node group at all.

    Uniquely named so a concurrent sibling in a parallel suite can neither adopt nor delete it,
    and so this check's session-tag mutations cannot race anyone else's.
    """
    eks = ctx.client("eks")
    _name, role_arn = _create_role(
        ctx,
        "sim2real-abac-clus-",
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
    )
    iam = ctx.client("iam")
    cluster_policy = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=_name, PolicyArn=cluster_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=_name, PolicyArn=cluster_policy))

    cluster = ctx.unique_name("sim2real-abac-")[:100]
    # IAM is eventually consistent and CreateCluster validates roleArn synchronously, so the
    # create itself is the bounded retry rather than a bare sleep.
    _wait_for(
        lambda: _try_create_cluster(eks, cluster, role_arn, _eks_subnets(ctx)),
        lambda ok: ok,
        timeout_s=180,
        interval_s=10,
        desc=f"CreateCluster {cluster} to stop failing on the freshly created cluster role",
    )
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster))
    desc = _wait_for(
        lambda: ctx.client("eks").describe_cluster(name=cluster)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {cluster} ACTIVE",
    )
    assert desc["status"] == "ACTIVE", (
        f"cluster {cluster} landed in {desc['status']!r}, expected ACTIVE; health="
        f"{desc.get('health')!r}"
    )
    return cluster, desc["endpoint"], desc["certificateAuthority"]["data"]


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
            tags={t["Key"]: t["Value"] for t in _FIXTURE_TAGS},
        )
        return True
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceInUseException":
            return True
        if code == "InvalidParameterException":
            return False  # role not yet visible to EKS; the caller retries within its deadline
        raise


def _k8s_bearer_token(ctx, cluster_name):
    """k8s-aws-v1.<base64url of a presigned STS GetCallerIdentity URL signing x-k8s-aws-id>.

    Signed through ctx.client("sts")'s OWN request signer rather than by registering a botocore
    event on the cached client: the client ctx hands back is SHARED, botocore appends repeated
    headers, and SigV4 canonicalises `x-k8s-aws-id: <c>,<c>` — which the API server's single-header
    replay then fails to match. The STS endpoint is the one the target's
    customer configures (ctx.service_url).
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


def _k8s(ctx, cluster, endpoint, ca_b64, method, path, body=None, timeout_s=45):
    """(status, parsed body) from the cluster's OWN Kubernetes API server over real TLS.

    TLS is validated against the CA DescribeCluster advertises and nothing else, so this is a
    genuine request to a genuine API server with no boto3 shim in between.
    """
    ssl_ctx = ssl.create_default_context(cadata=base64.b64decode(ca_b64).decode("ascii"))
    data = None if body is None else json.dumps(body).encode()
    req = _routed_request(ctx, endpoint.rstrip("/") + path, data=data, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("Authorization", "Bearer " + _k8s_bearer_token(ctx, cluster))
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


def _k8s_expect(ctx, cluster, endpoint, ca_b64, method, path, body=None, expect=(200, 201)):
    status, parsed = _k8s(ctx, cluster, endpoint, ca_b64, method, path, body=body)
    assert status in expect, (
        f"{method} {path} on the Kubernetes API of {cluster} returned {status}, expected one of "
        f"{expect}: {str(parsed)[:300]}"
    )
    return parsed


def _make_namespace_and_sa(ctx, cluster, endpoint, ca_b64, ns, sa):
    """Namespace + ServiceAccount + a Pod bound to it.

    AssumeRoleForPodIdentity REJECTS a TokenRequest that has no `boundObjectRef`: real AWS replies
    `InvalidTokenException: ... missing required claim - kubernetes.io/pod`. The Pod need not ever
    run — this cluster has no node group and the Pod stays Pending forever — the token request
    controller only needs a Pod object with a matching name+uid to exist, which is why this stays
    free of any compute.
    """
    _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST", "/api/v1/namespaces",
        body={
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": ns, "labels": {"sim2real": "eks-auth-abac"}},
        },
    )
    ctx.on_cleanup(
        lambda: _unless_cluster_gone(ctx, cluster, lambda: _k8s(ctx, cluster, endpoint, ca_b64, "DELETE", f"/api/v1/namespaces/{ns}"))
    )
    _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST", f"/api/v1/namespaces/{ns}/serviceaccounts",
        body={"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": sa}},
    )
    pod = _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST", f"/api/v1/namespaces/{ns}/pods",
        body={
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "sim2real-abac-pod", "labels": {"sim2real": "eks-auth-abac"}},
            "spec": {
                "serviceAccountName": sa,
                "containers": [
                    {
                        "name": "c",
                        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                        "command": ["sleep", "3600"],
                    }
                ],
                "restartPolicy": "Never",
            },
        },
    )
    return "sim2real-abac-pod", pod["metadata"]["uid"]


def _sa_token(ctx, cluster, endpoint, ca_b64, ns, sa, pod_name, pod_uid):
    """A REAL projected ServiceAccount token from the cluster's TokenRequest subresource,
    bound to *pod_name*/*pod_uid* — AssumeRoleForPodIdentity requires the bound claim."""
    resp = _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST",
        f"/api/v1/namespaces/{ns}/serviceaccounts/{sa}/token",
        body={
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "spec": {
                "audiences": [_AUDIENCE],
                "expirationSeconds": 900,
                "boundObjectRef": {
                    "kind": "Pod",
                    "apiVersion": "v1",
                    "name": pod_name,
                    "uid": pod_uid,
                },
            },
        },
    )
    token = resp["status"]["token"]
    assert token.count(".") == 2, f"TokenRequest returned a non-JWT token: {token[:64]!r}"
    return token


def _assume(ctx, cluster, token):
    """AssumeRoleForPodIdentity, retried only over the documented eventual-consistency window.

    Two transient windows, neither the behaviour under test (which lives entirely in the S3
    authorization a returned credential later makes): `InvalidRequestException` while the
    association itself is not yet effective, and `AccessDeniedException: ... EKS does not have
    permissions to assume the associated role` while the pod role's own TRUST policy has not
    yet propagated — as real AWS answers immediately after
    `iam:CreateRole` + `eks:CreatePodIdentityAssociation` for a brand-new role.
    """
    eks_auth = ctx.client("eks-auth")

    def _attempt():
        try:
            return eks_auth.assume_role_for_pod_identity(
                clusterName=cluster, token=token, eksNodeName="sim2real-abac-node"
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "InvalidRequestException":
                return None  # association not yet effective; the caller's deadline bounds this
            if code == "AccessDeniedException" and "assume the associated role" in message:
                return None  # trust policy not yet propagated; same deadline bounds this
            raise

    return _wait_for(
        _attempt,
        lambda r: r is not None,
        timeout_s=_ASSOCIATION_BARRIER_S,
        interval_s=5,
        desc=f"AssumeRoleForPodIdentity on {cluster} to stop reporting InvalidRequestException",
    )


def _s3_as(ctx, creds):
    """An S3 client signing with the VENDED pod-identity credentials.

    ctx.client's `creds` override is the sanctioned re-signing idiom: it keeps THIS target's
    endpoint and TLS wiring while replacing the identity, which is exactly what a hand-rolled
    boto3.client would get wrong.
    """
    return ctx.client(
        "s3",
        creds={
            "aws_access_key_id": creds["accessKeyId"],
            "aws_secret_access_key": creds["secretAccessKey"],
            "aws_session_token": creds["sessionToken"],
        },
    )


def _get(ctx, creds, bucket, key):
    return _s3_as(ctx, creds).get_object(Bucket=bucket, Key=key)["Body"].read()


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """EKS Pod Identity session tags are real ABAC attributes: a PrincipalTag/kubernetes-namespace
    condition grants S3 GetObject to one association and refuses a second in another namespace on the
    same role, disableSessionTags removes and restores it, and an unconditioned read always works.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    eks = ctx.client("eks")

    cluster, endpoint, ca_b64 = _create_cluster(ctx)

    # --- an S3 bucket holding two objects that differ only in which statement can reach them ---
    bucket = f"{ctx.unique_name('sim2real-abac-')}-{account}"[:63]
    create_args = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the ONE region where S3 rejects an explicit LocationConstraint.
        create_args["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_args)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": list(_FIXTURE_TAGS)})
    abac_key = _ABAC_PREFIX + ctx.unique_name("obj-")
    plain_key = _PLAIN_PREFIX + ctx.unique_name("obj-")
    abac_body = f"abac-{ctx.unique_name('')}".encode()
    plain_body = f"plain-{ctx.unique_name('')}".encode()
    s3.put_object(Bucket=bucket, Key=abac_key, Body=abac_body)
    s3.put_object(Bucket=bucket, Key=plain_key, Body=plain_body)

    # --- one role, two namespaces, one inline policy whose ABAC statement names namespace A ---
    ns_a, sa_a = ctx.unique_name("sim2real-abac-a-")[:63].lower(), "sim2real-sa-a"
    ns_b, sa_b = ctx.unique_name("sim2real-abac-b-")[:63].lower(), "sim2real-sa-b"
    pod_a = _make_namespace_and_sa(ctx, cluster, endpoint, ca_b64, ns_a, sa_a)
    pod_b = _make_namespace_and_sa(ctx, cluster, endpoint, ca_b64, ns_b, sa_b)

    pod_role_name, pod_role_arn = _create_role(
        ctx,
        "sim2real-abac-pod-",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "pods.eks.amazonaws.com"},
                    "Action": ["sts:AssumeRole", "sts:TagSession"],
                }
            ],
        },
    )
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                # Reachable ONLY by a session whose pod-identity tags name cluster/ns_a/sa_a.
                "Sid": "AbacScoped",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{_ABAC_PREFIX}*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalTag/eks-cluster-name": cluster,
                        "aws:PrincipalTag/kubernetes-namespace": ns_a,
                        "aws:PrincipalTag/kubernetes-service-account": sa_a,
                    }
                },
            },
            {
                # The twin control group: same role, same bucket, NO condition at all. Its
                # success in the same instant is what makes every refusal below attributable.
                "Sid": "AlwaysAllowed",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{_PLAIN_PREFIX}*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=pod_role_name, PolicyName="abac", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=pod_role_name, PolicyName="abac"))

    assoc_a = eks.create_pod_identity_association(
        clusterName=cluster, namespace=ns_a, serviceAccount=sa_a, roleArn=pod_role_arn,
        tags={t["Key"]: t["Value"] for t in _FIXTURE_TAGS},
    )["association"]
    ctx.on_cleanup(
        lambda: _unless_cluster_gone(ctx, cluster, lambda: eks.delete_pod_identity_association(
            clusterName=cluster, associationId=assoc_a["associationId"]
        ))
    )
    assoc_b = eks.create_pod_identity_association(
        clusterName=cluster, namespace=ns_b, serviceAccount=sa_b, roleArn=pod_role_arn,
        tags={t["Key"]: t["Value"] for t in _FIXTURE_TAGS},
    )["association"]
    ctx.on_cleanup(
        lambda: _unless_cluster_gone(ctx, cluster, lambda: eks.delete_pod_identity_association(
            clusterName=cluster, associationId=assoc_b["associationId"]
        ))
    )
    assert assoc_a["disableSessionTags"] is False, (
        "a freshly created pod identity association must report disableSessionTags=false (session "
        f"tags on by default); got {assoc_a['disableSessionTags']!r}"
    )

    def creds_a():
        token = _sa_token(ctx, cluster, endpoint, ca_b64, ns_a, sa_a, *pod_a)
        return _assume(ctx, cluster, token)["credentials"]

    def creds_b():
        token = _sa_token(ctx, cluster, endpoint, ca_b64, ns_b, sa_b, *pod_b)
        return _assume(ctx, cluster, token)["credentials"]

    # === beat 1: the positive control, and the measurement that bounds every absence below ===
    started = time.monotonic()
    _wait_for(
        lambda: _abac_readable(ctx, creds_a(), bucket, abac_key, abac_body),
        lambda ok: ok,
        timeout_s=_POLICY_BARRIER_S,
        interval_s=10,
        desc=(
            f"the ABAC-conditioned statement to authorize {abac_key} for the association in "
            f"{ns_a} (this is the grant propagating, not the behaviour under test)"
        ),
    )
    grant_latency = max(time.monotonic() - started, 1.0)
    assert _get(ctx, creds_a(), bucket, plain_key) == plain_body, (
        f"the unconditioned statement did not serve {plain_key} to the association in {ns_a}; "
        "the control group must work before any refusal below can be attributed"
    )

    # === beat 2: the tag carries the REAL namespace, not a constant ===
    # Association B differs from A in exactly one thing: which namespace/serviceAccount it binds.
    # Same role, same policy, same object. Its refusal is therefore attributable to the tag VALUE.
    settle = 3 * grant_latency
    code, message, caller_arn = _wait_for(
        lambda: _refusal_code_with_control(ctx, creds_b(), bucket, abac_key, plain_key, plain_body),
        lambda r: r[0] == "AccessDenied",
        timeout_s=max(settle, 60),
        interval_s=10,
        desc=(
            f"the association in {ns_b} to be refused {abac_key} (held for 3x the {grant_latency:.0f}s "
            "the grant itself took, so a merely slower-but-correct target is not scored as blocked)"
        ),
    )
    assert code == "AccessDenied", (
        f"an association in namespace {ns_b} was expected AccessDenied on {abac_key} — the policy "
        f"condition names namespace {ns_a} — but the refusal code was {code!r}"
    )
    expected = _denied_message(caller_arn, bucket, abac_key)
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # === beats 3+4: break exactly one thing — turn the session tags off ===
    eks.update_pod_identity_association(
        clusterName=cluster, associationId=assoc_a["associationId"], disableSessionTags=True
    )
    disabled = eks.describe_pod_identity_association(
        clusterName=cluster, associationId=assoc_a["associationId"]
    )["association"]
    assert disabled["disableSessionTags"] is True, (
        "DescribePodIdentityAssociation must report disableSessionTags=true after the update; got "
        f"{disabled['disableSessionTags']!r}"
    )
    assert disabled["roleArn"] == pod_role_arn, (
        f"the update must have changed ONLY disableSessionTags, but roleArn moved to "
        f"{disabled['roleArn']!r} (expected {pod_role_arn!r})"
    )
    code, message, caller_arn = _wait_for(
        lambda: _refusal_code_with_control(ctx, creds_a(), bucket, abac_key, plain_key, plain_body),
        lambda r: r[0] == "AccessDenied",
        timeout_s=_ASSOCIATION_BARRIER_S,
        interval_s=10,
        desc=(
            f"the association in {ns_a} to lose access to {abac_key} once its session tags are "
            "disabled, while the unconditioned object still reads in the same instant"
        ),
    )
    assert code == "AccessDenied", (
        f"with disableSessionTags=true the ABAC condition has no tags to match and {abac_key} must "
        f"be AccessDenied; got {code!r}"
    )
    expected = _denied_message(caller_arn, bucket, abac_key)
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # === beats 5+6: restore, and demand the IDENTICAL read back ===
    eks.update_pod_identity_association(
        clusterName=cluster, associationId=assoc_a["associationId"], disableSessionTags=False
    )
    restored = eks.describe_pod_identity_association(
        clusterName=cluster, associationId=assoc_a["associationId"]
    )["association"]
    assert restored["disableSessionTags"] is False, (
        "DescribePodIdentityAssociation must report disableSessionTags=false after the restore; got "
        f"{restored['disableSessionTags']!r}"
    )
    _wait_for(
        lambda: _abac_readable(ctx, creds_a(), bucket, abac_key, abac_body),
        lambda ok: ok,
        timeout_s=_ASSOCIATION_BARRIER_S,
        interval_s=10,
        desc=(
            f"re-enabling session tags to restore the association in {ns_a}'s access to {abac_key} "
            "with byte-identical content"
        ),
    )

    # Teardown of the control plane is INLINE, not only in ctx.on_cleanup: the cleanup chain runs
    # under a 60s budget that never affects the verdict, so a cut-off teardown would report PASS
    # while leaking a billable cluster.
    _delete_cluster(ctx, cluster)
    assert _cluster_status(ctx.client("eks"), cluster) == "GONE", (
        f"cluster {cluster} was still describable after an asserted inline delete"
    )


def _abac_readable(ctx, creds, bucket, key, expected):
    """True only when the ABAC-conditioned object reads back with EXACTLY the expected bytes."""
    try:
        body = _get(ctx, creds, bucket, key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "InvalidAccessKeyId"):
            return False
        raise
    assert body == expected, (
        f"{key} was authorized but served {body!r}, expected {expected!r} — the grant is real but "
        "the payload is not"
    )
    return True


def _refusal_code_with_control(ctx, creds, bucket, abac_key, plain_key, plain_body):
    """The refusal (code, message, caller ARN) on the conditioned object, ASSERTING the control
    still reads.

    The control read is inside the poll rather than beside it on purpose (a twin control group read in
    the same instant): a target whose credentials stopped working entirely, or which denies
    everything, must fail here rather than be scored as having correctly blocked.
    """
    assert _get(ctx, creds, bucket, plain_key) == plain_body, (
        f"the unconditioned object {plain_key} stopped serving {plain_body!r} to these credentials; "
        "the refusal on the conditioned object is therefore not attributable to session tags"
    )
    code, message = _error_code(
        lambda: _get(ctx, creds, bucket, abac_key),
        f"GetObject on the ABAC-conditioned {abac_key}",
    )
    caller_arn = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["accessKeyId"],
            "aws_secret_access_key": creds["secretAccessKey"],
            "aws_session_token": creds["sessionToken"],
        },
    ).get_caller_identity()["Arn"]
    return code, message, caller_arn


def _denied_message(caller_arn, bucket, key):
    """The exact AccessDenied message S3 returns when no identity-based policy allows the read."""
    return (
        f"User: {caller_arn} is not authorized to perform: s3:GetObject on resource: "
        f'"arn:aws:s3:::{bucket}/{key}" because no identity-based policy allows the s3:GetObject action'
    )


def _purge_bucket(s3, bucket):
    """Empty then delete the bucket this check created — scoped to this bucket alone."""
    token = None
    while True:
        kw = {"Bucket": bucket, "MaxKeys": 1000}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
        token = page.get("NextContinuationToken")
        if not token:
            break
    s3.delete_bucket(Bucket=bucket)


def _unless_cluster_gone(ctx, name, fn):
    """Run a cluster-scoped teardown unless the cluster is already deleted, which took it along."""
    if _cluster_status(ctx.client("eks"), name) != "GONE":
        fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
