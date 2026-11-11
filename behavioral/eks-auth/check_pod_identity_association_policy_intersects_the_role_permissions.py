"""pod-identity-association-policy-intersects-the-role-permissions."""
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


CHECK = "pod-identity-association-policy-intersects-the-role-permissions"
GROUP = "overly-permissive"
SERVICES = ["eks-auth"]

_CLUSTER_TIMEOUT_S = 900
_DELETE_TIMEOUT_S = 600
_POLICY_BARRIER_S = 300
# Long enough for a new or changed association `policy` to reach AssumeRoleForPodIdentity.
_ASSOCIATION_BARRIER_S = 180

_AUDIENCE = "pods.eks.amazonaws.com"
_FIXTURE_TAGS = {"sim2real": "eks-auth-sesspol"}
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


def _client_error(fn, desc):
    """The ClientError (code, message) raised by *fn*; raise if *fn* unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"{desc} was expected to be REFUSED but it SUCCEEDED, returning {result!r}"
    )


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
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=p))
    return name, arn


def _cluster_status(eks, name):
    try:
        return eks.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _if_cluster_exists(ctx, name, fn):
    """Run a cluster-scoped teardown *fn* only while the cluster exists: the run deletes the
    cluster inline, which removes its pods, namespaces and associations with it."""
    if _cluster_status(ctx.client("eks"), name) != "GONE":
        fn()


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
            return False
        raise


def _create_cluster(ctx):
    """A dedicated, uniquely named cluster with no node group: this check needs no compute."""
    eks = ctx.client("eks")
    _name, role_arn = _create_role(
        ctx,
        "sim2real-sesspol-clus-",
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
    name = ctx.unique_name("sim2real-sesspol-")[:100]
    subnets = _eks_subnets(ctx)
    _wait_for(
        lambda: _try_create_cluster(eks, name, role_arn, subnets),
        lambda ok: ok,
        timeout_s=180,
        interval_s=10,
        desc=f"CreateCluster {name} to stop failing on the freshly created cluster role",
    )
    ctx.on_cleanup(lambda: _delete_cluster(ctx, name))
    desc = _wait_for(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} ACTIVE",
    )
    assert desc["status"] == "ACTIVE", (
        f"cluster {name} landed in {desc['status']!r}, expected ACTIVE; health={desc.get('health')!r}"
    )
    return name, desc["endpoint"], desc["certificateAuthority"]["data"]


def _k8s_bearer_token(ctx, cluster_name):
    """k8s-aws-v1.<base64url of a presigned STS GetCallerIdentity URL signing x-k8s-aws-id>.

    Signed via the client's own signer: an event hook on a shared client repeats the header.
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


def _create_pod(ctx, cluster, endpoint, ca_b64, ns, sa, name):
    """A never-scheduled Pod the token is bound to: AssumeRoleForPodIdentity rejects a token
    without the `kubernetes.io/pod` claim, which TokenRequest adds only for a bound Pod."""
    resp = _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST", f"/api/v1/namespaces/{ns}/pods",
        body={
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": name, "labels": dict(_FIXTURE_TAGS)},
            "spec": {
                "serviceAccountName": sa,
                "containers": [{"name": "sim2real", "image": "public.ecr.aws/eks-distro/pause:3.2"}],
            },
        },
    )
    return resp["metadata"]["uid"]


def _sa_token(ctx, cluster, endpoint, ca_b64, ns, sa, pod_name, pod_uid):
    resp = _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST",
        f"/api/v1/namespaces/{ns}/serviceaccounts/{sa}/token",
        body={
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "spec": {
                "audiences": [_AUDIENCE],
                "expirationSeconds": 900,
                "boundObjectRef": {"kind": "Pod", "apiVersion": "v1", "name": pod_name, "uid": pod_uid},
            },
        },
    )
    token = resp["status"]["token"]
    assert token.count(".") == 2, f"TokenRequest returned a non-JWT token: {token[:64]!r}"
    return token


_ASSOC_NOT_READY_MSG = "EKS does not have permissions to assume the associated role"


def _assume(ctx, cluster, token):
    """Retry while a new or updated association propagates: InvalidRequestException, or
    AccessDeniedException with _ASSOC_NOT_READY_MSG. Any other AccessDenied is a real refusal.
    """
    eks_auth = ctx.client("eks-auth")

    def _attempt():
        try:
            return eks_auth.assume_role_for_pod_identity(
                clusterName=cluster, token=token, eksNodeName="sim2real-sesspol-node"
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "InvalidRequestException":
                return None
            if code == "AccessDeniedException" and _ASSOC_NOT_READY_MSG in message:
                return None
            raise

    return _wait_for(
        _attempt,
        lambda r: r is not None,
        timeout_s=_ASSOCIATION_BARRIER_S,
        interval_s=5,
        desc=(
            f"AssumeRoleForPodIdentity on {cluster} to stop reporting InvalidRequestException or "
            f"{_ASSOC_NOT_READY_MSG!r}"
        ),
    )


def _s3_denied_message(session_arn, action, bucket, key, policy_kind):
    """S3's exact AccessDenied message for *session_arn* refused *action* on bucket/key, where
    *policy_kind* is "identity-based" (the role lacks it) or "session" (the session policy omits it)."""
    return (
        f"User: {session_arn} is not authorized to perform: {action} on resource: "
        f'"arn:aws:s3:::{bucket}/{key}" because no {policy_kind} policy allows the {action} action'
    )


def _s3_as(ctx, creds):
    """An S3 client signing with the VENDED pod-identity credentials (ctx's sanctioned override)."""
    return ctx.client(
        "s3",
        creds={
            "aws_access_key_id": creds["accessKeyId"],
            "aws_secret_access_key": creds["secretAccessKey"],
            "aws_session_token": creds["sessionToken"],
        },
    )


def _session_policy(bucket, actions):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": sorted(actions),
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        }
    )


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
    """A Pod Identity association `policy` acts as a session policy intersected with the role:
    a ListBucket-only policy removes GetObject while ListBucket keeps working, and a policy naming
    s3:DeleteObject, which the role lacks, still cannot delete.

    Reference: https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdatePodIdentityAssociation.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    eks = ctx.client("eks")

    cluster, endpoint, ca_b64 = _create_cluster(ctx)

    bucket = f"{ctx.unique_name('sim2real-sesspol-')}-{account}"[:63]
    create_args = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the ONE region where S3 rejects an explicit LocationConstraint.
        create_args["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_args)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()]}
    )
    key = ctx.unique_name("obj-")
    body = f"sesspol-{ctx.unique_name('')}".encode()
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    ns, sa = ctx.unique_name("sim2real-sesspol-")[:63].lower(), "sim2real-sa"
    _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST", "/api/v1/namespaces",
        body={
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": ns, "labels": dict(_FIXTURE_TAGS)},
        },
    )
    ctx.on_cleanup(
        lambda: _if_cluster_exists(
            ctx, cluster, lambda: _k8s(ctx, cluster, endpoint, ca_b64, "DELETE", f"/api/v1/namespaces/{ns}")
        )
    )
    _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST", f"/api/v1/namespaces/{ns}/serviceaccounts",
        body={"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": sa}},
    )
    pod_name = "sim2real-sesspol-pod"
    pod_uid = _create_pod(ctx, cluster, endpoint, ca_b64, ns, sa, pod_name)
    ctx.on_cleanup(
        lambda: _if_cluster_exists(
            ctx,
            cluster,
            lambda: _k8s(ctx, cluster, endpoint, ca_b64, "DELETE", f"/api/v1/namespaces/{ns}/pods/{pod_name}"),
        )
    )

    # The ROLE holds exactly ListBucket + GetObject and NOT DeleteObject. That boundary is what
    # leg 3 intersects against, so it is asserted before any session policy exists.
    pod_role_name, pod_role_arn = _create_role(
        ctx,
        "sim2real-sesspol-pod-",
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
    iam.put_role_policy(
        RoleName=pod_role_name,
        PolicyName="role-boundary",
        PolicyDocument=_session_policy(bucket, ["s3:ListBucket", "s3:GetObject"]),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=pod_role_name, PolicyName="role-boundary")
    )

    assoc = eks.create_pod_identity_association(
        clusterName=cluster, namespace=ns, serviceAccount=sa, roleArn=pod_role_arn,
        tags=dict(_FIXTURE_TAGS),
    )["association"]
    assoc_id = assoc["associationId"]
    ctx.on_cleanup(
        lambda: _if_cluster_exists(
            ctx, cluster, lambda: eks.delete_pod_identity_association(clusterName=cluster, associationId=assoc_id)
        )
    )
    assert assoc.get("policy") is None, (
        f"a freshly created association must carry no session policy; got {assoc.get('policy')!r}"
    )

    def session():
        token = _sa_token(ctx, cluster, endpoint, ca_b64, ns, sa, pod_name, pod_uid)
        return _assume(ctx, cluster, token)

    def creds():
        return session()["credentials"]

    def can_list(c):
        return [o["Key"] for o in _s3_as(ctx, c).list_objects_v2(Bucket=bucket).get("Contents", [])]

    def get_bytes(c):
        return _s3_as(ctx, c).get_object(Bucket=bucket, Key=key)["Body"].read()

    # === leg 1: no session policy — the role's own boundary, and the latency that bounds the rest
    started = time.monotonic()
    _wait_for(
        lambda: _readable(ctx, creds(), bucket, key, body),
        lambda ok: ok,
        timeout_s=_POLICY_BARRIER_S,
        interval_s=10,
        desc=(
            "the role's inline policy to authorize GetObject for the vended pod-identity "
            "credentials (grant propagation, not the behaviour under test)"
        ),
    )
    grant_latency = max(time.monotonic() - started, 1.0)
    baseline_session = session()
    baseline = baseline_session["credentials"]
    assert can_list(baseline) == [key], (
        f"with no session policy the role's ListBucket must return exactly [{key!r}]; got "
        f"{can_list(baseline)!r}"
    )
    code, message = _client_error(
        lambda: _s3_as(ctx, baseline).delete_object(Bucket=bucket, Key=key),
        "DeleteObject with no session policy, against a role that does not hold s3:DeleteObject",
    )
    assert code == "AccessDenied", (
        f"the role does not hold s3:DeleteObject, so DeleteObject must be AccessDenied before any "
        f"session policy exists; got {code!r} — leg 3's refusal would otherwise be unattributable"
    )
    expected = _s3_denied_message(
        baseline_session["assumedRoleUser"]["arn"], "s3:DeleteObject", bucket, key, "identity-based"
    )
    assert message == expected, f"leg 1 DeleteObject: EXPECTED_MESSAGE={expected!r} GOT={message!r}"

    # === leg 2: break exactly one thing — a session policy that omits GetObject ===
    eks.update_pod_identity_association(
        clusterName=cluster,
        associationId=assoc_id,
        policy=_session_policy(bucket, ["s3:ListBucket"]),
        disableSessionTags=True,  # required by the API when `policy` is set
    )
    narrowed = eks.describe_pod_identity_association(
        clusterName=cluster, associationId=assoc_id
    )["association"]
    assert json.loads(narrowed["policy"])["Statement"][0]["Action"] == ["s3:ListBucket"], (
        "DescribePodIdentityAssociation must report the session policy just set; its Action list is "
        f"{json.loads(narrowed['policy'])['Statement'][0]['Action']!r}"
    )
    assert narrowed["roleArn"] == pod_role_arn, (
        f"the update must have changed only the session policy, but roleArn moved to "
        f"{narrowed['roleArn']!r} (expected {pod_role_arn!r})"
    )
    code, message, narrowed_arn = _wait_for(
        lambda: _refusal_with_list_control(ctx, session(), bucket, key),
        lambda r: r[0] == "AccessDenied",
        timeout_s=max(3 * grant_latency, _ASSOCIATION_BARRIER_S),
        interval_s=10,
        desc=(
            "the ListBucket-only session policy to intersect GetObject away, while ListBucket keeps "
            f"working in the same instant (held for at least 3x the {grant_latency:.0f}s the grant "
            "itself took, so a correct-but-slower target is not scored as having blocked)"
        ),
    )
    assert code == "AccessDenied", (
        "a session policy naming only s3:ListBucket must intersect s3:GetObject away, so GetObject "
        f"must be AccessDenied; got {code!r}"
    )
    expected = _s3_denied_message(narrowed_arn, "s3:GetObject", bucket, key, "session")
    assert message == expected, f"leg 2 GetObject: EXPECTED_MESSAGE={expected!r} GOT={message!r}"

    # === leg 3: restore AND prove the intersection cannot ADD ===
    eks.update_pod_identity_association(
        clusterName=cluster,
        associationId=assoc_id,
        policy=_session_policy(bucket, ["s3:ListBucket", "s3:GetObject", "s3:DeleteObject"]),
        disableSessionTags=True,
    )
    widened = eks.describe_pod_identity_association(
        clusterName=cluster, associationId=assoc_id
    )["association"]
    assert "s3:DeleteObject" in json.loads(widened["policy"])["Statement"][0]["Action"], (
        "the widened session policy must be the one Describe now reports; got "
        f"{json.loads(widened['policy'])['Statement'][0]['Action']!r}"
    )
    _wait_for(
        lambda: _readable(ctx, creds(), bucket, key, body),
        lambda ok: ok,
        timeout_s=_ASSOCIATION_BARRIER_S,
        interval_s=10,
        desc=(
            "widening the session policy to restore GetObject, returning byte-identical content "
            "(B2's restore beat: the identical call must succeed again)"
        ),
    )
    widened_session = session()
    widened_creds = widened_session["credentials"]
    assert can_list(widened_creds) == [key], (
        f"ListBucket must still return exactly [{key!r}] under the widened policy; got "
        f"{can_list(widened_creds)!r}"
    )
    code, message = _client_error(
        lambda: _s3_as(ctx, widened_creds).delete_object(Bucket=bucket, Key=key),
        "DeleteObject under a session policy that names s3:DeleteObject but a role that does not",
    )
    assert code == "AccessDenied", (
        "a session policy is an INTERSECTION with the role's permissions, so naming s3:DeleteObject "
        "in it cannot grant an action the role lacks; DeleteObject must still be AccessDenied but "
        f"the code was {code!r}"
    )
    expected = _s3_denied_message(
        widened_session["assumedRoleUser"]["arn"], "s3:DeleteObject", bucket, key, "identity-based"
    )
    assert message == expected, f"leg 3 DeleteObject: EXPECTED_MESSAGE={expected!r} GOT={message!r}"
    # ... and the object really is still there, read through a different operation than the delete.
    assert get_bytes(widened_creds) == body, (
        f"the refused DeleteObject must have left {key!r} intact with its original bytes"
    )

    _delete_cluster(ctx, cluster)
    assert _cluster_status(ctx.client("eks"), cluster) == "GONE", (
        f"cluster {cluster} was still describable after an asserted inline delete"
    )


def _readable(ctx, creds, bucket, key, expected):
    """True only when GetObject returns EXACTLY the expected bytes."""
    try:
        got = _s3_as(ctx, creds).get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "InvalidAccessKeyId"):
            return False
        raise
    assert got == expected, (
        f"{key!r} was authorized but served {got!r}, expected {expected!r} — the grant is real but "
        "the payload is not"
    )
    return True


def _refusal_with_list_control(ctx, assumed, bucket, key):
    """The GetObject refusal (code, message, session arn) for *assumed*, asserting ListBucket still
    works with the same credentials so a fully broken session cannot pass as an intersection.
    Returns code and message None while GetObject still succeeds (policy not yet propagated).
    """
    creds = assumed["credentials"]
    listed = [
        o["Key"] for o in _s3_as(ctx, creds).list_objects_v2(Bucket=bucket).get("Contents", [])
    ]
    assert listed == [key], (
        f"ListBucket is inside the session policy and must still return exactly [{key!r}]; it "
        f"returned {listed!r}, so the GetObject refusal is not attributable to the intersection"
    )
    try:
        _s3_as(ctx, creds).get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        code = message = None
    return code, message, assumed["assumedRoleUser"]["arn"]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
