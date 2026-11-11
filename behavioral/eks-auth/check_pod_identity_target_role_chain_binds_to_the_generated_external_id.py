"""pod-identity-target-role-chain-binds-to-the-generated-external-id."""
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


CHECK = "pod-identity-target-role-chain-binds-to-the-generated-external-id"
GROUP = "overly-permissive"
SERVICES = ["eks-auth"]

_CLUSTER_TIMEOUT_S = 900
_DELETE_TIMEOUT_S = 600
_POLICY_BARRIER_S = 300  # an IAM trust-policy rewrite converges well under this
_ASSOCIATION_BARRIER_S = 180
_TRUST_SETTLE_S = 600

_AUDIENCE = "pods.eks.amazonaws.com"
_FIXTURE_TAGS = {"sim2real": "eks-auth-chain"}
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


def _error_detail(fn, desc):
    """The (code, message) raised by *fn*. RAISES if *fn* unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
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
    """create_role, retried on MalformedPolicyDocument: a trust policy naming a just-created role
    as Principal is rejected until IAM propagates it as a resolvable principal."""
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)[:64]

    def _try_create():
        try:
            return iam.create_role(
                RoleName=name,
                AssumeRolePolicyDocument=json.dumps(trust),
                Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
            )["Role"]["Arn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "MalformedPolicyDocument":
                return None
            raise

    arn = _wait_for(
        _try_create,
        lambda a: a is not None,
        timeout_s=60,
        interval_s=5,
        desc=f"CreateRole {name} to accept a just-created principal in its trust policy",
    )
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
        "sim2real-chain-clus-",
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
    name = ctx.unique_name("sim2real-chain-")[:100]
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

    Signed via the request signer, not a botocore event on the shared client, which would repeat
    the x-k8s-aws-id header and break the API server's signature match.
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


def _create_unscheduled_pod(ctx, cluster, endpoint, ca_b64, ns, sa):
    """A Pod object bound to *sa*, never scheduled (no node group exists to run it on).

    AssumeRoleForPodIdentity needs a token with a `kubernetes.io/pod` claim, which TokenRequest only
    sets when `boundObjectRef` names a real Pod; the Pod need not ever be scheduled.
    """
    name = "sim2real-chain-pod"
    resp = _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST", f"/api/v1/namespaces/{ns}/pods",
        body={
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": name},
            "spec": {
                "serviceAccountName": sa,
                "containers": [
                    {"name": "main", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023"}
                ],
            },
        },
    )
    return name, resp["metadata"]["uid"]


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


def _assume_for_pod(ctx, cluster, token, *, tolerate_consistency=True):
    """AssumeRoleForPodIdentity, optionally retried over the documented consistency window."""
    eks_auth = ctx.client("eks-auth")

    def _call():
        return eks_auth.assume_role_for_pod_identity(
            clusterName=cluster, token=token, eksNodeName="sim2real-chain-node"
        )

    if not tolerate_consistency:
        return _call()

    def _attempt():
        try:
            return _call()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            # InvalidRequestException is the documented consistency window; AccessDeniedException
            # is also returned transiently before a fresh role's trust policy has propagated. A
            # permanently wrong trust still surfaces because the caller re-asserts afterward.
            if code in ("InvalidRequestException", "AccessDeniedException"):
                return None
            raise

    return _wait_for(
        _attempt,
        lambda r: r is not None,
        timeout_s=_ASSOCIATION_BARRIER_S,
        interval_s=5,
        desc=(
            f"AssumeRoleForPodIdentity on {cluster} to stop reporting "
            "InvalidRequestException/AccessDeniedException"
        ),
    )


def _client_as(ctx, service, creds):
    """A client signing with the VENDED credentials (ctx's sanctioned re-signing override)."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["accessKeyId"],
            "aws_secret_access_key": creds["secretAccessKey"],
            "aws_session_token": creds["sessionToken"],
        },
    )


def _assumed_role_prefix(role_arn):
    """The assumed-role identity prefix STS vends for *role_arn* (`arn:aws:sts::`, not `iam`)."""
    return role_arn.replace(":iam::", ":sts::").replace(":role/", ":assumed-role/")


def _target_trust(initial_role_arn, external_id):
    """role2's trust: role1's ARN as Principal (the second hop runs as role1's session), gated by
    the externalId condition. sts:TagSession is a separate unconditioned statement: the chained
    session re-asserts Pod Identity's session tags, and bundling it under the condition is denied.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": initial_role_arn},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": initial_role_arn},
                "Action": "sts:TagSession",
            },
        ],
    }


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
    """Pod Identity targetRoleArn chains to the target role, bound by the EKS-generated externalId:
    unchained creds are the initial role's and cannot read, chained ones are the target's and read,
    a wrong external id in the target trust is refused, and restoring it reads again.

    Reference: https://docs.aws.amazon.com/eks/latest/APIReference/API_CreatePodIdentityAssociation.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    eks = ctx.client("eks")

    cluster, endpoint, ca_b64 = _create_cluster(ctx)

    bucket = f"{ctx.unique_name('sim2real-chain-')}-{account}"[:63]
    create_args = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the ONE region where S3 rejects an explicit LocationConstraint.
        create_args["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_args)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()]},
    )
    key = ctx.unique_name("obj-")
    body = f"chain-{ctx.unique_name('')}".encode()
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    ns, sa = ctx.unique_name("sim2real-chain-")[:63].lower(), "sim2real-sa"
    _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST", "/api/v1/namespaces",
        body={
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": ns, "labels": dict(_FIXTURE_TAGS)},
        },
    )
    ctx.on_cleanup(
        lambda: _unless_cluster_gone(ctx, cluster, lambda: _k8s(ctx, cluster, endpoint, ca_b64, "DELETE", f"/api/v1/namespaces/{ns}"))
    )
    _k8s_expect(
        ctx, cluster, endpoint, ca_b64, "POST", f"/api/v1/namespaces/{ns}/serviceaccounts",
        body={"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": sa}},
    )
    pod_name, pod_uid = _create_unscheduled_pod(ctx, cluster, endpoint, ca_b64, ns, sa)

    # role1: assumable by pod identity, allowed to assume role2, and holding NO s3 permission — so a
    # successful GetObject anywhere below can only be role2's.
    initial_name, initial_arn = _create_role(
        ctx,
        "sim2real-chain-init-",
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
    # role2: holds the only s3 permission in this check. Its trust starts DELIBERATELY unsatisfiable
    # (no external id is known yet) and is rewritten once EKS has generated one. role1 ALSO needs an
    # identity-based permission to assume role2 -- the second hop is performed using role1's own
    # assumed session, so both role2's resource-based trust (below) and this identity policy must
    # agree. See _target_trust's docstring.
    target_name, target_arn = _create_role(
        ctx,
        "sim2real-chain-tgt-",
        _target_trust(initial_arn, "sim2real-placeholder-not-yet-generated"),
    )
    iam.put_role_policy(
        RoleName=initial_name,
        PolicyName="assume-target",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sts:AssumeRole", "sts:TagSession"],
                        "Resource": target_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=initial_name, PolicyName="assume-target"))
    iam.put_role_policy(
        RoleName=target_name,
        PolicyName="read-object",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=target_name, PolicyName="read-object"))

    assoc = eks.create_pod_identity_association(
        clusterName=cluster, namespace=ns, serviceAccount=sa, roleArn=initial_arn,
        tags=dict(_FIXTURE_TAGS),
    )["association"]
    assoc_id = assoc["associationId"]
    ctx.on_cleanup(
        lambda: _unless_cluster_gone(ctx, cluster, lambda: eks.delete_pod_identity_association(clusterName=cluster, associationId=assoc_id))
    )

    def token():
        return _sa_token(ctx, cluster, endpoint, ca_b64, ns, sa, pod_name, pod_uid)

    # === leg 1: no target role — the credentials are the INITIAL role's and cannot read ===
    unchained = _assume_for_pod(ctx, cluster, token())
    expected_initial = _assumed_role_prefix(initial_arn)
    assert unchained["assumedRoleUser"]["arn"].startswith(expected_initial), (
        f"with no targetRoleArn the vended identity must be the initial role's; "
        f"assumedRoleUser.arn is {unchained['assumedRoleUser']['arn']!r}, expected a session under "
        f"{expected_initial!r}"
    )
    who = _client_as(ctx, "sts", unchained["credentials"]).get_caller_identity()
    assert who["Arn"] == unchained["assumedRoleUser"]["arn"], (
        f"STS must agree with the response about who these credentials are: GetCallerIdentity says "
        f"{who['Arn']!r}, AssumeRoleForPodIdentity said {unchained['assumedRoleUser']['arn']!r}"
    )
    code, message = _error_detail(
        lambda: _client_as(ctx, "s3", unchained["credentials"]).get_object(
            Bucket=bucket, Key=key
        ),
        "GetObject with the UNCHAINED initial role's credentials",
    )
    expected_message = (
        f"User: {unchained['assumedRoleUser']['arn']} is not authorized to perform: s3:GetObject "
        f'on resource: "arn:aws:s3:::{bucket}/{key}" because no identity-based policy allows the '
        "s3:GetObject action"
    )
    assert (code, message) == ("AccessDenied", expected_message), (
        "the initial role holds no s3 permission, so an unchained GetObject must be AccessDenied with "
        f"the implicit-deny message naming it — otherwise leg 2's success proves nothing; got "
        f"{(code, message)!r}, expected {('AccessDenied', expected_message)!r}"
    )

    # === leg 2: add the target role, write EKS's generated externalId into its trust, and read ===
    eks.update_pod_identity_association(
        clusterName=cluster, associationId=assoc_id, targetRoleArn=target_arn
    )
    chained_record = eks.describe_pod_identity_association(
        clusterName=cluster, associationId=assoc_id
    )["association"]
    assert chained_record["targetRoleArn"] == target_arn, (
        f"DescribePodIdentityAssociation must report targetRoleArn={target_arn!r}; it reports "
        f"{chained_record.get('targetRoleArn')!r}"
    )
    external_id = chained_record["externalId"]
    assert isinstance(external_id, str) and external_id, (
        "EKS must GENERATE an externalId for a target-role association — the field is in neither "
        f"the create nor the update request, so it can only come from the service; got "
        f"{external_id!r} in {chained_record!r}"
    )
    iam.update_assume_role_policy(
        RoleName=target_name,
        PolicyDocument=json.dumps(_target_trust(initial_arn, external_id)),
    )
    started = time.monotonic()
    _wait_for(
        lambda: _readable_via_chain(ctx, cluster, token(), bucket, key, body),
        lambda ok: ok,
        timeout_s=_POLICY_BARRIER_S,
        interval_s=10,
        desc=(
            "the chain to work once the target role's trust names EKS's generated externalId "
            "(IAM trust-policy propagation, not the behaviour under test)"
        ),
    )
    chain_latency = max(time.monotonic() - started, 1.0)
    chained = _assume_for_pod(ctx, cluster, token())
    expected_target = _assumed_role_prefix(target_arn)
    assert chained["assumedRoleUser"]["arn"].startswith(expected_target), (
        f"with targetRoleArn set, the credentials injected must be the TARGET role's; "
        f"assumedRoleUser.arn is {chained['assumedRoleUser']['arn']!r}, expected a session under "
        f"{expected_target!r}"
    )
    who = _client_as(ctx, "sts", chained["credentials"]).get_caller_identity()
    assert who["Arn"] == chained["assumedRoleUser"]["arn"], (
        f"STS must agree the chained credentials are the target role's: GetCallerIdentity says "
        f"{who['Arn']!r}, the response said {chained['assumedRoleUser']['arn']!r}"
    )
    assert (
        _client_as(ctx, "s3", chained["credentials"])
        .get_object(Bucket=bucket, Key=key)["Body"]
        .read()
        == body
    ), f"the chained credentials must read {key!r} back as {body!r}"

    # === legs 3+4: break exactly one thing — the external id in the target's trust condition ===
    wrong_id = external_id[::-1] + "-x"
    assert wrong_id != external_id, "the substituted external id must actually differ"
    iam.update_assume_role_policy(
        RoleName=target_name, PolicyDocument=json.dumps(_target_trust(initial_arn, wrong_id))
    )
    # Polled to settle: STS keeps serving a cached ALLOW for minutes after a trust policy tightens.
    _wait_for(
        lambda: _chain_refused(ctx, cluster, token()),
        lambda refused: refused,
        timeout_s=_TRUST_SETTLE_S,
        interval_s=15,
        desc=(
            "the chain to be refused once the target role's trust condition names a DIFFERENT "
            "external id; polled to SETTLE over a window long enough to outlast STS's cached ALLOW "
            "after a trust policy tightens (~300s measured, see _TIMEOUT['sts'])"
        ),
    )
    # Effect absent, via an independent read: the association still exists and still names the
    # target role, so the refusal is the CHAIN failing rather than the association vanishing.
    still_there = eks.describe_pod_identity_association(
        clusterName=cluster, associationId=assoc_id
    )["association"]
    assert still_there["targetRoleArn"] == target_arn, (
        f"the association must be untouched — only the target role's trust changed — but "
        f"targetRoleArn is now {still_there.get('targetRoleArn')!r}"
    )
    assert still_there["externalId"] == external_id, (
        f"EKS's generated externalId must not have changed: it was {external_id!r} and Describe now "
        f"reports {still_there['externalId']!r}"
    )

    # === legs 5+6: restore the generated value and demand the IDENTICAL call succeed ===
    iam.update_assume_role_policy(
        RoleName=target_name, PolicyDocument=json.dumps(_target_trust(initial_arn, external_id))
    )
    _wait_for(
        lambda: _readable_via_chain(ctx, cluster, token(), bucket, key, body),
        lambda ok: ok,
        timeout_s=max(3 * chain_latency, _POLICY_BARRIER_S),
        interval_s=10,
        desc=(
            "restoring EKS's generated externalId in the target role's trust to make the identical "
            "chained GetObject succeed again with byte-identical content"
        ),
    )

    _delete_cluster(ctx, cluster)
    assert _cluster_status(ctx.client("eks"), cluster) == "GONE", (
        f"cluster {cluster} was still describable after an asserted inline delete"
    )


def _readable_via_chain(ctx, cluster, token, bucket, key, expected):
    """True only when the CHAINED credentials read the object back as EXACTLY *expected*."""
    try:
        vended = _assume_for_pod(ctx, cluster, token, tolerate_consistency=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in (
            "AccessDeniedException",
            "InvalidRequestException",
        ):
            return False
        raise
    try:
        got = _client_as(ctx, "s3", vended["credentials"]).get_object(Bucket=bucket, Key=key)[
            "Body"
        ].read()
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "InvalidAccessKeyId"):
            return False
        raise
    assert got == expected, (
        f"{key!r} was authorized through the chain but served {got!r}, expected {expected!r} — the "
        "chain is real but the payload is not"
    )
    return True


def _chain_refused(ctx, cluster, token):
    """True once the tightened chain is refused (asserting AccessDeniedException); False on STS's
    cached ALLOW, which keeps _wait_for polling."""
    try:
        _assume_for_pod(ctx, cluster, token, tolerate_consistency=False)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "AccessDeniedException", (
            "with the target role's trust naming a different sts:ExternalId, the chain cannot be "
            f"completed and AssumeRoleForPodIdentity must be refused; got {code!r} (DRAFT H3: this "
            "code is the least confident assertion in the file)"
        )
        return True
    return False


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
