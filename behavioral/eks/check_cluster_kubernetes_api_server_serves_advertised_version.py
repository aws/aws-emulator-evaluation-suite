"""cluster-kubernetes-api-server-serves-advertised-version."""
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


CHECK = "cluster-kubernetes-api-server-serves-advertised-version"
GROUP = 'data-plane'
SERVICES = ['eks']

_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
# Zone IDs that do not offer EKS control planes; CreateCluster rejects a subnet set that includes one.
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_TAGS = {"simparity": "candidates-09-eks", "simparity-check": CHECK}


# The cluster
# teardown helper polls DeleteCluster to completion, so a failure mid-check cannot leak
# a billable control plane.


def _is_gone(fn):
    """Teardown probe: True once fn raises ResourceNotFoundException, False while it succeeds."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False


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


def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get(
            "AttachedPolicies", []
        ):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _ensure_role(ctx, name, service, managed_policies=()):
    """Create a throwaway IAM role, register teardown, return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="candidates_09 eks fidelity check",
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"identity cannot create IAM role {name}: {exc}") from exc
        raise
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return arn


def _create_cluster_with_role_propagation(c, *, timeout_s=180, interval_s=10, **kwargs):
    """CreateCluster, retrying while IAM's new role has not yet propagated to EKS.

    IAM is eventually consistent and EKS validates roleArn synchronously, so a role created moments
    ago can make CreateCluster fail with InvalidParameterException even though the role is correct.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            c.create_cluster(**kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs of the default VPC."""
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            f"need subnets in >=2 EKS-supported AZs, found {len(by_az)}"
        )
    return [by_az[az] for az in sorted(by_az)][:2]


def _teardown_cluster(c, name):
    """Delete a cluster in dependency order and poll it to actually gone.

    DeleteCluster is REFUSED while any nodegroup or Fargate profile still
    exists, so firing them in the wrong order (or not polling) leaks a control
    plane that bills per hour forever. This check creates no children, but the
    helper drains them anyway so a partial failure cannot leak.
    Deadlines: 1800s for a nodegroup (it must terminate real EC2 instances),
    900s for a Fargate profile, 1800s for the control plane itself.
    """
    try:
        for ng in c.list_nodegroups(clusterName=name).get("nodegroups", []):
            c.delete_nodegroup(clusterName=name, nodegroupName=ng)
            _wait_for(
                lambda ng=ng: _is_gone(
                    lambda: c.describe_nodegroup(clusterName=name, nodegroupName=ng)
                ),
                lambda gone: gone,
                timeout_s=1800,
                interval_s=20,
                desc=f"nodegroup {ng} deleted",
            )
        for fp in c.list_fargate_profiles(clusterName=name).get(
            "fargateProfileNames", []
        ):
            c.delete_fargate_profile(clusterName=name, fargateProfileName=fp)
            _wait_for(
                lambda fp=fp: _is_gone(
                    lambda: c.describe_fargate_profile(
                        clusterName=name, fargateProfileName=fp
                    )
                ),
                lambda gone: gone,
                timeout_s=900,
                interval_s=15,
                desc=f"fargate profile {fp} deleted",
            )
        for addon in c.list_addons(clusterName=name).get("addons", []):
            c.delete_addon(clusterName=name, addonName=addon)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        c.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "ResourceInUseException",
        ):
            raise
    _wait_for(
        lambda: _is_gone(lambda: c.describe_cluster(name=name)),
        lambda gone: gone,
        timeout_s=1800,
        interval_s=20,
        desc=f"cluster {name} fully deleted",
    )


def _https_get(ctx, url, ca_pem, *, token=None, timeout_s=30):
    """GET *url* over HTTPS trusting ONLY *ca_pem*. Returns (status, raw body).

    The CA is pinned with load_verify_locations(cadata=...) so a server that does
    not present the certificate chain DescribeCluster advertised fails the TLS
    handshake (SSLCertVerificationError propagates and fails the check) rather
    than being silently accepted.

    *token*, when given, is sent as an Authorization: Bearer header.
    """
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.load_verify_locations(cadata=ca_pem)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = _routed_request(ctx, url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ssl_ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _k8s_bearer_token(ctx, cluster_name, *, ttl_s=900):
    """Mint the EKS Kubernetes bearer token for the CURRENT caller.

    The EKS API server authenticates with the aws-iam-authenticator scheme: the token is
    "k8s-aws-v1." + unpadded base64url of a PRESIGNED sts:GetCallerIdentity URL that has the
    cluster name bound into it as a SIGNED `x-k8s-aws-id` header. The API server replays that URL
    against STS to learn which AWS principal is calling; the signed header is what stops a token
    minted for one cluster being replayed against another.

    Built here from botocore's own presigner rather than shelling out to `aws eks get-token`, so
    the check still needs no external binary. The `before-sign` hook adds the header BEFORE SigV4
    runs, which is what gets it into X-Amz-SignedHeaders.
    """
    sts = ctx.client("sts", endpoint_url=ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com"))
    event = "before-sign.sts.GetCallerIdentity"

    def _bind_cluster(request, **kwargs):
        request.headers.add_header("x-k8s-aws-id", cluster_name)

    # ctx.client is cached, so the hook is scoped to this one presign and removed after it.
    sts.meta.events.register(event, _bind_cluster)
    try:
        url = sts.generate_presigned_url(
            "get_caller_identity", Params={}, ExpiresIn=ttl_s, HttpMethod="GET"
        )
    finally:
        sts.meta.events.unregister(event, _bind_cluster)
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip(
        "="
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ACTIVE cluster's API server presents the advertised CA, refuses anonymous /version and namespace
    reads with a k8s Status failure, serves /version equal to DescribeCluster.version and a namespace list
    with kube-system to the creator's token, and refuses a token minted for another cluster name.
    """
    c = ctx.client("eks")
    role_arn = _ensure_role(
        ctx,
        ctx.unique_name("sim2real-behav-eks-cp-"),
        "eks.amazonaws.com",
        [_EKS_CLUSTER_POLICY],
    )
    subnets = _subnet_ids(ctx)
    name = ctx.unique_name("sim2real-behav-eks-k8s-")

    ctx.on_cleanup(lambda: _teardown_cluster(c, name))
    _create_cluster_with_role_propagation(
        c,
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={
            "subnetIds": subnets,
            "endpointPublicAccess": True,
            "endpointPrivateAccess": False,
        },
        accessConfig={
            "authenticationMode": "API",
            "bootstrapClusterCreatorAdminPermissions": True,
        },
        tags=dict(_TAGS),
    )

    resp = _wait_for(
        lambda: c.describe_cluster(name=name),
        lambda r: r["cluster"]["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1500,
        interval_s=20,
        desc=f"cluster {name} status in (ACTIVE, FAILED)",
    )
    cluster = resp["cluster"]
    assert cluster["status"] == "ACTIVE", (
        f"cluster {name} landed in {cluster['status']!r}; "
        f"health={cluster.get('health')!r}"
    )

    endpoint = cluster.get("endpoint") or ""
    assert not (p := ctx.published_url_mismatch(endpoint)), p
    ca_b64 = (cluster.get("certificateAuthority") or {}).get("data") or ""
    assert ca_b64, "ACTIVE cluster is missing certificateAuthority.data"
    ca_pem = base64.b64decode(ca_b64).decode("ascii")
    assert ca_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        "certificateAuthority.data did not base64-decode to a PEM certificate: "
        f"{ca_pem[:60]!r}"
    )
    assert "-----END CERTIFICATE-----" in ca_pem, (
        f"certificateAuthority.data PEM is truncated: {ca_pem[-60:]!r}"
    )

    base = endpoint.rstrip("/")

    def _assert_refused(path, status, body):
        assert status in (401, 403), (
            f"anonymous GET {path} returned {status}, expected an authentication refusal "
            f"(401; 403 is the only acceptable alternative): {body[:300]!r}"
        )
        refusal = json.loads(body)
        assert refusal.get("kind") == "Status", (
            f"refusal body for {path} is not a k8s Status object: {refusal!r}"
        )
        assert refusal.get("status") == "Failure", (
            f"unexpected refusal body for {path}: {refusal!r}"
        )
        assert "items" not in refusal, (
            f"anonymous GET {path} leaked data despite {status}: {refusal!r}"
        )
        return refusal

    # (1) Authentication is enforced on the DISCOVERY surface too, not just on collections: real
    #     EKS answers an anonymous GET /version with 401, so there is no unauthenticated way to
    #     read the served version.
    status, body = _https_get(ctx, base + "/version", ca_pem)
    _assert_refused("/version", status, body)

    # (2) ... and on a protected collection.
    status, body = _https_get(ctx, base + "/api/v1/namespaces?limit=1", ca_pem)
    _assert_refused("/api/v1/namespaces", status, body)

    # (3) AUTHENTICATED as the cluster creator, the API server is reachable and agrees with the
    #     version DescribeCluster advertises.
    token = _k8s_bearer_token(ctx, name)
    status, body = _https_get(ctx, base + "/version", ca_pem, token=token)
    assert status == 200, (
        f"authenticated GET /version on {endpoint} returned {status}: {body[:300]!r}. The cluster "
        f"was created with authenticationMode=API and "
        f"bootstrapClusterCreatorAdminPermissions=true, so this check's own caller is "
        f"cluster-admin and must be accepted"
    )
    version = json.loads(body)
    for field in ("major", "minor", "gitVersion"):
        assert version.get(field), f"/version is missing {field}: {version!r}"
    served = f"{version['major']}.{version['minor'].rstrip('+')}"
    assert served == cluster["version"], (
        f"API server serves k8s {served!r} but DescribeCluster advertises "
        f"{cluster['version']!r} (gitVersion={version['gitVersion']!r})"
    )

    # (4) The same token reads a protected collection, which is what proves the 401s above were
    #     authentication being ENFORCED rather than the API server refusing everything.
    status, body = _https_get(ctx, base + "/api/v1/namespaces", ca_pem, token=token)
    assert status == 200, (
        f"authenticated GET /api/v1/namespaces returned {status}: {body[:300]!r}"
    )
    listing = json.loads(body)
    assert listing.get("kind") == "NamespaceList", (
        f"expected a k8s NamespaceList, got kind={listing.get('kind')!r}"
    )
    namespaces = {
        item.get("metadata", {}).get("name") for item in listing.get("items", [])
    }
    assert "kube-system" in namespaces, (
        f"a real Kubernetes API server always has the kube-system namespace; got "
        f"{sorted(n for n in namespaces if n)!r}"
    )

    # (5) The cluster-name binding in the token is real: a token minted for a DIFFERENT cluster
    #     name is signed by the same principal but must not authenticate here, which is what stops
    #     a token being replayed across clusters.
    wrong = _k8s_bearer_token(ctx, name + "-not-this-cluster")
    status, body = _https_get(ctx, base + "/version", ca_pem, token=wrong)
    assert status in (401, 403), (
        f"a bearer token whose signed x-k8s-aws-id names a different cluster was ACCEPTED "
        f"({status}); the cluster name must be bound into the token: {body[:300]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
