"""eks-oidc-discovery-and-jwks-verify-a-projected-token-offline."""
from __future__ import annotations

import base64
import calendar
import hashlib
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


CHECK = "eks-oidc-discovery-and-jwks-verify-a-projected-token-offline"
GROUP = 'data-plane'
SERVICES = ['eks']

_CLUSTER_ROLE_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
# EKS refuses to place a control plane in these zone IDs.
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "b3-eks-workloads"}

# CreateCluster -> ACTIVE takes roughly 7-8 minutes and DeleteCluster -> gone a few minutes;
# these bounds are ~2x margins.
_CLUSTER_TIMEOUT_S = 800
_CLUSTER_DELETE_TIMEOUT_S = 500
_DELETE_RETRY_TIMEOUT_S = 300
_TOKEN_TTL_S = 3600

# The RFC 8017 EMSA-PKCS1-v1_5 DigestInfo DER prefix for SHA-256. The recovered signature block
# must be 0x00 0x01 <0xFF padding> 0x00 || this || sha256(signing input).
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")
_AUDIENCE = "sts.amazonaws.com"
_ALT_AUDIENCE = "sts.wrong-audience.example.com"


# ===== helpers =====


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
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service},
                       "Action": ["sts:AssumeRole"]}],
    })


def _create_role(ctx, name, service, managed_policies=()):
    """Create this check's own uniquely named IAM role and return its ARN."""
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust(service),
        Description="sim2real b3-eks-workloads oidc/jwks check",
        Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
    )["Role"]["Arn"]
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    # IAM exposes no condition to poll for "assumable by EKS"; _create_cluster retries the
    # synchronous InvalidParameterException instead.
    return arn


def _delete_role(iam, name):
    try:
        for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _fixture_subnets(ctx):
    """Default-VPC subnets in EKS-supported AZs that also offer the node instance type."""
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
    by_az = {}
    for sn in sorted(
        ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"],
        key=lambda s: s["AvailabilityZone"],
    ):
        if sn["AvailabilityZone"] in usable:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= 2, (
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


def _create_cluster(ctx, name, role_arn):
    """Create the dedicated control plane and return its ACTIVE description."""
    c = ctx.client("eks")
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            c.create_cluster(
                name=name,
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
            )
            break
        except ClientError as exc:
            # The one legitimate retry: IAM has not yet propagated the freshly created cluster
            # role, which EKS validates synchronously. Bounded, and exhaustion FAILS.
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            assert time.monotonic() < deadline, (
                f"CreateCluster kept rejecting the cluster role {role_arn!r} for "
                f"{_DELETE_RETRY_TIMEOUT_S}s: {exc}"
            )
            time.sleep(2)
    cluster = _wait_for(
        lambda: c.describe_cluster(name=name)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", (
        f"cluster {name!r} landed in {cluster['status']!r}; health={cluster.get('health')!r}"
    )
    return cluster


def _teardown_cluster(c, name):
    """Delete the control plane and poll until the API says it is actually gone.

    Run inline at the end of the check body because the delete outlasts the cleanup budget.
    """
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            c.delete_cluster(name=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
            assert time.monotonic() < deadline, (
                f"DeleteCluster on {name!r} was still refused with ResourceInUseException after "
                f"{_DELETE_RETRY_TIMEOUT_S}s: {exc}"
            )
            time.sleep(15)
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s == "GONE",
        timeout_s=_CLUSTER_DELETE_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} fully deleted",
    )


def _delete_namespace(ctx, conn, ns):
    """Delete *ns*; nothing is left to delete once its cluster is deleting or gone."""
    try:
        status = ctx.client("eks").describe_cluster(name=conn[2])["cluster"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETING":
        return
    _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}", timeout_s=90)


def _k8s_token(ctx, cluster_name, *, ttl_s=900):
    """Mint the EKS Kubernetes bearer token for the current caller (k8s-aws-v1 scheme).

    botocore's ``add_header`` APPENDS, so an injector registered twice on one cached client would
    sign ``x-k8s-aws-id: <c>,<c>`` and get 401.
    """
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


def _k8s(ctx, conn, method, path, *, body=None, timeout_s=60, authenticate=True):
    """Request the cluster's Kubernetes API server, trusting ONLY the advertised CA."""
    base, ca_pem, name = conn
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.load_verify_locations(cadata=ca_pem)
    headers = {"Accept": "application/json"}
    if authenticate:
        headers["Authorization"] = f"Bearer {_k8s_token(ctx, name)}"
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


def _public_get(ctx, url, *, timeout_s=30, ssl_ctx=None):
    """Fetch a URL over HTTPS against the PUBLIC trust store (not the cluster CA)."""
    req = _routed_request(ctx, url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ssl_ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _b64url(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _pkcs1_v15_recover(jwk, signature):
    """Recover the PKCS#1 v1.5 signature block: sig^e mod n, as k bytes. Stdlib only."""
    n = int.from_bytes(_b64url(jwk["n"]), "big")
    e = int.from_bytes(_b64url(jwk["e"]), "big")
    k = (n.bit_length() + 7) // 8
    return pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")


def _expected_block(nbytes, digest):
    pad = nbytes - 3 - len(_SHA256_DIGESTINFO) - len(digest)
    return b"\x00\x01" + b"\xff" * pad + b"\x00" + _SHA256_DIGESTINFO + digest


def _token_request(ctx, conn, ns, sa, audience):
    return _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/serviceaccounts/{sa}/token",
        body={
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "spec": {"audiences": [audience], "expirationSeconds": _TOKEN_TTL_S},
        },
    )


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An EKS cluster's public OIDC discovery doc matches its issuer, and the JWKS key verifies a
    TokenRequest token's RS256 signature offline; tampering breaks it, claims name this
    ServiceAccount, and the JWKS is public on public PKI while the API server is 401.

    Reference: https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html"""
    eks = ctx.client("eks")
    iam = ctx.client("iam")
    suffix = ctx.unique_name("")[:8]
    cluster_name = f"sim2real-b3-oidc-{suffix}"
    role_name = f"sim2real-b3-oidc-cr-{suffix}"
    body_failed = []

    role_arn = _create_role(ctx, role_name, "eks.amazonaws.com", [_CLUSTER_ROLE_POLICY])
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    cluster = _create_cluster(ctx, cluster_name, role_arn)
    ctx.on_cleanup(lambda: _teardown_cluster(eks, cluster_name))

    ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    assert ca_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"certificateAuthority.data did not decode to a PEM certificate: {ca_pem[:60]!r}"
    )
    conn = (cluster["endpoint"], ca_pem, cluster_name)
    issuer = cluster["identity"]["oidc"]["issuer"]

    try:
        ns = ctx.unique_name("sim2real-b3-oidc-")[:63].lower()
        sa = "sim2real-oidc-sa"
        _k8s_json(ctx, conn, "POST", "/api/v1/namespaces",
                  body={"apiVersion": "v1", "kind": "Namespace",
                        "metadata": {"name": ns,
                                     "labels": {"sim2real": "b3-eks-workloads"}}})
        ctx.on_cleanup(lambda: _delete_namespace(ctx, conn, ns))
        sa_obj = _k8s_json(ctx, conn, "POST", f"/api/v1/namespaces/{ns}/serviceaccounts",
                           body={"apiVersion": "v1", "kind": "ServiceAccount",
                                 "metadata": {"name": sa}})
        sa_uid = sa_obj["metadata"]["uid"]

        minted = _token_request(ctx, conn, ns, sa, _AUDIENCE)
        token = minted["status"]["token"]
        parts = token.split(".")
        assert len(parts) == 3, f"the TokenRequest token is not a three-part JWS: {token[:80]!r}"
        header_b64, payload_b64, sig_b64 = parts
        header = json.loads(_b64url(header_b64))
        claims = json.loads(_b64url(payload_b64))
        signature = _b64url(sig_b64)

        # (1) The discovery document exists on the PUBLIC internet and agrees with the issuer the
        #     EKS control plane advertises. A discovery doc whose `issuer` disagrees breaks every
        #     conforming OIDC client.
        disc_status, disc_raw = _public_get(ctx, issuer.rstrip("/") + "/.well-known/openid-configuration")
        assert disc_status == 200, (
            f"GET {issuer}/.well-known/openid-configuration returned {disc_status}, so the "
            f"advertised OIDC issuer does not serve a discovery document: {disc_raw[:300]!r}"
        )
        doc = json.loads(disc_raw)
        assert doc["issuer"] == issuer, (
            f"the discovery document declares issuer {doc['issuer']!r} but DescribeCluster "
            f"advertises {issuer!r}"
        )

        # (2) The document is spec-conformant in the fields an IRSA/OIDC client actually reads.
        assert doc["jwks_uri"].startswith(issuer.rstrip("/") + "/"), (
            f"jwks_uri {doc['jwks_uri']!r} is not under the issuer {issuer!r}"
        )
        assert doc["id_token_signing_alg_values_supported"] == ["RS256"], (
            f"the issuer advertises signing algorithms "
            f"{doc['id_token_signing_alg_values_supported']!r}, not ['RS256']"
        )
        assert doc["response_types_supported"] == ["id_token"], (
            f"response_types_supported is {doc['response_types_supported']!r}"
        )
        assert "sub" in doc["claims_supported"], (
            f"claims_supported {doc['claims_supported']!r} omits 'sub', which is the claim every "
            f"IRSA trust policy conditions on"
        )

        # (3) The JWKS is served, is public (no Authorization header), and carries a usable RSA
        #     signing key.
        jwks_status, jwks_raw = _public_get(ctx, doc["jwks_uri"])
        assert jwks_status == 200, (
            f"GET {doc['jwks_uri']} with no Authorization header returned {jwks_status}; the JWKS "
            f"must be anonymously readable: {jwks_raw[:300]!r}"
        )
        keys = json.loads(jwks_raw)["keys"]
        signing = [
            k for k in keys
            if k.get("kty") == "RSA" and k.get("alg") == "RS256" and k.get("use") == "sig"
            and k.get("n") and k.get("e")
        ]
        assert signing, (
            f"the JWKS at {doc['jwks_uri']} has no RSA/RS256/sig key with both n and e: {keys!r}"
        )

        # (4) The token's JOSE header names RS256 -- not `none`, not HS256 -- and its kid selects
        #     exactly one published key.
        assert header["alg"] == "RS256", (
            f"the projected ServiceAccount token is signed with {header['alg']!r}; a symmetric or "
            f"absent algorithm means the published JWKS cannot verify anything"
        )
        matched = [k for k in signing if k["kid"] == header["kid"]]
        assert len(matched) == 1, (
            f"the token's kid {header['kid']!r} matches {len(matched)} of the JWKS's "
            f"{[k.get('kid') for k in keys]!r}"
        )
        jwk = matched[0]

        # (5) THE HEADLINE: the signature verifies offline, by this check's own arithmetic, against
        #     the modulus and exponent the issuer published. No golden, no network call.
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        digest = hashlib.sha256(signing_input).digest()
        recovered = _pkcs1_v15_recover(jwk, signature)
        expected = _expected_block(len(recovered), digest)
        assert recovered == expected, (
            f"the RS256 signature on the projected token does NOT verify against the JWKS key "
            f"{header['kid']!r}: sig^e mod n recovered {recovered[:24].hex()}..."
            f"{recovered[-40:].hex()} but a valid PKCS#1 v1.5 block over sha256(signing input) "
            f"would be {expected[:24].hex()}...{expected[-40:].hex()}"
        )

        # (6) The claims name this issuer, the requested audience and this ServiceAccount.
        assert claims["iss"] == issuer, f"token iss is {claims['iss']!r}, not {issuer!r}"
        assert claims["aud"] == [_AUDIENCE], (
            f"token aud is {claims['aud']!r}, not the requested [{_AUDIENCE!r}]"
        )
        assert claims["sub"] == f"system:serviceaccount:{ns}:{sa}", (
            f"token sub is {claims['sub']!r}; an IRSA trust policy conditions on exactly this "
            f"string, so a different shape silently breaks every StringEquals on it"
        )

        # (7) The token is bound to real stored cluster state: the `kubernetes.io` claim block
        #     carries the ServiceAccount UID the API server minted when it created the object.
        k8s_claims = claims["kubernetes.io"]
        assert k8s_claims["namespace"] == ns, (
            f"kubernetes.io.namespace is {k8s_claims['namespace']!r}, not {ns!r}"
        )
        assert k8s_claims["serviceaccount"]["name"] == sa, (
            f"kubernetes.io.serviceaccount.name is "
            f"{k8s_claims['serviceaccount']['name']!r}, not {sa!r}"
        )
        assert k8s_claims["serviceaccount"]["uid"] == sa_uid, (
            f"kubernetes.io.serviceaccount.uid is {k8s_claims['serviceaccount']['uid']!r} but the "
            f"ServiceAccount the API server stored has uid {sa_uid!r}"
        )

        # (8) Two independently produced representations of the same expiry agree.
        assert claims["exp"] - claims["iat"] == _TOKEN_TTL_S, (
            f"the token's lifetime is {claims['exp'] - claims['iat']}s but "
            f"expirationSeconds={_TOKEN_TTL_S} was requested"
        )
        stamp = minted["status"]["expirationTimestamp"]
        parsed = calendar.timegm(time.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ"))
        assert abs(parsed - claims["exp"]) <= 60, (
            f"TokenRequest status.expirationTimestamp {stamp!r} parses to {parsed} but the "
            f"token's own exp claim is {claims['exp']} -- the two representations disagree"
        )

        # (9) FAILURE ARM A -- flip the last byte of the signature. The recovered block stops
        #     looking like a PKCS#1 block at all, so assertion (5) is not vacuous.
        tampered_sig = bytearray(signature)
        tampered_sig[-1] ^= 0x01
        recovered_bad_sig = _pkcs1_v15_recover(jwk, bytes(tampered_sig))
        assert recovered_bad_sig != expected, (
            "flipping the last byte of the signature still verified, so assertion (5) is not "
            "actually checking the signature"
        )
        assert not recovered_bad_sig.startswith(b"\x00\x01\xff\xff"), (
            f"a one-byte signature corruption left intact PKCS#1 padding "
            f"{recovered_bad_sig[:8].hex()}, which is arithmetically impossible for a real RSA "
            f"modulus -- the key material is not what it claims to be"
        )

        # (10) FAILURE ARM B -- flip a byte of the SIGNING INPUT instead. The padding survives (the
        #      signature is untouched) and only the trailing digest differs, proving the digest
        #      itself is being compared and not merely the block's shape.
        flipped_input = signing_input[:-1] + bytes([signing_input[-1] ^ 0x01])
        flipped_expected = _expected_block(len(recovered), hashlib.sha256(flipped_input).digest())
        assert recovered != flipped_expected, (
            "a one-byte change to the signing input produced the same PKCS#1 block, so the digest "
            "comparison in assertion (5) is vacuous"
        )
        assert recovered[:-32] == flipped_expected[:-32], (
            f"the padding half of the block changed too, so failure arm B is not isolating the "
            f"digest: {recovered[:-32][:16].hex()} vs {flipped_expected[:-32][:16].hex()}"
        )
        assert recovered[-32:] == digest and flipped_expected[-32:] != digest, (
            f"the recovered trailing 32 bytes {recovered[-32:].hex()} are not sha256 of the real "
            f"signing input {digest.hex()}"
        )

        # (11) The requested audience is honoured rather than ignored, and changing it changes
        #      nothing else: same subject, same issuer, still verifiable by the same key.
        alt = _token_request(ctx, conn, ns, sa, _ALT_AUDIENCE)
        alt_header_b64, alt_payload_b64, alt_sig_b64 = alt["status"]["token"].split(".")
        alt_claims = json.loads(_b64url(alt_payload_b64))
        assert alt_claims["aud"] == [_ALT_AUDIENCE], (
            f"a TokenRequest for audience {_ALT_AUDIENCE!r} minted a token with aud "
            f"{alt_claims['aud']!r} -- the audience is being ignored, which would let a token "
            f"issued for one relying party be replayed at another"
        )
        assert alt_claims["sub"] == claims["sub"], (
            f"changing only the audience also changed the subject to {alt_claims['sub']!r}"
        )
        alt_signing_input = f"{alt_header_b64}.{alt_payload_b64}".encode("ascii")
        alt_recovered = _pkcs1_v15_recover(jwk, _b64url(alt_sig_b64))
        assert alt_recovered == _expected_block(
            len(alt_recovered), hashlib.sha256(alt_signing_input).digest()
        ), (
            f"the second token, minted for audience {_ALT_AUDIENCE!r}, does not verify against the "
            f"same published key {jwk['kid']!r}"
        )

        # (12) The two trust anchors are genuinely different. The issuer is a public AWS-hosted
        #      endpoint on the public PKI; the API server is not, and is not anonymously readable.
        cluster_only = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cluster_only.check_hostname = True
        cluster_only.verify_mode = ssl.CERT_REQUIRED
        cluster_only.load_verify_locations(cadata=ca_pem)
        # urlopen wraps a TLS verification failure in URLError, so the specific exception is read
        # off `.reason` -- catching URLError alone would also absorb a DNS or connect failure and
        # let this assertion pass for the wrong reason.
        try:
            _public_get(ctx, doc["jwks_uri"], ssl_ctx=cluster_only)
            tls_reason = None
        except urllib.error.URLError as exc:
            tls_reason = exc.reason
        assert isinstance(tls_reason, ssl.SSLCertVerificationError), (
            f"fetching {doc['jwks_uri']} while trusting ONLY the cluster's certificateAuthority "
            f"PEM did not fail TLS verification (got {tls_reason!r}); the OIDC issuer must be a "
            f"separate endpoint on the public PKI, not something the cluster CA signs"
        )
        anon_status, anon_raw = _k8s(
            ctx, conn, "GET", f"/api/v1/namespaces/{ns}", authenticate=False
        )
        assert anon_status == 401, (
            f"the API server answered an anonymous GET with {anon_status}, not 401: "
            f"{anon_raw[:300]!r} -- the JWKS being public must not mean the API server is"
        )
        assert b"\"items\"" not in anon_raw and sa_uid.encode() not in anon_raw, (
            f"the 401 body leaked cluster state: {anon_raw[:300]!r}"
        )

        # Inline, verified teardown under the check's own budget.
        _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}", timeout_s=90)
        _wait_for(
            lambda: _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}")[0],
            lambda code: code == 404,
            timeout_s=180,
            interval_s=5,
            desc=f"namespace {ns} deleted",
        )
    except BaseException:
        # Set so the inline teardown's own failure cannot mask the failure that caused it.
        # ctx.on_cleanup remains the net for that path.
        body_failed.append(True)
        raise
    finally:
        try:
            _teardown_cluster(eks, cluster_name)
            _delete_role(iam, role_name)
        except BaseException:
            if not body_failed:
                raise

    remaining = [
        n for n in ctx.client("eks").list_clusters().get("clusters", [])
        if n == cluster_name
    ]
    assert remaining == [], (
        f"the control plane {cluster_name!r} survived the inline teardown: ListClusters still "
        f"reports {remaining!r}, which is a billable leak"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
