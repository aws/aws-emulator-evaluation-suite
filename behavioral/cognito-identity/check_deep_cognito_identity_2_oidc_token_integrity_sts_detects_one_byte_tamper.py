"""deep-cognito-identity-2-oidc-token-integrity-sts-detects-one-byte-tamper."""
from __future__ import annotations

import base64
import json
import time
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-identity-2-oidc-token-integrity-sts-detects-one-byte-tamper"
GROUP = 'token-integrity'
SERVICES = ['cognito-identity']

# Cognito Identity signs its OpenID tokens with
# RS512, not RS256: the JOSE header is {"kid": "<region>-<n>", "typ": "JWS", "alg": "RS512"} and
# the issuer's own discovery document (https://cognito-identity.amazonaws.com/.well-known/
# openid-configuration) advertises id_token_signing_alg_values_supported == ["RS512"] only.
EXPECTED_ALG = "RS512"
EXPECTED_TYP = "JWS"
# The issuer is the partition-global Cognito Identity host, not a regional one (the
# regional identity-pool ARN travels in a separate claim): https, the service
# label, then the domain, which is the target's own, and no path.
ISSUER_LABEL = "cognito-identity"
FEDERATED_PRINCIPAL = "cognito-identity.amazonaws.com"
ERR_INVALID_TOKEN = "InvalidIdentityToken"
# The tamper refusal names a per-run value between this prefix and suffix.
MSG_UNVALIDATED_PREFIX = "The web identity token provided could not be validated. See the "
MSG_UNVALIDATED_SUFFIX = " documentation for requirements."
MSG_UNSIGNED = "We don't accept unsigned JWTs"
SESSION_NAME = "sim2real-oidc-integrity"


# ===== helpers =====

def _assert_global_issuer(iss, region):
    """``iss`` is ``https://cognito-identity.<domain>``: the service label leads the host, no
    region label follows it, and the URL has no path, query or fragment."""
    parts = urlsplit(iss) if isinstance(iss, str) else None
    labels = (parts.hostname or "").split(".") if parts else []
    assert (parts is not None and parts.scheme == "https" and labels[0] == ISSUER_LABEL
            and len(labels) > 1 and all(labels[1:]) and region not in labels
            and not parts.path and not parts.query and not parts.fragment), (
        f"iss must be the global https://{ISSUER_LABEL}.<domain> issuer, got {iss!r}")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _error(fn):
    """Call fn() expecting failure; return the AWS error (Code, Message). An unexpected SUCCESS raises,
    because turning acceptance into a falsy sentinel would let an over-permissive target pass."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet."""
    deadline = time.time() + timeout_s
    last = None
    last_exc = None
    while time.time() < deadline:
        try:
            last = fn()
            if pred(last):
                return last
            last_exc = None
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


def _flip_one_payload_byte(payload_raw: bytes) -> tuple[bytes, int]:
    """Flip the low bit of the middle-most byte that stays an alphanumeric JSON string character,
    so the tampered payload is still well-formed JSON and differs from the original in exactly one
    byte. STS then cannot reject it for being unparseable -- only for failing signature validation.
    """
    safe = set(b"abcdefghijklmnopqrstuvwxy0123456789")
    mid = len(payload_raw) // 2
    for offset in range(len(payload_raw)):
        for idx in (mid + offset, mid - offset):
            if 0 <= idx < len(payload_raw) and payload_raw[idx] in safe:
                flipped = bytearray(payload_raw)
                flipped[idx] ^= 0x01
                return bytes(flipped), idx
    raise AssertionError(f"no flippable byte in a {len(payload_raw)}-byte payload")


# ===== check =====

@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """STS redeems the OpenID token Cognito Identity vends, refuses it with one payload byte
    flipped (and an alg:none re-header) with InvalidIdentityToken, and redeems the untouched
    token again afterwards, so the token is really signed."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_oidc_integrity_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        AllowClassicFlow=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": FEDERATED_PRINCIPAL},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}},
        }],
    })
    role_name = ctx.unique_name("sim2real-oidc-integrity-")[:64]
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    partition = role["Arn"].split(":")[1]
    expected_assumed_arn = f"arn:{partition}:sts::{account}:assumed-role/{role_name}/{SESSION_NAME}"

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    minted = ci.get_open_id_token(IdentityId=identity_id)
    assert minted["IdentityId"] == identity_id, (
        f"GetOpenIdToken echoed IdentityId {minted['IdentityId']!r} != {identity_id!r}"
    )
    token = minted["Token"]

    # --- the token is a JWS with the exact header and issuer real AWS emits -------------------
    segments = token.split(".")
    assert len(segments) == 3, f"expected a 3-segment JWS, got {len(segments)} segments"
    header_b64, payload_b64, signature_b64 = segments
    header = json.loads(_b64url_decode(header_b64))
    payload_raw = _b64url_decode(payload_b64)
    claims = json.loads(payload_raw)
    signature = _b64url_decode(signature_b64)

    assert header.get("alg") == EXPECTED_ALG, (
        f"JOSE header alg must be exactly {EXPECTED_ALG!r} (never 'none', never merely truthy), "
        f"got {header.get('alg')!r}"
    )
    assert header.get("typ") == EXPECTED_TYP, f"JOSE header typ must be {EXPECTED_TYP!r}, got {header!r}"
    assert isinstance(header.get("kid"), str) and header["kid"].startswith(f"{ctx.region}-"), (
        f"JOSE header kid must name a {ctx.region} signing key, got {header.get('kid')!r}"
    )
    # An RS512 signature is exactly the RSA modulus length; Cognito's keys are 2048-bit.
    assert len(signature) == 256, (
        f"an RS512 signature from a 2048-bit key is 256 bytes, got {len(signature)}"
    )
    _assert_global_issuer(claims.get("iss"), ctx.region)
    assert claims.get("sub") == identity_id, f"sub {claims.get('sub')!r} != IdentityId {identity_id!r}"
    assert claims.get("aud") == pool_id, f"aud {claims.get('aud')!r} != identity pool {pool_id!r}"

    def _assume(web_token):
        return sts.assume_role_with_web_identity(
            RoleArn=role["Arn"], RoleSessionName=SESSION_NAME, WebIdentityToken=web_token,
        )

    def _assert_redeems(response, phase):
        assert response["AssumedRoleUser"]["Arn"] == expected_assumed_arn, (
            f"[{phase}] AssumedRoleUser.Arn must be exactly {expected_assumed_arn!r}, got "
            f"{response['AssumedRoleUser']['Arn']!r}"
        )
        assert response["SubjectFromWebIdentityToken"] == identity_id, (
            f"[{phase}] SubjectFromWebIdentityToken {response['SubjectFromWebIdentityToken']!r} "
            f"!= {identity_id!r}"
        )
        assert response["Audience"] == pool_id, (
            f"[{phase}] Audience {response['Audience']!r} != {pool_id!r}"
        )
        assert response["Provider"] == FEDERATED_PRINCIPAL, (
            f"[{phase}] Provider {response['Provider']!r} != {FEDERATED_PRINCIPAL!r}"
        )

    # --- positive control BEFORE: the untouched token redeems (the retry absorbs only IAM
    # propagation of the new role's trust policy, which no API exposes as a condition) --------
    before = _poll_until(
        lambda: _assume(token),
        lambda r: "Credentials" in r,
        description="sts:AssumeRoleWithWebIdentity to accept the untouched token (role propagation)",
    )
    _assert_redeems(before, "before tamper")

    # --- break exactly one thing: one byte of the payload segment ------------------------------
    tampered_raw, idx = _flip_one_payload_byte(payload_raw)
    diff = [i for i in range(len(payload_raw)) if payload_raw[i] != tampered_raw[i]]
    assert diff == [idx] and len(tampered_raw) == len(payload_raw), (
        f"the tamper must change exactly one byte, changed offsets {diff!r}"
    )
    tampered_claims = json.loads(tampered_raw)  # still well-formed: the refusal is not a parse error
    assert tampered_claims != claims, "the tampered payload must decode to different claims"
    tampered_token = f"{header_b64}.{_b64url_encode(tampered_raw)}.{signature_b64}"
    assert tampered_token != token and tampered_token.split(".")[0::2] == [header_b64, signature_b64], (
        "the tampered token must differ only in its payload segment"
    )

    err = _error(lambda: _assume(tampered_token))
    code, msg = err.get("Code"), err.get("Message") or ""
    assert code == ERR_INVALID_TOKEN, (
        f"STS must refuse a token whose payload byte {idx} was flipped "
        f"({chr(payload_raw[idx])!r} -> {chr(tampered_raw[idx])!r}) with {ERR_INVALID_TOKEN!r}, "
        f"got {code!r}"
    )
    assert msg.startswith(MSG_UNVALIDATED_PREFIX) and msg.endswith(MSG_UNVALIDATED_SUFFIX), msg

    # --- positive control AFTER: the untouched token still redeems -----------------------------
    after = _assume(token)
    _assert_redeems(after, "after tamper")

    # --- a second, independent break: the untouched payload re-headed as alg:none, unsigned ----
    none_header = dict(header, alg="none")
    unsigned = f"{_b64url_encode(json.dumps(none_header).encode())}.{payload_b64}."
    err_none = _error(lambda: _assume(unsigned))
    assert (err_none.get("Code"), err_none.get("Message")) == (ERR_INVALID_TOKEN, MSG_UNSIGNED), (
        f"STS must refuse an unsigned alg:none token with {ERR_INVALID_TOKEN!r}: {MSG_UNSIGNED!r}, "
        f"got {err_none!r}"
    )

    final = _assume(token)
    _assert_redeems(final, "after alg:none")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
