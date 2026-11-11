"""access-token-verifies-rs256-under-an-issuer-jwks-key-distinct-from-the-id-tokens."""
from __future__ import annotations

import base64
import hashlib
import json
import ssl
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-token-verifies-rs256-under-an-issuer-jwks-key-distinct-from-the-id-tokens"
GROUP = "oidc-discovery"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_GONE = "ResourceNotFoundException"
# DER DigestInfo prefix for SHA-256 in an RSASSA-PKCS1-v1_5 signature (RFC 8017 section 9.2).
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The access token verifies RS256 under the RSA sig key its kid names in the unsigned
    {iss}/.well-known/jwks.json, and that key is not the one the same sign-in's ID token names.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html"""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id), _GONE))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(FLOWS), GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(_teardown(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id), _GONE))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(_teardown(
        lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username),
        _GONE, "UserNotFoundException"))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )
    tokens = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]
    id_jws = _jws(tokens["IdToken"])
    access_jws = _jws(tokens["AccessToken"])
    iss = id_jws["claims"].get("iss")
    assert isinstance(iss, str) and iss.endswith(f"/{pool_id}"), (
        f"expected the ID token's iss to end in the pool id, got iss={iss!r}"
    )
    assert access_jws["claims"].get("iss") == iss, (
        f"expected the access token's iss to equal the ID token's {iss!r}, "
        f"got {access_jws['claims'].get('iss')!r}"
    )

    keys = _get_json(ctx, f"{iss}/.well-known/jwks.json").get("keys")
    assert isinstance(keys, list), f"expected a JWKS keys array, got {keys!r}"
    by_kid = {k.get("kid"): k for k in keys if isinstance(k, dict)}
    kid = access_jws["header"].get("kid")
    jwk = by_kid.get(kid)
    assert jwk is not None, (
        f"the access token's kid is not among the {len(keys)} keys of its issuer's JWKS"
    )
    shape = {f: jwk.get(f) for f in ("kty", "alg", "use")}
    assert shape == {"kty": "RSA", "alg": "RS256", "use": "sig"}, (
        f"expected the access token's key to be an RSA RS256 signing key, got {shape!r}"
    )
    # RFC 7518 section 6.3.1: an RSA public JWK carries its modulus n and exponent e.
    assert all(isinstance(jwk.get(f), str) and jwk[f] for f in ("n", "e")), (
        f"expected the access token's RSA key to carry n and e, got members {sorted(jwk)!r}"
    )
    assert access_jws["header"].get("alg") == "RS256", (
        f"expected the access token's header alg RS256, got {access_jws['header'].get('alg')!r}"
    )
    assert _rs256_verifies(jwk, access_jws["signing_input"], access_jws["signature"]), (
        "the access token's signature does not verify under the JWKS key its kid names"
    )
    # A user pool signs ID and access tokens with separate key pairs.
    id_kid = id_jws["header"].get("kid")
    assert id_kid in by_kid and id_kid != kid, (
        f"expected the ID token to name another key of the JWKS: id kid "
        f"{'equals the access kid' if id_kid == kid else 'in JWKS: ' + repr(id_kid in by_kid)}"
    )


# ===== helpers =====
def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _jws(token: str) -> dict:
    """Header, claims, signing input and signature of a compact JWS."""
    parts = token.split(".")
    assert len(parts) == 3, f"not a compact JWS (header.payload.signature): {token[:24]!r}..."
    return {"header": json.loads(_b64url_decode(parts[0])),
            "claims": json.loads(_b64url_decode(parts[1])),
            "signing_input": f"{parts[0]}.{parts[1]}".encode(),
            "signature": _b64url_decode(parts[2])}


def _rs256_verifies(jwk: dict, signing_input: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 SHA-256 verification of ``signature`` under the JWK's n and e."""
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    size = (n.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    encoded = pow(int.from_bytes(signature, "big"), e, n).to_bytes(size, "big")
    digest = hashlib.sha256(signing_input).digest()
    padding = b"\xff" * (size - len(_SHA256_DIGEST_INFO) - len(digest) - 3)
    return encoded == b"\x00\x01" + padding + b"\x00" + _SHA256_DIGEST_INFO + digest


def _tls(ctx):
    """The TLS context ctx.http_verify asks for: a CA bundle path, unverified, or the default."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _get_json(ctx, url: str) -> dict:
    """GET a published URL on the target, unsigned, and parse its JSON body."""
    target, headers = ctx.endpoint_route(url)
    request = urllib.request.Request(target, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30, context=_tls(ctx)) as resp:  # noqa: S310
            body = resp.read().decode()
    except urllib.error.HTTPError as exc:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: {url} answered HTTP {exc.code}: {exc.read()[:200]!r}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise AssertionError(f"DATAPLANE_UNIMPLEMENTED: nothing answered at {url}: {exc}") from exc
    try:
        return json.loads(body)
    except ValueError as exc:
        raise AssertionError(f"{url} answered a non-JSON body: {body[:200]!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
