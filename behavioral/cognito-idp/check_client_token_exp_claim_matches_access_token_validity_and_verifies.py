"""client-token-exp-claim-matches-access-token-validity-and-verifies."""
from __future__ import annotations

import base64
import hashlib
import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "client-token-exp-claim-matches-access-token-validity-and-verifies"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-idp"]

#: AccessTokenValidity configured on the app client, in seconds (the 5-minute minimum).
_VALIDITY_S = 300
#: Client/server clock skew plus request latency allowed around now + validity.
_SKEW_S = 120


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetClientToken for a client with AccessTokenValidity 300 s returns ExpiresIn 300 and a token
    whose exp is exactly iat + 300 and within 120 s of now + 300, signed by a key the pool publishes.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html
    """
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)

    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-m2m-"),
        GenerateSecret=True,
        ExplicitAuthFlows=["ALLOW_CLIENT_TOKEN_AUTH"],
        AccessTokenValidity=_VALIDITY_S,
        TokenValidityUnits={"AccessToken": "seconds"},
    )["UserPoolClient"]
    client_id = client["ClientId"]
    client_secret = client["ClientSecret"]

    before = time.time()
    result = cognito.get_client_token(ClientId=client_id, Secret=client_secret)["ClientAuthenticationResult"]
    after = time.time()
    assert result["ExpiresIn"] == _VALIDITY_S, f"expected ExpiresIn {_VALIDITY_S}, got {result['ExpiresIn']!r}"
    assert result["TokenType"] == "Bearer", f"expected TokenType Bearer, got {result.get('TokenType')!r}"

    token = result["AccessToken"]
    header_b64, payload_b64, sig_b64 = token.split(".")
    claims = _decode_jwt_segment(payload_b64)
    assert claims["token_use"] == "access", f"expected token_use 'access', got {claims.get('token_use')!r}"
    assert claims["client_id"] == client_id, f"expected client_id {client_id!r}, got {claims.get('client_id')!r}"
    assert claims["exp"] - claims["iat"] == _VALIDITY_S, (
        f"exp - iat must equal the configured {_VALIDITY_S}s, got {claims['exp'] - claims['iat']}s"
    )
    low, high = before + _VALIDITY_S - _SKEW_S, after + _VALIDITY_S + _SKEW_S
    assert low <= claims["exp"] <= high, (
        f"exp {claims['exp']} must lie within {_SKEW_S}s of now + {_VALIDITY_S}s, i.e. in "
        f"[{low:.0f}, {high:.0f}]"
    )

    # While valid, the token verifies against the RS256 key with its kid in the pool's JWKS.
    header = _decode_jwt_segment(header_b64)
    assert header.get("alg") == "RS256", f"expected alg RS256, got {header.get('alg')!r}"
    url = _jwks_url(cognito, pool_id)
    try:
        jwks = _http_get_json(ctx, url)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: the pool's JWKS document {url} answered 404, so no public "
            f"signing key is served"
        ) from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: nothing answered at the pool's JWKS document {url}: {exc}"
        ) from exc
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    assert jwk is not None, f"kid {header.get('kid')!r} not present in JWKS {jwks}"
    assert jwk.get("kty") == "RSA", f"expected an RSA JWK, got {jwk.get('kty')!r}"
    signature = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    assert _verify_rs256(f"{header_b64}.{payload_b64}".encode(), signature, jwk), (
        "the client token's RS256 signature must verify against the published JWKS key"
    )


def _create_user_pool(ctx, cognito):
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _decode_jwt_segment(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def _jwks_url(client, pool_id: str) -> str:
    """Public JWKS document URL for a user pool, resolved from the client's endpoint_url."""
    return f"{client.meta.endpoint_url.rstrip('/')}/{pool_id}/.well-known/jwks.json"


def _tls(ctx):
    """The TLS context ctx.http_verify asks for: a CA bundle path, unverified, or the default."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http_get_json(ctx, url: str, timeout_s: float = 30) -> dict:
    with urllib.request.urlopen(url, timeout=timeout_s, context=_tls(ctx)) as r:  # noqa: S310 - fixed https/http scheme
        return json.loads(r.read().decode())


def _b64url_to_int(segment: str) -> int:
    padding = "=" * (-len(segment) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(segment + padding), "big")


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict) -> bool:
    """Verify an RS256 (RSASSA-PKCS1-v1_5, SHA-256) JWT signature against a JWK public key."""
    n = _b64url_to_int(jwk["n"])
    e = _b64url_to_int(jwk["e"])
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    # DigestInfo DER prefix for SHA-256.
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    expected = b"\x00\x01" + b"\xff" * (k - len(prefix) - len(digest) - 3) + b"\x00" + prefix + digest
    return em == expected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
