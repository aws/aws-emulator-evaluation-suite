"""openid-discovery-jwks-uri-serves-unique-unpadded-rs256-signing-keys."""
from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from behavioral_harness import tags

CHECK = "openid-discovery-jwks-uri-serves-unique-unpadded-rs256-signing-keys"
GROUP = "oidc-discovery"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
# RFC 7515 base64url: the URL-safe alphabet with the trailing '=' padding removed.
_B64URL = re.compile(r"[A-Za-z0-9_-]+")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The ID token issuer's discovery document names that issuer, RS256 and a jwks_uri whose
    every key is a unique-kid RSA RS256 signing key in unpadded base64url; exactly the key the
    token's kid names verifies it."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: c.delete_user_pool(UserPoolId=_p))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(FLOWS), GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )
    id_token = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["IdToken"]
    header, claims, signing_input, signature = _jwt(id_token)
    issuer = claims.get("iss")
    _assert_issuer(ctx, issuer, pool_id)

    # OpenID Connect Discovery 1.0 section 4: the document lives under the issuer and repeats it.
    cfg = _get_json(ctx, f"{issuer}/.well-known/openid-configuration")
    assert cfg.get("issuer") == issuer, (
        f"the discovery issuer must equal the token's iss {issuer!r}, got {cfg.get('issuer')!r}"
    )
    assert cfg.get("jwks_uri") == f"{issuer}/.well-known/jwks.json", (
        f"expected jwks_uri {issuer + '/.well-known/jwks.json'!r}, got {cfg.get('jwks_uri')!r}"
    )
    assert cfg.get("id_token_signing_alg_values_supported") == ["RS256"], (
        f"expected id_token_signing_alg_values_supported ['RS256'], got "
        f"{cfg.get('id_token_signing_alg_values_supported')!r}"
    )
    assert cfg.get("subject_types_supported") == ["public"], (
        f"expected subject_types_supported ['public'], got {cfg.get('subject_types_supported')!r}"
    )

    keys = _get_json(ctx, cfg["jwks_uri"]).get("keys")
    assert isinstance(keys, list) and keys, f"expected a non-empty JWKS keys array, got {keys!r}"
    kids = [k.get("kid") for k in keys]
    assert len(set(kids)) == len(kids), (
        f"JWKS kids must be unique, got {len(kids)} keys and {len(set(kids))} distinct kids"
    )
    for i, key in enumerate(keys):
        shape = {f: key.get(f) for f in ("kty", "alg", "use")}
        assert shape == {"kty": "RSA", "alg": "RS256", "use": "sig"}, (
            f"JWKS key {i} must be an RSA RS256 signing key, got {shape!r}"
        )
        assert isinstance(key.get("kid"), str) and key["kid"], (
            f"JWKS key {i} has no kid: {key.get('kid')!r}"
        )
        for member in ("n", "e"):
            value = key.get(member)
            assert isinstance(value, str) and _B64URL.fullmatch(value), (
                f"JWKS key {i} member {member} must be unpadded base64url, got "
                f"{(value[-4:] if isinstance(value, str) else value)!r} at its end"
            )
        modulus = int.from_bytes(_b64url_decode(key["n"]), "big")
        assert modulus.bit_length() >= 2048, (
            f"JWKS key {i} modulus is {modulus.bit_length()} bits, expected at least 2048"
        )
        assert int.from_bytes(_b64url_decode(key["e"]), "big") == 65537, (
            f"JWKS key {i} exponent must be 65537, got e={key['e']!r}"
        )

    verifying = [k["kid"] for k in keys if _rs256_verifies(k, signing_input, signature)]
    assert verifying == [header.get("kid")], (
        f"exactly the key named by the ID token's kid must verify it; {len(verifying)} of "
        f"{len(keys)} keys verify and the header kid is "
        f"{'present' if header.get('kid') in kids else 'absent'}"
    )


# ===== helpers =====
def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _jwt(token: str) -> tuple[dict, dict, bytes, bytes]:
    """(header, claims, signing input, signature) of a compact JWS."""
    parts = token.split(".")
    assert len(parts) == 3, f"not a compact JWS (header.payload.signature): {token[:24]!r}..."
    return (json.loads(_b64url_decode(parts[0])), json.loads(_b64url_decode(parts[1])),
            f"{parts[0]}.{parts[1]}".encode(), _b64url_decode(parts[2]))


def _tls(ctx):
    """The TLS context ctx.http_verify asks for: a CA bundle path, unverified, or the default."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _get_json(ctx, url: str) -> dict:
    """GET a published URL on the target and parse its JSON body."""
    target, headers = ctx.endpoint_route(url)
    request = urllib.request.Request(target, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30, context=_tls(ctx)) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: {url} answered HTTP {exc.code}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise AssertionError(f"DATAPLANE_UNIMPLEMENTED: nothing answered at {url}: {exc}") from exc


def _assert_issuer(ctx, iss, pool_id: str) -> None:
    """iss is https://cognito-idp.<region>.<domain>/<pool id>; the domain is the target's own."""
    parts = urlsplit(iss) if isinstance(iss, str) else None
    labels = (parts.hostname or "").split(".") if parts else []
    assert (parts is not None and parts.scheme == "https"
            and labels[:2] == ["cognito-idp", ctx.region] and len(labels) > 2
            and all(labels[2:]) and parts.path == f"/{pool_id}"
            and not parts.query and not parts.fragment), (
        f"the ID token must be issued by https://cognito-idp.{ctx.region}.<domain>/<pool id>, "
        f"got iss={iss!r}"
    )


def _rs256_verifies(jwk: dict, signing_input: bytes, signature: bytes) -> bool:
    """True when the RSASSA-PKCS1-v1_5 SHA-256 signature verifies under the JWK's public key."""
    key = rsa.RSAPublicNumbers(
        int.from_bytes(_b64url_decode(jwk["e"]), "big"),
        int.from_bytes(_b64url_decode(jwk["n"]), "big"),
    ).public_key()
    try:
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
