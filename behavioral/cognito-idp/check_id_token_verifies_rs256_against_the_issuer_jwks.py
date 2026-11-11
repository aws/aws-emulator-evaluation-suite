"""id-token-verifies-rs256-against-the-issuer-jwks."""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from behavioral_harness import tags

CHECK = "id-token-verifies-rs256-against-the-issuer-jwks"
GROUP = "oidc-discovery"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_TIER = "sim2real-gold"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A USER_PASSWORD_AUTH ID token verifies RS256 under the kid it names in its issuer's JWKS,
    with iss, aud, token_use, cognito:username, sub and custom: claims a web app relies on."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        Schema=[{"Name": "tier", "AttributeDataType": "String", "Mutable": True}],
        UserPoolTags=dict(_POOL_TAGS),
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
    c.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "custom:tier", "Value": _TIER}],
    )
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )
    stored = {a["Name"]: a["Value"]
              for a in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]}

    id_token = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["IdToken"]
    header, claims, signing_input, signature = _jwt(id_token)
    assert header.get("alg") == "RS256", f"expected ID token alg RS256, got {header!r}"
    assert header.get("kid"), f"expected a kid in the ID token header, got {header!r}"

    _assert_issuer(ctx, claims.get("iss"), pool_id)
    assert claims.get("aud") == client_id, (
        f"expected aud to be the app client {client_id!r}, got {claims.get('aud')!r}"
    )
    assert claims.get("token_use") == "id", f"expected token_use 'id', got {claims.get('token_use')!r}"
    assert claims.get("cognito:username") == username, (
        f"expected cognito:username {username!r}, got {claims.get('cognito:username')!r}"
    )
    assert claims.get("sub") == stored["sub"], (
        f"expected sub to equal the stored sub attribute, got {claims.get('sub')!r}"
    )
    assert claims.get("custom:tier") == _TIER, (
        f"expected custom:tier {_TIER!r}, got {claims.get('custom:tier')!r}"
    )
    assert isinstance(claims.get("exp"), int) and isinstance(claims.get("iat"), int), (
        f"expected integer exp and iat, got exp={claims.get('exp')!r} iat={claims.get('iat')!r}"
    )
    assert claims["exp"] - claims["iat"] == 3600, (
        f"expected the default one-hour ID token lifetime, got exp-iat={claims['exp'] - claims['iat']}"
    )

    jwks = _get_json(ctx, f"{claims['iss']}/.well-known/jwks.json")
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == header["kid"]), None)
    assert jwk is not None, (
        f"the ID token's kid is not among the {len(jwks.get('keys', []))} keys of its issuer's JWKS"
    )
    assert jwk.get("kty") == "RSA" and jwk.get("alg") == "RS256", (
        f"expected an RSA RS256 key for the ID token's kid, got kty={jwk.get('kty')!r} "
        f"alg={jwk.get('alg')!r}"
    )
    assert _rs256_verifies(jwk, signing_input, signature), (
        "the ID token's RS256 signature does not verify under the issuer's published key for its kid"
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
