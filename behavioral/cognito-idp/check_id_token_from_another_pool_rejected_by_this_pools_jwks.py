"""id-token-from-another-pool-rejected-by-this-pools-jwks."""
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

CHECK = "id-token-from-another-pool-rejected-by-this-pools-jwks"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Each pool signs with its own keys: an ID token verifies under its own pool's JWKS, shared
    by the pool's clients, and under no key of another pool's JWKS, whose kids and moduli are
    disjoint."""
    c = ctx.client("cognito-idp")
    pools = {}
    for label in ("a", "b"):
        pool_id = c.create_user_pool(
            PoolName=ctx.unique_name(f"sim2real-behav-cip-pool-{label}-"),
            UserPoolTags=dict(_POOL_TAGS),
        )["UserPool"]["Id"]
        ctx.on_cleanup(lambda _p=pool_id: c.delete_user_pool(UserPoolId=_p))
        client_ids = []
        for _ in range(2 if label == "a" else 1):
            client_id = c.create_user_pool_client(
                UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
                ExplicitAuthFlows=list(FLOWS), GenerateSecret=False,
            )["UserPoolClient"]["ClientId"]
            ctx.on_cleanup(
                lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
            )
            client_ids.append(client_id)
        username = ctx.unique_name("sim2real-behav-cip-user-")
        c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
        ctx.on_cleanup(
            lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
        )
        c.admin_set_user_password(
            UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
        )
        tokens = [
            c.initiate_auth(
                ClientId=cid, AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
            )["AuthenticationResult"]["IdToken"]
            for cid in client_ids
        ]
        pools[label] = {"id": pool_id, "tokens": tokens}

    for label in ("a", "b"):
        _, claims, _, _ = _jwt(pools[label]["tokens"][0])
        _assert_issuer(ctx, claims.get("iss"), pools[label]["id"])
        pools[label]["keys"] = _get_json(ctx, f"{claims['iss']}/.well-known/jwks.json").get("keys", [])
        assert pools[label]["keys"], f"pool {label}'s JWKS publishes no keys"

    # Positive control: both clients of pool a get tokens signed by the same pool key.
    kids_a = {k["kid"] for k in pools["a"]["keys"]}
    for i, token in enumerate(pools["a"]["tokens"]):
        header, _, signing_input, signature = _jwt(token)
        assert header.get("kid") in kids_a, (
            f"client {i} of pool a signed with a kid absent from pool a's JWKS"
        )
        own = next(k for k in pools["a"]["keys"] if k["kid"] == header["kid"])
        assert _rs256_verifies(own, signing_input, signature), (
            f"client {i} of pool a: the ID token does not verify under its own pool's key"
        )
    header_kids = {_jwt(t)[0].get("kid") for t in pools["a"]["tokens"]}
    assert len(header_kids) == 1, (
        f"the clients of one pool must share its signing key, got {len(header_kids)} distinct kids"
    )

    kids_b = {k["kid"] for k in pools["b"]["keys"]}
    shared_kids = kids_a & kids_b
    assert not shared_kids, f"two pools publish {len(shared_kids)} kid(s) in common"
    moduli_a = {k["n"] for k in pools["a"]["keys"]}
    shared_moduli = moduli_a & {k["n"] for k in pools["b"]["keys"]}
    assert not shared_moduli, f"two pools publish {len(shared_moduli)} RSA modulus/moduli in common"

    # The negative: a verifier trusting pool b's JWKS accepts no token pool a issued.
    for i, token in enumerate(pools["a"]["tokens"]):
        _, _, signing_input, signature = _jwt(token)
        accepted = [k["kid"] for k in pools["b"]["keys"]
                    if _rs256_verifies(k, signing_input, signature)]
        assert accepted == [], (
            f"pool a's ID token from client {i} verifies under {len(accepted)} of pool b's keys"
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
