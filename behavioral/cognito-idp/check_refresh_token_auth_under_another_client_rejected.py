"""refresh-token-auth-under-another-client-rejected."""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from behavioral_harness import tags

CHECK = "refresh-token-auth-under-another-client-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """REFRESH_TOKEN_AUTH refuses a refresh token under another client of the same pool with
    NotAuthorizedException and its exact message; the issuing client still mints a verifiable
    ID token from it."""
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
    signed_in = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]
    other_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(FLOWS), GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=other_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )
    # The other client is fully usable for this user: its own sign-in succeeds.
    other_claims = _jwt(c.initiate_auth(
        ClientId=other_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["IdToken"])[1]
    assert other_claims.get("aud") == other_id, (
        f"the other client's own sign-in must mint an ID token for it, got aud "
        f"{other_claims.get('aud')!r}"
    )

    code, message = _error(lambda: c.initiate_auth(
        ClientId=other_id, AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": signed_in["RefreshToken"]},
    ))
    assert (code, message) == ("NotAuthorizedException", "Refresh Token has different Client"), (
        f"expected NotAuthorizedException 'Refresh Token has different Client', got {(code, message)!r}"
    )

    # Positive control: the refused token still refreshes under the client that issued it.
    refreshed = c.initiate_auth(
        ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": signed_in["RefreshToken"]},
    )["AuthenticationResult"]
    header, claims, signing_input, signature = _jwt(refreshed["IdToken"])
    assert claims.get("aud") == client_id, (
        f"the issuing client's refresh must mint an ID token for it, got aud {claims.get('aud')!r}"
    )
    jwks = _get_json(ctx, f"{claims['iss']}/.well-known/jwks.json")
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    assert jwk is not None and _rs256_verifies(jwk, signing_input, signature), (
        "the issuing client's refreshed ID token must verify under its issuer's JWKS"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {sorted(result)!r}")


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
