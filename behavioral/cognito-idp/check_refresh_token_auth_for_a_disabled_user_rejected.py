"""refresh-token-auth-for-a-disabled-user-rejected."""
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

CHECK = "refresh-token-auth-for-a-disabled-user-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """AdminDisableUser makes REFRESH_TOKEN_AUTH and sign-in fail NotAuthorizedException with exact
    messages and revokes the refresh token for good, while the ID token issued before stays
    RS256-verifiable under the JWKS."""
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
    header, claims, signing_input, signature = _jwt(signed_in["IdToken"])
    assert claims.get("aud") == client_id, f"expected aud {client_id!r}, got {claims.get('aud')!r}"

    c.admin_disable_user(UserPoolId=pool_id, Username=username)
    enabled = c.admin_get_user(UserPoolId=pool_id, Username=username)["Enabled"]
    assert enabled is False, f"AdminGetUser must report the user disabled, got Enabled={enabled!r}"

    refresh = _error(lambda: c.initiate_auth(
        ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": signed_in["RefreshToken"]},
    ))
    assert refresh == ("NotAuthorizedException", "User is disabled."), (
        f"expected NotAuthorizedException 'User is disabled.' refreshing a disabled user, got {refresh!r}"
    )
    sign_in = _error(lambda: c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    ))
    assert sign_in == ("NotAuthorizedException", "User is disabled."), (
        f"expected NotAuthorizedException 'User is disabled.' signing in a disabled user, got {sign_in!r}"
    )

    # The ID token issued before the disable is a signed statement, not a session: it still
    # verifies under the issuer's JWKS, so expiry is what bounds it.
    jwks = _get_json(ctx, f"{claims['iss']}/.well-known/jwks.json")
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    assert jwk is not None and _rs256_verifies(jwk, signing_input, signature), (
        "the ID token issued before the disable must still verify under its issuer's JWKS"
    )

    # Positive control: re-enabled, the same user signs in and mints a verifiable ID token again.
    c.admin_enable_user(UserPoolId=pool_id, Username=username)
    again = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]
    header2, claims2, signing_input2, signature2 = _jwt(again["IdToken"])
    assert claims2.get("sub") == claims.get("sub"), "the re-enabled user's ID token must keep its sub"
    jwk2 = next((k for k in jwks.get("keys", []) if k.get("kid") == header2.get("kid")), None)
    assert jwk2 is not None and _rs256_verifies(jwk2, signing_input2, signature2), (
        "the re-enabled user's new ID token must verify under its issuer's JWKS"
    )
    # Disabling revoked the earlier refresh token for good: re-enabling does not revive it.
    revived = _error(lambda: c.initiate_auth(
        ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": signed_in["RefreshToken"]},
    ))
    assert revived == ("NotAuthorizedException", "Refresh Token has been revoked"), (
        f"expected NotAuthorizedException 'Refresh Token has been revoked' for the pre-disable "
        f"refresh token after re-enabling, got {revived!r}"
    )
    c.initiate_auth(
        ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": again["RefreshToken"]},
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
