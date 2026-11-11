"""openid-configuration-of-a-pool-without-a-domain-names-the-token-issuer-and-endpoints-under-it."""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "openid-configuration-of-a-pool-without-a-domain-names-the-token-issuer-and-endpoints-under-it"
GROUP = "oidc-discovery"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_GONE = "ResourceNotFoundException"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """For a user pool with no domain, the unsigned {iss}/.well-known/openid-configuration of its
    ID token's iss names that issuer, RS256, and jwks_uri and the authorize/token/userInfo/revoke/
    logout endpoints, all under the issuer itself.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
    Reference: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig"""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id), _GONE))
    # Precondition: the hosted endpoints sit under the issuer only while the pool has no domain.
    described = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert not described.get("Domain") and not described.get("CustomDomain"), (
        f"expected the new pool to have no domain, got Domain={described.get('Domain')!r} "
        f"CustomDomain={described.get('CustomDomain')!r}"
    )
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
    iss = _claims(tokens["IdToken"]).get("iss")
    assert isinstance(iss, str) and iss.endswith(f"/{pool_id}"), (
        f"expected the ID token's iss to end in the pool id, got iss={iss!r}"
    )
    access_iss = _claims(tokens["AccessToken"]).get("iss")
    assert access_iss == iss, (
        f"expected the access token's iss to equal the ID token's {iss!r}, got {access_iss!r}"
    )

    status, content_type, doc = _get_json(ctx, f"{iss}/.well-known/openid-configuration")
    assert (status, content_type) == (200, "application/json"), (
        f"expected 200 application/json for the discovery document, got {status} {content_type!r}"
    )
    expected = {
        "issuer": iss,
        "jwks_uri": f"{iss}/.well-known/jwks.json",
        "authorization_endpoint": f"{iss}/authorize",
        "token_endpoint": f"{iss}/token",
        "userinfo_endpoint": f"{iss}/userInfo",
        "revocation_endpoint": f"{iss}/revoke",
        "end_session_endpoint": f"{iss}/logout",
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["code", "token"],
        "subject_types_supported": ["public"],
        "scopes_supported": ["openid", "email", "phone", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }
    for field, want in expected.items():
        assert doc.get(field) == want, (
            f"discovery field {field}: expected {want!r}, got {doc.get(field)!r}"
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


def _claims(token: str) -> dict:
    """The decoded payload of a compact JWS."""
    parts = token.split(".")
    assert len(parts) == 3, f"not a compact JWS (header.payload.signature): {token[:24]!r}..."
    return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))


def _tls(ctx):
    """The TLS context ctx.http_verify asks for: a CA bundle path, unverified, or the default."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _get_json(ctx, url: str) -> tuple[int, str, dict]:
    """(status, media type, JSON body) of an unsigned GET of a published URL on the target."""
    target, headers = ctx.endpoint_route(url)
    request = urllib.request.Request(target, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30, context=_tls(ctx)) as resp:  # noqa: S310
            body = resp.read().decode()
            media = (resp.headers.get("Content-Type") or "").split(";")[0].strip()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: {url} answered HTTP {exc.code}: {exc.read()[:200]!r}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise AssertionError(f"DATAPLANE_UNIMPLEMENTED: nothing answered at {url}: {exc}") from exc
    try:
        return status, media, json.loads(body)
    except ValueError as exc:
        raise AssertionError(f"{url} answered a non-JSON body: {body[:200]!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
