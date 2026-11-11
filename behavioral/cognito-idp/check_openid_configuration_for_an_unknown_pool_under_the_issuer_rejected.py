"""openid-configuration-for-an-unknown-pool-under-the-issuer-rejected."""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "openid-configuration-for-an-unknown-pool-under-the-issuer-rejected"
GROUP = "oidc-discovery"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_GONE = "ResourceNotFoundException"
_DOCS = ("/.well-known/openid-configuration", "/.well-known/jwks.json")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Beside a pool whose discovery and JWKS documents serve at its token issuer, the same paths
    for a pool id that does not exist answer 404 JSON naming that pool as nonexistent."""
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
    id_token = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["IdToken"]
    iss = _claims(id_token).get("iss")
    assert isinstance(iss, str) and iss.endswith(f"/{pool_id}"), (
        f"expected the ID token's iss to end in the pool id, got iss={iss!r}"
    )

    # Positive control: both documents serve for the pool that exists.
    status, body = _get(ctx, f"{iss}{_DOCS[0]}")
    assert status == 200 and json.loads(body).get("issuer") == iss, (
        f"expected the pool's discovery document to serve its issuer, got {status} {body[:200]!r}"
    )
    status, body = _get(ctx, f"{iss}{_DOCS[1]}")
    assert status == 200 and isinstance(json.loads(body).get("keys"), list), (
        f"expected the pool's JWKS document to serve a keys array, got {status} {body[:200]!r}"
    )

    # A well-formed pool id in this region that no pool carries.
    unknown = f"{ctx.region}_{uuid.uuid4().hex[:9]}"
    assert unknown != pool_id, "the generated pool id collides with the created pool"
    base = iss[: -len(pool_id)] + unknown
    for path in _DOCS:
        status, body = _get(ctx, f"{base}{path}")
        assert status == 404, (
            f"expected 404 for {path} of a nonexistent pool, got {status} {body[:200]!r}"
        )
        try:
            doc = json.loads(body)
        except ValueError:
            doc = body[:200]
        assert doc == {"message": f"User pool {unknown} does not exist."}, (
            f"expected {path} of a nonexistent pool to name it as nonexistent, got {doc!r}"
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


def _get(ctx, url: str) -> tuple[int, str]:
    """(status, body) of an unsigned GET of a published URL on the target; an HTTP error is data."""
    target, headers = ctx.endpoint_route(url)
    request = urllib.request.Request(target, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30, context=_tls(ctx)) as resp:  # noqa: S310
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise AssertionError(f"DATAPLANE_UNIMPLEMENTED: nothing answered at {url}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
