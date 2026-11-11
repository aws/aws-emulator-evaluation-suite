"""deep-appsync-2-appsync-authz-oidc-iat-ttl-rejects-aged-token."""
from __future__ import annotations

import base64
import json
import secrets
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deep-appsync-2-appsync-authz-oidc-iat-ttl-rejects-aged-token"
GROUP = "authorization-denied"
SERVICES = ["appsync", "cognito-idp"]

IAT_TTL_MS = 8_000
# The aged leg waits until the token is this old -- comfortably past iatTTL even allowing for
# second-granularity ``iat`` and a few seconds of clock skew, and far inside the token's 1h exp.
AGED_S = 18

SDL = """schema { query: Query }
type Query {
    ping: String
}
"""

JS_PONG = """import { runtime } from '@aws-appsync/utils';

export function request(ctx) {
  runtime.earlyReturn('pong');
  return {};
}

export function response(ctx) {
  return ctx.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


def _tags_kv():
    return {"sim2real": CHECK, "sim2real:managed": "true"}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0, description="condition",
                ctx=None):
    """Poll probe() until predicate(result) is truthy and return it; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(url, headers, payload, timeout_s=40):
    """POST JSON and return (status, parsed_body); 4xx/5xx statuses are returned, not raised."""
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _jwt_claims(token):
    """Decode (NOT verify) a JWT's payload -- only to read ``iat``, which the issuer minted."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _user_pool(ctx):
    """A user pool, an admin-auth app client and one confirmed user; returns a token minter."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-appsync-authz-"),
        UserPoolTags=_tags_kv(),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName="sim2real-behav-appsync-authz",
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    username = ctx.unique_name("user-")
    password = "Aa1!" + secrets.token_urlsafe(16)
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    def mint():
        return idp.admin_initiate_auth(
            UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]

    issuer = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool_id}"
    return issuer, client_id, mint


def _graphql_api(ctx, svc, sdl, **api_kwargs):
    """Create a GraphQL API + ACTIVE schema + a NONE-backed ``ping`` resolver; return
    (api_id, graphql_uri)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"), tags=_tags_kv(), **api_kwargs,
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=180.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: got {status['status']!r} "
        f"details={status.get('details')!r}"
    )
    ds_name = _alnum(ctx, "none")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="ping", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_PONG,
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping"))
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    return api_id, uri


# timing:real-time — ttl: 8 s https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "concern:e2e", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An OPENID_CONNECT API with iatTTL rejects a token whose iat is older than iatTTL with 401
    UnauthorizedException, while a twin API without iatTTL accepts the same unexpired token.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
    """
    svc = ctx.client("appsync")
    issuer, client_id, mint = _user_pool(ctx)

    ttl_id, ttl_url = _graphql_api(
        ctx, svc, SDL, authenticationType="OPENID_CONNECT",
        openIDConnectConfig={"issuer": issuer, "clientId": client_id, "iatTTL": IAT_TTL_MS},
    )
    stored = svc.get_graphql_api(apiId=ttl_id)["graphqlApi"].get("openIDConnectConfig") or {}
    assert stored.get("iatTTL") == IAT_TTL_MS, (
        f"the api did not retain iatTTL={IAT_TTL_MS}: {stored!r}"
    )
    _plain_id, plain_url = _graphql_api(
        ctx, svc, SDL, authenticationType="OPENID_CONNECT",
        openIDConnectConfig={"issuer": issuer, "clientId": client_id},
    )

    document = {"query": "query P { ping }"}

    def _ask(url, token):
        target, route = ctx.endpoint_route(url)
        return _post_json(target, {"Authorization": token, **route}, document)

    def _accepted(res):
        return res[0] == 200 and res[1] == {"data": {"ping": "pong"}}

    # Warm-up absorbs JWKS fetch and API readiness; each attempt mints a new token so none is aged.
    for label, url in (("ttl", ttl_url), ("plain", plain_url)):
        _poll_until(
            lambda u=url: _ask(u, mint()), _accepted,
            timeout_s=_budget_s(ctx, 240.0), interval_s=1.0,
            description=f"the {label} OIDC api to accept a freshly minted token", ctx=ctx,
        )

    # Fresh token: iatTTL admits it.
    token = mint()
    iat = int(_jwt_claims(token)["iat"])
    exp = int(_jwt_claims(token)["exp"])
    # Precondition on the check's own clock, read BEFORE the request leaves: the FRESH leg only
    # means something if the token is sent while its age is inside iatTTL.
    sent_age = time.time() - iat
    # elapsed-bound: the token's age must be inside iatTTL, the bound the API itself enforces.
    assert sent_age < IAT_TTL_MS / 1000.0, (
        f"the FRESH token was {sent_age:.1f}s old before it was sent -- not inside iatTTL, so the "
        f"leg would prove nothing"
    )
    fresh = _ask(ttl_url, token)
    assert _accepted(fresh), (
        f"a token sent {sent_age:.1f}s after iat must be accepted under iatTTL={IAT_TTL_MS}ms, "
        f"got {fresh!r}"
    )

    # Wait on the token's own clock until it is AGED_S old; there is nothing else to poll.
    remaining = iat + AGED_S - time.time()
    if remaining > 0:
        time.sleep(remaining)
    aged_age = time.time() - iat
    assert aged_age >= AGED_S and time.time() < exp, (
        f"the aged leg must run past {AGED_S}s and before exp: age {aged_age:.1f}s, exp in "
        f"{exp - time.time():.0f}s"
    )
    status, body = _ask(ttl_url, token)
    assert status == 401, (
        f"a token {aged_age:.1f}s past iat must be rejected under iatTTL={IAT_TTL_MS}ms with 401, "
        f"got {status!r} {body!r}"
    )
    assert "data" not in body or body.get("data") is None, (
        f"a rejected request must carry no data: {body!r}"
    )
    errors = body.get("errors") or []
    assert errors == [{"errorType": "UnauthorizedException", "message": "Unauthorized"}], (
        f"the aged-token rejection must be exactly one UnauthorizedException with message "
        f"'Unauthorized', got {errors!r}"
    )

    plain = _ask(plain_url, token)
    assert _accepted(plain), (
        f"the SAME aged token must still be accepted by the twin api with no iatTTL (it is "
        f"{aged_age:.1f}s old and unexpired), got {plain!r}"
    )

    # A newly minted token is admitted again.
    repaired = _ask(ttl_url, mint())
    assert _accepted(repaired), (
        f"a newly minted token must be accepted by the iatTTL api again, got {repaired!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
