"""auth-type-switch-to-iam-denies-api-key-and-admits-sigv4."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from behavioral_harness import tags

CHECK = "auth-type-switch-to-iam-denies-api-key-and-admits-sigv4"
GROUP = "overly-permissive"
SERVICES = ["appsync"]

SDL = """schema { query: Query }
type Query {
    echo(msg: String!): String
}
"""

# A NONE data source performs no invocation, so runtime.earlyReturn() produces the result.
JS_ECHO = (
    "import { runtime } from '@aws-appsync/utils';\n"
    "export function request(ctx) {\n  runtime.earlyReturn(ctx.args.msg);\n  return {};\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}

AUTH_FLIP_TIMEOUT_S = 180.0


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_raw(ctx, url, headers, body, timeout_s=30):
    """POST already-serialised bytes -> (status, parsed_body). A 4xx/5xx is a RESULT.

    Takes bytes rather than a dict because the SigV4 leg must send the byte-identical body it
    signed.
    """
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=body, method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
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


def _sigv4_headers(ctx, url, body):
    """SigV4-sign a raw HTTPS POST for the ``appsync`` signing name.

    Signs with the keys ``ctx.subprocess_env()`` exposes, never the ambient credential chain.
    """
    env = ctx.subprocess_env()
    akid = env.get("AWS_ACCESS_KEY_ID")
    assert akid, (
        "no signing credentials are reachable through ctx.subprocess_env(); the signed control "
        "leg cannot be built, and falling back to the ambient chain would sign as a DIFFERENT "
        "account"
    )
    creds = Credentials(akid, env["AWS_SECRET_ACCESS_KEY"], env.get("AWS_SESSION_TOKEN"))
    request = AWSRequest(
        method="POST", url=url, data=body, headers={"Content-Type": "application/json"}
    )
    SigV4Auth(creds, "appsync", ctx.region).add_auth(request)
    return dict(request.headers)


def _graphql_api(ctx, svc, sdl, **api_kwargs):
    """Create a GraphQL API + an ACTIVE schema; return (api_id, name, graphql_uri)."""
    name = ctx.unique_name("sim2real-behav-appsync-api-")
    api = svc.create_graphql_api(
        name=name,
        authenticationType=api_kwargs.pop("authenticationType", "API_KEY"),
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
        **api_kwargs,
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
        f"schema creation did not succeed: expected SUCCESS/ACTIVE, got {status['status']!r} "
        f"details={status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    return api_id, name, uri


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Switching authenticationType to AWS_IAM makes the same api-key request 401
    UnauthorizedException while the key still exists and SigV4 is served; restoring API_KEY
    re-admits the key and refuses SigV4.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
    """
    svc = ctx.client("appsync")
    api_id, api_name, url = _graphql_api(ctx, svc, SDL)

    ds_name = _alnum(ctx, "ds")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="echo",
        kind="UNIT", dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_ECHO,
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="echo"))

    key = svc.create_api_key(apiId=api_id, description="sim2real-behav auth-flip key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))

    marker = ctx.unique_name("flip-")
    body = json.dumps({
        "query": "query Echo($m: String!) { echo(msg: $m) }",
        "variables": {"m": marker},
    }).encode()

    def _with_key():
        return _post_raw(ctx, url, {"x-api-key": key}, body)

    def _with_sigv4():
        return _post_raw(ctx, url, _sigv4_headers(ctx, url, body), body)

    # ---- beat 1: positive control on API_KEY -------------------------------------------------
    # A freshly created resolver can answer 200 with a null field for a few seconds, so the poll
    # waits for the VALUE, not merely for a body.
    _status, ok = _poll_until(
        _with_key,
        lambda res: res[0] == 200 and ((res[1].get("data") or {}).get("echo") == marker),
        timeout_s=AUTH_FLIP_TIMEOUT_S, interval_s=5.0,
        description="the API_KEY control leg to resolve the marker on the live endpoint",
    )
    assert not ok.get("errors"), f"the API_KEY control leg returned errors: {ok!r}"

    # ---- beat 2: break exactly one thing ----------------------------------------------------
    flipped = svc.update_graphql_api(
        apiId=api_id, name=api_name, authenticationType="AWS_IAM"
    )["graphqlApi"]
    assert flipped["authenticationType"] == "AWS_IAM", (
        f"UpdateGraphqlApi did not report the new mode: expected AWS_IAM, got "
        f"{flipped['authenticationType']!r}"
    )

    # ---- beat 3: the specific refusal, on the identical request ------------------------------
    denied_status, denied = _poll_until(
        _with_key,
        lambda res: res[0] == 401,
        timeout_s=AUTH_FLIP_TIMEOUT_S, interval_s=5.0,
        description="the auth-mode flip to reach the data plane and refuse the api key",
    )
    assert denied_status == 401, (
        f"expected HTTP 401 for an api key against an AWS_IAM-only api, got {denied_status!r} "
        f"body={denied!r}"
    )
    denied_errors = denied.get("errors") or []
    assert len(denied_errors) == 1, (
        f"expected exactly one error on the refusal, got {len(denied_errors)}: {denied_errors!r}"
    )
    assert denied_errors[0].get("errorType") == "UnauthorizedException", (
        f"expected errorType UnauthorizedException on the refusal, got "
        f"{denied_errors[0].get('errorType')!r} in {denied_errors[0]!r}"
    )
    assert "data" not in denied, (
        f"a refused request must carry no GraphQL data envelope at all; got keys "
        f"{sorted(denied)!r} in {denied!r}"
    )

    # ---- beat 4: effect absent, via reads through DIFFERENT operations -----------------------
    got = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert got["authenticationType"] == "AWS_IAM", (
        f"GetGraphqlApi disagrees with the flip: expected AWS_IAM, got "
        f"{got['authenticationType']!r}"
    )
    live_keys = [k["id"] for k in svc.list_api_keys(apiId=api_id).get("apiKeys", [])]
    assert key in live_keys, (
        f"the api key vanished across the auth-mode flip, so the 401 above proves nothing about "
        f"the auth MODE; expected {key!r} in ListApiKeys, got {live_keys!r}"
    )

    # ---- beat 5: the new mode is genuinely served (kills 'refuses everything') ---------------
    signed_status, signed = _poll_until(
        _with_sigv4,
        lambda res: res[0] == 200 and ((res[1].get("data") or {}).get("echo") == marker),
        timeout_s=AUTH_FLIP_TIMEOUT_S, interval_s=5.0,
        description="a SigV4-signed copy of the SAME body to be served under AWS_IAM",
    )
    assert signed_status == 200 and not signed.get("errors"), (
        f"the SigV4 leg did not succeed under AWS_IAM: {signed_status!r} {signed!r}"
    )
    assert signed["data"]["echo"] == marker, (
        f"the SigV4 leg resolved the wrong value: expected {marker!r}, got {signed['data']!r}"
    )

    # ---- beat 6: restore, and the identical api-key call works again -------------------------
    svc.update_graphql_api(apiId=api_id, name=api_name, authenticationType="API_KEY")
    restored_status, restored = _poll_until(
        _with_key,
        lambda res: res[0] == 200 and ((res[1].get("data") or {}).get("echo") == marker),
        timeout_s=AUTH_FLIP_TIMEOUT_S, interval_s=5.0,
        description="restoring API_KEY to re-admit the identical api-key request",
    )
    assert restored_status == 200 and not restored.get("errors"), (
        f"restoring API_KEY did not re-admit the identical request: {restored_status!r} "
        f"{restored!r}"
    )

    # The inverse of beat 5: AWS_IAM is no longer an accepted mode, so the request that just
    # succeeded must now be refused. Single-shot on purpose -- the api-key poll above already
    # proved the restored config is live on the data plane, so a retry here would only mask a
    # target that keeps honouring a withdrawn auth mode.
    inv_status, inv = _with_sigv4()
    assert inv_status == 401, (
        f"AWS_IAM was removed from the api, so the SigV4 request that succeeded in beat 5 must "
        f"now be refused; got {inv_status!r} body={inv!r}"
    )
    inv_errors = inv.get("errors") or []
    assert inv_errors and inv_errors[0].get("errorType") == "UnauthorizedException", (
        f"expected errorType UnauthorizedException for a withdrawn auth mode, got {inv_errors!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
