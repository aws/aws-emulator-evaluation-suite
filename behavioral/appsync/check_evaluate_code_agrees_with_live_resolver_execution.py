"""evaluate-code-agrees-with-live-resolver-execution."""
from __future__ import annotations

# EvaluateCode(function="response") returns the handler's return value JSON-encoded, so a
# string result is quoted. runtime.earlyReturn() would bypass both the data source and response(),
# so request() uses a plain ``return { payload }``, which AppSync unwraps into ctx.result.

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "evaluate-code-agrees-with-live-resolver-execution"
GROUP = "server-side"
SERVICES = ["appsync"]

SDL = """schema { query: Query }
type Query {
    transform(msg: String!): String
}
"""

# A non-trivial pure function of the argument, so echoing the input or a constant both fail.
# The same source is handed to EvaluateCode and installed as the live resolver.
JS_TRANSFORM = """export function request(ctx) {
  return { payload: ctx.args.msg };
}

export function response(ctx) {
  const msg = ctx.result;
  const upper = msg.toUpperCase();
  const reversed = upper.split('').reverse().join('');
  return reversed + ':' + msg.length;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


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


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=json.dumps(payload).encode(), method="POST",
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


def _expected(msg):
    """Python transcription of JS_TRANSFORM's response(), so both paths cannot agree on a wrong value."""
    return msg.upper()[::-1] + ":" + str(len(msg))


def _graphql_api(ctx, svc, sdl):
    """Create an API_KEY GraphQL API + an ACTIVE schema + a key -> (api_id, uri, key)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
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
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav evalcode key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))
    return api_id, uri, key



@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """EvaluateCode and the live resolver run the same APPSYNC_JS code to the same answer, which
    matches the transform recomputed locally; two different inputs give two different answers.
    """
    svc = ctx.client("appsync")
    api_id, url, key = _graphql_api(ctx, svc, SDL)

    ds_name = _alnum(ctx, "ds")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="transform", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_TRANSFORM,
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="transform")
    )

    installed = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="transform")["resolver"]
    assert installed.get("code") == JS_TRANSFORM, (
        f"the resolver AppSync stored is not the source the sandbox will be handed, so the "
        f"agreement below would be meaningless; stored {len(installed.get('code') or '')} chars "
        f"vs {len(JS_TRANSFORM)} declared"
    )

    markers = [ctx.unique_name("evalcode-"), ctx.unique_name("second-")]
    live_answers, sandbox_answers = [], []

    for marker in markers:
        want = _expected(marker)

        sandboxed = svc.evaluate_code(
            runtime=APPSYNC_JS,
            code=JS_TRANSFORM,
            function="response",
            # ``result`` mirrors the live path: AppSync unwraps request()'s ``payload`` into ctx.result.
            context=json.dumps({"arguments": {"msg": marker}, "result": marker}),
        )
        assert not sandboxed.get("error"), (
            f"EvaluateCode reported an error for the response handler: {sandboxed.get('error')!r}"
        )
        raw = sandboxed.get("evaluationResult")
        assert raw is not None, (
            f"EvaluateCode returned no evaluationResult for {marker!r}: {sandboxed!r}"
        )
        sandbox_value = json.loads(raw)
        sandbox_answers.append(sandbox_value)

        _status, body = _poll_until(
            lambda _m=marker: _post_json(
                ctx, url, {"x-api-key": key},
                {"query": "query T($m: String!) { transform(msg: $m) }",
                 "variables": {"m": _m}},
            ),
            lambda res: res[0] == 200 and (res[1].get("data") or {}).get("transform") is not None,
            timeout_s=180.0, interval_s=5.0,
            description=f"the live endpoint to resolve transform({marker!r})",
        )
        assert not body.get("errors"), f"the live leg returned errors for {marker!r}: {body!r}"
        live_value = body["data"]["transform"]
        live_answers.append(live_value)

        assert live_value == want, (
            f"the LIVE engine got the transform wrong for {marker!r}: expected {want!r}, got "
            f"{live_value!r}"
        )
        assert sandbox_value == want, (
            f"the EvaluateCode SANDBOX got the transform wrong for {marker!r}: expected {want!r}, "
            f"got {sandbox_value!r}"
        )
        assert sandbox_value == live_value, (
            f"the sandbox and the live query engine disagree for {marker!r}: sandbox "
            f"{sandbox_value!r} vs live {live_value!r}"
        )

    # Two different inputs must give two different answers on both paths.
    assert live_answers[0] != live_answers[1], (
        f"both markers produced the identical live answer {live_answers[0]!r}, so the transform "
        f"is not a function of its input on the live path"
    )
    assert sandbox_answers[0] != sandbox_answers[1], (
        f"both markers produced the identical sandbox answer {sandbox_answers[0]!r}, so "
        f"EvaluateCode is not evaluating the code it was given"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
