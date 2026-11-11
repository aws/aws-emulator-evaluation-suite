"""graphql-pipeline-stash-prev-result-and-before-return."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "graphql-pipeline-stash-prev-result-and-before-return"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query mutation: Mutation }
type Query {
    ping: String
}
type Mutation {
    compose(tenant: String!): String
}
"""

def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """A unique name with NO hyphens -- AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*``."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST a JSON body with stdlib urllib -> (status, parsed_body, headers).

    A transport failure returns status None so callers can keep polling a warming endpoint.
    """
    data = json.dumps(payload).encode()
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=data, method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw, hdrs = resp.status, resp.read().decode(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        status, raw, hdrs = exc.code, exc.read().decode(errors="replace"), dict(exc.headers)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}, {}
    try:
        return status, (json.loads(raw) if raw else {}), hdrs
    except ValueError:
        return status, {"raw": raw}, hdrs


def _gql(ctx, url, api_key, query, variables=None):
    payload = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    return _post_json(ctx, url, {"x-api-key": api_key}, payload)


def _graphql_endpoint(ctx, svc, sdl, **api_kwargs):
    """Create an API_KEY GraphQL API + active schema + api key -> (api_id, graphql_url, api_key)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType=api_kwargs.pop("authenticationType", "API_KEY"),
        **api_kwargs,
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    url = (api.get("uris") or {}).get("GRAPHQL")
    if not url:
        raise AssertionError("GraphQL API exposed no GRAPHQL endpoint URI")
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=120, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal state",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: status={status['status']!r} details={status.get('details')!r}"
    )
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav graphql key")["apiKey"]["id"]
    return api_id, url, key


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A PIPELINE resolver chains $ctx.prev.result, carries $ctx.stash, and #return short-circuits it.

    Over a mutation, #return in the before-template skips both functions and the after-template;
    restoring the template restores the full pipeline result."""
    svc = ctx.client("appsync")
    api_id, url, api_key = _graphql_endpoint(ctx, svc, SDL)

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))

    fn_one = svc.create_function(
        apiId=api_id, name=_alnum(ctx, "fn"), dataSourceName=ds["name"],
        functionVersion="2018-05-29",
        requestMappingTemplate=(
            "#set($ctx.stash.tenant = $ctx.args.tenant)\n"
            '{"version":"2018-05-29","payload":{}}'
        ),
        responseMappingTemplate='$util.toJson("one")',
    )["functionConfiguration"]
    ctx.on_cleanup(lambda _f=fn_one["functionId"]: svc.delete_function(apiId=api_id, functionId=_f))

    fn_two = svc.create_function(
        apiId=api_id, name=_alnum(ctx, "fn"), dataSourceName=ds["name"],
        functionVersion="2018-05-29",
        requestMappingTemplate='{"version":"2018-05-29","payload":{}}',
        responseMappingTemplate='$util.toJson("fn2-saw-${ctx.prev.result}")',
    )["functionConfiguration"]
    ctx.on_cleanup(lambda _f=fn_two["functionId"]: svc.delete_function(apiId=api_id, functionId=_f))

    pipeline = {"functions": [fn_one["functionId"], fn_two["functionId"]]}
    after_template = '$util.toJson("${ctx.prev.result}|${ctx.stash.tenant}")'
    svc.create_resolver(
        apiId=api_id, typeName="Mutation", fieldName="compose",
        kind="PIPELINE", pipelineConfig=pipeline,
        requestMappingTemplate="{}",
        responseMappingTemplate=after_template,
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Mutation", fieldName="compose"))

    mutation = "mutation M($t: String!) { compose(tenant: $t) }"

    def _compose():
        status, body, _h = _gql(ctx, url, api_key, mutation, {"t": "acme"})
        if status != 200 or not isinstance(body.get("data"), dict):
            return None
        assert not body.get("errors"), f"unexpected GraphQL errors: {body.get('errors')!r}"
        return body["data"].get("compose")

    # 1. prev.result chaining + stash survival, over a mutation.
    composed = _poll_until(
        _compose, lambda v: v is not None, timeout_s=180, interval_s=5.0,
        description="the pipeline mutation to resolve on the live endpoint",
    )
    assert composed == "fn2-saw-one|acme", (
        f"expected function 2 to observe function 1's result via $ctx.prev.result and the "
        f"resolver's after-template to observe $ctx.stash.tenant, got {composed!r}"
    )

    # 2. #return in the resolver's BEFORE template short-circuits the whole pipeline.
    svc.update_resolver(
        apiId=api_id, typeName="Mutation", fieldName="compose",
        kind="PIPELINE", pipelineConfig=pipeline,
        requestMappingTemplate='#return("short-circuited")',
        responseMappingTemplate=after_template,
    )
    short = _poll_until(
        _compose, lambda v: v == "short-circuited", timeout_s=180, interval_s=5.0,
        description="#return in the before-template to short-circuit the pipeline",
    )
    assert short == "short-circuited", (
        f"expected #return in the resolver's before-template to return its value directly, got {short!r}"
    )
    assert "fn2-saw" not in short and "acme" not in short, (
        f"expected #return to skip BOTH pipeline functions and the after-template, but the "
        f"result still carries their output: {short!r}"
    )

    # 3. Control: restoring the before-template restores the pipeline, so step 2 proved the
    #    short-circuit, not a broken resolver.
    svc.update_resolver(
        apiId=api_id, typeName="Mutation", fieldName="compose",
        kind="PIPELINE", pipelineConfig=pipeline,
        requestMappingTemplate="{}",
        responseMappingTemplate=after_template,
    )
    restored = _poll_until(
        _compose, lambda v: v == "fn2-saw-one|acme", timeout_s=180, interval_s=5.0,
        description="the pipeline to resume after the before-template is restored",
    )
    assert restored == "fn2-saw-one|acme", (
        f"expected the pipeline to resume once #return was removed, got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
