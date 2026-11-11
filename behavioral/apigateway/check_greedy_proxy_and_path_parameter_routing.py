"""greedy-proxy-and-path-parameter-routing."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "greedy-proxy-and-path-parameter-routing"
GROUP = 'resources'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "greedy-proxy-routing"},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _resource(ctx, ag, api_id, parent_id, path_part):
    """A child resource (registered for teardown) under parent_id."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=parent_id, pathPart=path_part
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id))
    return resource_id

def _mock_method(ag, api_id, resource_id, http_method, response_template,
                 request_parameters=None):
    """A fully wired MOCK method: 200 request template + 200 integration response."""
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
        authorizationType="NONE", requestParameters=request_parameters or {},
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200",
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200",
        selectionPattern="", responseTemplates={"application/json": response_template},
    )

def _http(method, url, body=None, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310 - fixed http(s) scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())

def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the
    emulator's /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"

def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=120.0, interval_s=3.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds.

    A REST API deployment becomes servable on its stage asynchronously, so the first
    touch of a freshly (re-)deployed stage polls to a condition with a bounded
    deadline rather than sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; "
                f"last=({status}, {text!r})"
            )
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """At a deployed stage a concrete resource wins over a sibling greedy {proxy+}, the greedy
    resource binds the whole multi-segment remainder to the proxy path parameter, and ANY
    answers every HTTP method; $context.resourcePath names the route that matched."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)

    items_id = _resource(ctx, ag, api_id, root_id, "items")
    item_by_id = _resource(ctx, ag, api_id, items_id, "{id}")
    _mock_method(
        ag, api_id, item_by_id, "GET",
        '{"route":"items-id","id":"$input.params(\'id\')",'
        '"resourcePath":"$context.resourcePath","method":"$context.httpMethod"}',
        request_parameters={"method.request.path.id": True},
    )

    greedy_id = _resource(ctx, ag, api_id, root_id, "{proxy+}")
    _mock_method(
        ag, api_id, greedy_id, "ANY",
        '{"route":"greedy","proxy":"$input.params(\'proxy\')",'
        '"resourcePath":"$context.resourcePath","method":"$context.httpMethod"}',
        request_parameters={"method.request.path.proxy": True},
    )

    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_unique_token()}"
    ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment_id,
        tags={"sim2real": "greedy-proxy-routing"},
    )
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))

    # The concrete /items/{id} route must win over the sibling greedy route.
    specific_url = _apigw_url(ctx, api_id, stage, "/items/42")
    _, _, text = _poll_http(
        specific_url, lambda s, h, t: s == 200,
        description=f"GET {specific_url} to be served by the deployed stage",
    )
    specific = json.loads(text)
    assert specific.get("route") == "items-id", (
        f"expected the concrete resource /items/{{id}} to win over the sibling "
        f"greedy {{proxy+}} resource for GET /items/42, got {specific!r}"
    )
    assert specific.get("resourcePath") == "/items/{id}", (
        f"expected $context.resourcePath='/items/{{id}}', got "
        f"{specific.get('resourcePath')!r}"
    )
    assert specific.get("id") == "42", (
        f"expected the path parameter id to bind to '42', got {specific.get('id')!r}"
    )

    # A path no concrete resource matches falls to {proxy+}, which captures the
    # WHOLE remainder (two segments), not just the first.
    greedy_url = _apigw_url(ctx, api_id, stage, "/elsewhere/deep")
    status, _, text = _http("GET", greedy_url)
    assert status == 200, f"expected 200 from the greedy route, got {status}: {text}"
    greedy = json.loads(text)
    assert greedy.get("route") == "greedy", (
        f"expected GET /elsewhere/deep to be served by {{proxy+}}, got {greedy!r}"
    )
    assert greedy.get("resourcePath") == "/{proxy+}", (
        f"expected $context.resourcePath='/{{proxy+}}', got {greedy.get('resourcePath')!r}"
    )
    assert greedy.get("proxy") == "elsewhere/deep", (
        f"expected the greedy path parameter to capture the full remaining path "
        f"'elsewhere/deep', got {greedy.get('proxy')!r}"
    )

    # ANY must answer a method other than GET on the same resource.
    status, _, text = _http("POST", greedy_url, body=b"{}",
                            headers={"Content-Type": "application/json"})
    assert status == 200, f"expected ANY to answer POST, got {status}: {text}"
    posted = json.loads(text)
    assert posted.get("route") == "greedy" and posted.get("method") == "POST", (
        f"expected the ANY method on {{proxy+}} to serve POST with "
        f"$context.httpMethod='POST', got {posted!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
