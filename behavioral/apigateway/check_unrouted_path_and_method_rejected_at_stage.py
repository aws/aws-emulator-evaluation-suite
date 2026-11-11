"""unrouted-path-and-method-rejected-at-stage."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "unrouted-path-and-method-rejected-at-stage"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']

_MISSING_TOKEN_MESSAGE = "Missing Authentication Token"


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
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id))
    return resource_id

def _mock_method(ag, api_id, resource_id, http_method, response_template):
    """A fully wired MOCK method: 200 request template + 200 integration response."""
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
        authorizationType="NONE",
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

def _message(text):
    """The `message` field of an execute-api gateway response body."""
    try:
        return json.loads(text).get("message")
    except (ValueError, AttributeError):
        return None


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A deployed stage answers 403 "Missing Authentication Token" for a deeper path under a real
    resource, an unconfigured method on a real resource and the bare root, while the configured
    route still serves 200, so neither a catch-all nor a blanket 403 passes."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _child(ctx, ag, api_id, "ok")
    _mock_method(ag, api_id, resource_id, "GET", '{"marker":"configured-route"}')

    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_unique_token()}"
    ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment_id,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))

    ok_url = _apigw_url(ctx, api_id, stage, "/ok")
    _poll_http(
        ok_url,
        lambda s, h, t: s == 200 and _message(t) is None,
        description=f"GET {ok_url} to serve the configured route",
    )

    negatives = [
        ("GET", _apigw_url(ctx, api_id, stage, "/ok/deeper"),
         "a deeper path under a configured resource, with no resource of its own"),
        ("POST", ok_url,
         "a configured resource addressed with an unconfigured HTTP method"),
        ("GET", _apigw_url(ctx, api_id, stage, ""),
         "the stage root, which has no method on the API's root resource"),
    ]
    for method, url, why in negatives:
        status, headers, text = _http(method, url, body=b"" if method == "POST" else None)
        assert status == 403, (
            f"expected 403 for {why} ({method} {url}), got {status}: {text!r}. "
            f"Real API Gateway refuses an unresolvable route with the "
            f"MISSING_AUTHENTICATION_TOKEN gateway response, not 404 and never 200."
        )
        assert _message(text) == _MISSING_TOKEN_MESSAGE, (
            f"expected the 403 body for {why} to be "
            f'{{"message":"{_MISSING_TOKEN_MESSAGE}"}}, got {text!r} '
            f"(x-amzn-errortype={headers.get('x-amzn-errortype')!r})"
        )

    # Control: the refusals are route-scoped, not a whole-stage outage.
    status, _, text = _http("GET", ok_url)
    assert status == 200, (
        f"control: the configured route must still serve after the refusals, "
        f"got {status}: {text!r}"
    )
    assert json.loads(text).get("marker") == "configured-route", (
        f"control: expected the configured route's mapped body, got {text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
