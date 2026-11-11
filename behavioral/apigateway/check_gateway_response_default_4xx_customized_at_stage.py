"""gateway-response-default-4xx-customized-at-stage."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "gateway-response-default-4xx-customized-at-stage"
GROUP = 'gateway-responses'
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

    A REST API deployment (and a gateway-response change, which takes effect with the
    next deployment) becomes servable asynchronously, so each first touch polls to a
    condition with a bounded deadline rather than sleeping a fixed amount."""
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

def _field(text, name):
    """A named field of a JSON response body, or None."""
    try:
        return json.loads(text).get(name)
    except (ValueError, AttributeError):
        return None


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A customized DEFAULT_4XX gateway response replaces the body and adds a header on every
    uncustomized 4xx at the stage; a customized MISSING_AUTHENTICATION_TOKEN then takes
    precedence over DEFAULT_4XX, including its statusCode override (403 -> 404)."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _child(ctx, ag, api_id, "ok")
    _mock_method(ag, api_id, resource_id, "GET", '{"marker":"configured-route"}')

    # Customize DEFAULT_4XX before the first deployment so there is no ambiguity about
    # which configuration the stage is serving.
    ag.put_gateway_response(
        restApiId=api_id, responseType="DEFAULT_4XX",
        responseTemplates={"application/json": '{"custom":"default-4xx"}'},
        responseParameters={"gatewayresponse.header.X-Sim-Gw": "'default4xx'"},
    )
    stored = ag.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    assert (stored.get("responseTemplates") or {}).get("application/json") == (
        '{"custom":"default-4xx"}'
    ), f"precondition: the DEFAULT_4XX template must round-trip, got {stored!r}"

    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_unique_token()}"
    ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment_id,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))

    ok_url = _apigw_url(ctx, api_id, stage, "/ok")
    _poll_http(
        ok_url, lambda s, h, t: s == 200,
        description=f"GET {ok_url} to serve the configured route",
    )

    # An unrouted path produces MISSING_AUTHENTICATION_TOKEN, which is NOT customized,
    # so it must fall back to DEFAULT_4XX.
    missing_url = _apigw_url(ctx, api_id, stage, "/no-such-path")
    status, headers, text = _poll_http(
        missing_url, lambda s, h, t: _field(t, "custom") == "default-4xx",
        description=(
            f"GET {missing_url} to be answered by the customized DEFAULT_4XX gateway "
            f"response (the MISSING_AUTHENTICATION_TOKEN type falls back to it)"
        ),
    )
    assert status == 403, (
        f"the DEFAULT_4XX customization declares no statusCode, so the underlying 403 "
        f"must be preserved, got {status}: {text!r}"
    )
    assert headers.get("x-sim-gw") == "default4xx", (
        f"expected the DEFAULT_4XX responseParameters static header mapping to emit "
        f"X-Sim-Gw: default4xx, got {headers.get('x-sim-gw')!r}"
    )
    assert "Missing Authentication Token" not in (text or ""), (
        f"the customized template must REPLACE the default body, not be appended to "
        f"it, got {text!r}"
    )

    # Customize the specific type: its body and statusCode must win over DEFAULT_4XX.
    ag.put_gateway_response(
        restApiId=api_id, responseType="MISSING_AUTHENTICATION_TOKEN", statusCode="404",
        responseTemplates={"application/json": '{"custom":"specific-matk"}'},
    )
    ag.create_deployment(restApiId=api_id, stageName=stage)
    status, headers, text = _poll_http(
        missing_url, lambda s, h, t: _field(t, "custom") == "specific-matk",
        description=(
            f"GET {missing_url} to be answered by the individually customized "
            f"MISSING_AUTHENTICATION_TOKEN gateway response instead of DEFAULT_4XX"
        ),
    )
    assert status == 404, (
        f"expected the specific gateway response's statusCode override (404) to win "
        f"over the underlying 403, got {status}: {text!r}"
    )
    assert headers.get("x-sim-gw") is None, (
        f"a response type that is individually customized no longer inherits from "
        f"DEFAULT_4XX, so its X-Sim-Gw header must be absent, got "
        f"{headers.get('x-sim-gw')!r}"
    )

    # Control: shaping gateway responses must not disturb the integration path.
    status, _, text = _http("GET", ok_url)
    assert status == 200 and _field(text, "marker") == "configured-route", (
        f"control: the configured route must still serve its own mapped 200 body, "
        f"got {status}: {text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
