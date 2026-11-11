"""apigw-http-proxy-passes-cors-header-plain-http-integration-drops-it."""
from __future__ import annotations

import random
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-http-proxy-passes-cors-header-plain-http-integration-drops-it"
GROUP = "integrations"
SERVICES = ["apigateway"]

_ORIGIN = "https://sim2real.example"


def _http(method, url, headers=None, timeout_s=20):
    """HTTP request via urllib. Returns (status, lower-cased headers, text)."""
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - fixed https
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read().decode()


def _poll_http(url, predicate, *, timeout_s=90.0, interval_s=3.0, description="response"):
    deadline = time.monotonic() + timeout_s
    while True:
        status, headers, text = _http("GET", url)
        if predicate(status, headers, text):
            return status, headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last=({status}, {text!r})")
        time.sleep(interval_s)


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    DeleteRestApi's account-wide burst is small (a few consecutive deletes within seconds
    throttle), so concurrent teardowns can exhaust it; the retry makes cleanup converge.
    """
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(5.0, 0.5 * (2**attempt)) + random.uniform(0, 0.3))


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Fronting the same MOCK /backend response, an HTTP_PROXY integration copies its custom and
    Access-Control-Allow-Origin headers onto the client response verbatim, while a plain HTTP
    integration with no responseParameters mapping drops both."""
    ag = ctx.client("apigateway")

    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-cors-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real:managed": "true"},
    )["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    root_id = ag.get_resources(restApiId=api_id)["items"][0]["id"]

    # The backend: a MOCK integration that always answers 200 with a custom header and a
    # static CORS header.
    backend_resource = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="backend")["id"]
    ag.put_method(
        restApiId=api_id, resourceId=backend_resource, httpMethod="GET", authorizationType="NONE"
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=backend_resource,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id,
        resourceId=backend_resource,
        httpMethod="GET",
        statusCode="200",
        responseParameters={
            "method.response.header.X-Backend-Marker": False,
            "method.response.header.Access-Control-Allow-Origin": False,
        },
    )
    ag.put_integration_response(
        restApiId=api_id,
        resourceId=backend_resource,
        httpMethod="GET",
        statusCode="200",
        responseParameters={
            "method.response.header.X-Backend-Marker": "'sim2real-backend-value'",
            "method.response.header.Access-Control-Allow-Origin": f"'{_ORIGIN}'",
        },
        responseTemplates={"application/json": '{"ok": true}'},
    )

    backend_url = f"{ctx.rest_api_url(api_id, 'live')}/backend"

    # The front door: two more resources on the SAME API, pointed at the backend's own
    # invoke URL.
    proxy_resource = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="viaproxy")["id"]
    ag.put_method(
        restApiId=api_id, resourceId=proxy_resource, httpMethod="GET", authorizationType="NONE"
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=proxy_resource,
        httpMethod="GET",
        type="HTTP_PROXY",
        integrationHttpMethod="GET",
        uri=backend_url,
    )

    plain_resource = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="viaplain")["id"]
    ag.put_method(
        restApiId=api_id, resourceId=plain_resource, httpMethod="GET", authorizationType="NONE"
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=plain_resource,
        httpMethod="GET",
        type="HTTP",
        integrationHttpMethod="GET",
        uri=backend_url,
        passthroughBehavior="WHEN_NO_MATCH",
    )
    # Deliberately no responseParameters here: a plain HTTP integration only exposes a
    # backend header the integration response explicitly maps onto the method response.
    ag.put_method_response(restApiId=api_id, resourceId=plain_resource, httpMethod="GET", statusCode="200")
    ag.put_integration_response(
        restApiId=api_id,
        resourceId=plain_resource,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": ""},
    )

    ag.create_deployment(restApiId=api_id, stageName="live")

    # Confirm the backend itself actually serves both headers, before judging the fronts.
    direct_status, direct_headers, _direct_text = _poll_http(
        backend_url, lambda s, h, t: s == 200, description="backend MOCK response"
    )
    assert direct_status == 200, f"backend did not come up: {direct_status}"
    assert direct_headers.get("x-backend-marker") == "sim2real-backend-value", (
        f"backend's own response is missing its marker header, got {direct_headers!r}"
    )
    assert direct_headers.get("access-control-allow-origin") == _ORIGIN, (
        f"backend's own response is missing its CORS header, got {direct_headers!r}"
    )

    proxy_url = f"{ctx.rest_api_url(api_id, 'live')}/viaproxy"
    plain_url = f"{ctx.rest_api_url(api_id, 'live')}/viaplain"

    proxy_status, proxy_headers, proxy_text = _poll_http(
        proxy_url, lambda s, h, t: s == 200, description="HTTP_PROXY route"
    )
    assert proxy_status == 200, f"expected 200 via HTTP_PROXY, got {proxy_status}: {proxy_text!r}"
    assert proxy_headers.get("x-backend-marker") == "sim2real-backend-value", (
        f"HTTP_PROXY must copy the backend's custom header verbatim, got {proxy_headers!r}"
    )
    assert proxy_headers.get("access-control-allow-origin") == _ORIGIN, (
        f"HTTP_PROXY must copy the backend's CORS header verbatim, got {proxy_headers!r}"
    )

    plain_status, plain_headers, _plain_text = _poll_http(
        plain_url, lambda s, h, t: s == 200, description="plain HTTP route"
    )
    assert plain_status == 200, f"expected 200 via plain HTTP integration, got {plain_status}"
    assert "x-backend-marker" not in plain_headers, (
        f"a plain HTTP integration with no responseParameters mapping must NOT expose the "
        f"backend's custom header, got headers {plain_headers!r}"
    )
    assert "access-control-allow-origin" not in plain_headers, (
        f"a plain HTTP integration with no responseParameters mapping must NOT expose the "
        f"backend's CORS header either -- a browser preflight against this route would be "
        f"blocked even though the SAME backend grants it through HTTP_PROXY; got headers "
        f"{plain_headers!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
