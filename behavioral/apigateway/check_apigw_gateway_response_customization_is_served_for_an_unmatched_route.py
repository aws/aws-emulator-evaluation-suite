"""apigw-gateway-response-customization-is-served-for-an-unmatched-route."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-gateway-response-customization-is-served-for-an-unmatched-route"
GROUP = 'gateway-responses'
SERVICES = ['apigateway']


# ===== helpers (self-contained) =====
def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account, so a throttle can
    be unrelated to the claim."""
    from botocore.exceptions import ClientError
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _create_api(ctx, ag, scenario):
    """Create a REGIONAL REST API (registered for teardown) and return its id.

    A REST API's only handle is a server-minted id,
    so the name, the description AND the tag all carry the sim2real marker."""
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        description=f"sim2real {scenario}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": scenario},
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)))
    return resource_id


def _http(method, url, body=None, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=150.0, interval_s=3.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds.

    A deployment becomes servable on its stage asynchronously, so the first touch of a
    freshly deployed stage polls to a condition with a bounded deadline rather than
    sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status}, {text!r})"
            )
        time.sleep(interval_s)
# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A customized MISSING_AUTHENTICATION_TOKEN gateway response replaces the status code, body
    and a response header the deployed stage serves for a path matching no route (with
    $context.error.responseType resolved), while a matched route is untouched."""
    ag = ctx.client("apigateway")
    marker = f"sim2real-gwr-{_unique_token()}"

    api_id = _create_api(ctx, ag, "gateway-response-customization")
    known_id = _child(ctx, ag, api_id, "known")
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=known_id, httpMethod="GET", authorizationType="NONE",
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=known_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode":200}'},
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=known_id, httpMethod="GET", statusCode="200",
    ))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=known_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"route":"matched"}'},
    ))

    _retry_throttled(lambda: ag.put_gateway_response(
        restApiId=api_id, responseType="MISSING_AUTHENTICATION_TOKEN", statusCode="418",
        responseParameters={"gatewayresponse.header.X-Sim2real-Gwr": f"'{marker}'"},
        responseTemplates={"application/json": (
            '{"custom":"%s","type":"$context.error.responseType"}' % marker
        )},
    ))
    stored = ag.get_gateway_response(
        restApiId=api_id, responseType="MISSING_AUTHENTICATION_TOKEN")
    assert stored["statusCode"] == "418", (
        f"precondition: the customization must round-trip through the control plane "
        f"before it can be graded on the data plane, got {stored!r}"
    )

    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName="test", deploymentId=deployment_id,
        tags={"sim2real": "gateway-response-customization"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName="test")))

    known_url = _apigw_url(ctx, api_id, "test", "/known")
    unknown_url = _apigw_url(ctx, api_id, "test", f"/unknown-{_unique_token()}")

    known_status, _kh, known_text = _poll_http(
        known_url, lambda s, h, t: s == 200,
        description=f"GET {known_url} to be served by the deployed stage",
    )

    unknown_status, unknown_headers, unknown_body = _http("GET", unknown_url)
    assert unknown_status == 418, (
        f"expected the customized 418 for a path matching no route, got "
        f"{unknown_status!r} body={unknown_body!r}"
    )
    parsed = json.loads(unknown_body)
    assert parsed["custom"] == marker, (
        f"expected the customized gateway-response body carrying {marker!r}, got "
        f"{unknown_body!r}"
    )
    assert parsed["type"] == "MISSING_AUTHENTICATION_TOKEN", (
        f"expected $context.error.responseType to resolve to "
        f"MISSING_AUTHENTICATION_TOKEN, got {parsed['type']!r} in {unknown_body!r}"
    )
    assert unknown_headers.get("x-sim2real-gwr") == marker, (
        f"expected the gatewayresponse.header parameter to reach the client as "
        f"X-Sim2real-Gwr: {marker!r}, got {unknown_headers.get('x-sim2real-gwr')!r}"
    )
    assert "Missing Authentication Token" not in unknown_body, (
        f"the default gateway-response text leaked through the customization: "
        f"{unknown_body!r}"
    )

    assert known_status == 200 and json.loads(known_text) == {"route": "matched"}, (
        f"control: customizing MISSING_AUTHENTICATION_TOKEN must not change a MATCHED "
        f"route, got {known_status!r}: {known_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
