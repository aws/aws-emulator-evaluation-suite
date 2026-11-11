"""apigw-gateway-response-messagestring-renders-prequoted-error-message."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-gateway-response-messagestring-renders-prequoted-error-message"
GROUP = "gateway-responses"
SERVICES = ["apigateway"]


# ===== helpers (self-contained) =====
def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff: the
    apigateway control plane rate-limits mutating calls per account."""
    import random
    from botocore.exceptions import ClientError
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(10.0, 1.0 * (2 ** attempt)) + random.uniform(0, 0.3))


def _root_id(ag, api_id):
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"root resource not found on {api_id!r}")


def _http(method, url, *, verify=True):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(  # noqa: S310 - fixed https scheme
            req, timeout=15, context=_ssl_context(verify)
        ) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read().decode()
    except OSError as exc:
        return None, {}, repr(exc)


def _budget_s(ctx, want):
    """`want` seconds, capped by the time the runner leaves this check."""
    left = ctx.time_left()
    return want if left is None else max(1.0, min(want, left - 10.0))


def _poll(ctx, fn, predicate, *, timeout_s=150.0, interval_s=3.0, description="result"):
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    while True:
        result = fn()
        if predicate(*result):
            return result
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{description} not observed within {budget:.0f}s; last={result!r}")
        time.sleep(interval_s)
# ===== end helpers =====


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A customized gateway response embeds $context.error.messageString directly as a
    JSON value (already quoted) and renders the gateway's own error message, identical
    to a sibling field that manually quotes $context.error.message."""
    ag = ctx.client("apigateway")

    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"), endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))

    root_id = _root_id(ag, api_id)
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": '{"served":true}'}))

    _retry_throttled(lambda: ag.put_gateway_response(
        restApiId=api_id, responseType="MISSING_AUTHENTICATION_TOKEN",
        responseTemplates={"application/json": (
            '{"quoted":$context.error.messageString,"manually_quoted":"$context.error.message"}'
        )},
    ))
    stored = ag.get_gateway_response(restApiId=api_id, responseType="MISSING_AUTHENTICATION_TOKEN")
    assert "$context.error.messageString" in (
        (stored.get("responseTemplates") or {}).get("application/json") or ""
    ), f"precondition: the customization must round-trip through the control plane, got {stored!r}"

    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    stage_name = "test"
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage_name, deploymentId=deployment_id,
        tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage_name)))

    known_url = f"{ctx.rest_api_url(api_id, stage_name)}/"
    unknown_url = f"{ctx.rest_api_url(api_id, stage_name)}/no-such-route"

    verify = ctx.http_verify
    status, _headers, text = _poll(
        ctx, lambda: _http("GET", known_url, verify=verify), lambda s, h, t: s == 200,
        description=f"GET {known_url} to be served by the deployed stage",
    )
    assert json.loads(text) == {"served": True}, (
        f"precondition: the matched route must serve its own body, got {text!r}"
    )

    status, _headers, text = _poll(
        ctx, lambda: _http("GET", unknown_url, verify=verify), lambda s, h, t: s == 403,
        description=f"GET {unknown_url} to be answered by the customized gateway response",
    )
    parsed = json.loads(text)
    assert parsed["quoted"] == "Missing Authentication Token", (
        f"expected $context.error.messageString to resolve to the gateway's own error "
        f"message, got {parsed.get('quoted')!r} in {text!r}"
    )
    assert parsed["manually_quoted"] == parsed["quoted"], (
        f"expected the manually-quoted $context.error.message to render the identical "
        f"text as the pre-quoted messageString, got {parsed['manually_quoted']!r} vs "
        f"{parsed['quoted']!r}"
    )

    # Control: the customization did not disturb the matched route.
    status, _headers, text = _http("GET", known_url, verify=verify)
    assert status == 200 and json.loads(text) == {"served": True}, (
        f"control: the matched route must still serve its own body, got {status!r}: {text!r}"
    )


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
