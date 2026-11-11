"""httpapi-stage-default-throttle-returns-default-too-many-requests."""
from __future__ import annotations

import concurrent.futures
import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "httpapi-stage-default-throttle-returns-default-too-many-requests"
GROUP = "throttling"
SERVICES = ["apigatewayv2", "apigateway"]


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


def _http(method, url, *, verify=True):
    """(status, lowercased headers, body text); a 4xx/5xx is a result, a network error is
    (None, {}, repr), not an exception."""
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
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An HTTP API stage's DefaultRouteSettings throttle (rate 1, burst 1) sheds part of
    a concurrent burst with the exact default THROTTLED envelope, and still serves
    outside the burst.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-throttling.html
    """
    ag = ctx.client("apigateway")
    agw = ctx.client("apigatewayv2")

    # A REST API MOCK method as the HTTP_PROXY backend: self-contained, needs no Lambda.
    backend_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-httpapi-backend-"),
        endpointConfiguration={"types": ["REGIONAL"]}, tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=backend_id)))
    backend_root = [i for i in ag.get_resources(restApiId=backend_id)["items"] if i["path"] == "/"][0]["id"]
    _retry_throttled(lambda: ag.put_method(
        restApiId=backend_id, resourceId=backend_root, httpMethod="GET", authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=backend_id, resourceId=backend_root, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=backend_id, resourceId=backend_root, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=backend_id, resourceId=backend_root, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": '{"backend":"served"}'}))
    backend_dep = _retry_throttled(lambda: ag.create_deployment(restApiId=backend_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=backend_id, stageName="b", deploymentId=backend_dep,
        tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_stage(restApiId=backend_id, stageName="b")))
    backend_url = f"{ctx.rest_api_url(backend_id, 'b')}/"

    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP",
        Tags={"sim2real": CHECK},
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id, IntegrationType="HTTP_PROXY", IntegrationMethod="GET",
        IntegrationUri=backend_url, PayloadFormatVersion="1.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /", Target=f"integrations/{integration_id}")
    agw.create_stage(
        ApiId=api_id, StageName="$default", AutoDeploy=True,
        DefaultRouteSettings={"ThrottlingRateLimit": 1.0, "ThrottlingBurstLimit": 1},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default"))

    url = f"{ctx.stage_url(api['ApiEndpoint'], '$default')}/"

    status, _headers, text = _poll(
        ctx, lambda: _http("GET", url, verify=ctx.http_verify), lambda s, h, t: s == 200,
        description=f"GET {url} to be served before the burst",
    )
    assert json.loads(text) == {"backend": "served"}, (
        f"precondition: an unburst call must reach the HTTP_PROXY backend, got {text!r}"
    )

    verify = ctx.http_verify
    budget = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + budget
    while True:
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
            results = list(pool.map(lambda _: _http("GET", url, verify=verify), range(40)))
        shed = [r for r in results if r[0] == 429]
        if shed:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"a stage DefaultRouteSettings throttle of rate=1/burst=1 never shed a single "
                f"request out of repeated 40-way concurrent bursts against {url}"
                f" within {budget:.0f}s; last burst statuses {sorted(r[0] or 0 for r in results)!r}"
            )
        time.sleep(5.0)
    # Only the burst that shed a request shows the throttle partially serving it.
    served_during_burst = [t for st, _h, t in results if st == 200]
    _rej_status, _rej_headers, rej_text = shed[0]
    assert rej_text == '{"message":"Too Many Requests"}', (
        f"expected the exact default THROTTLED body, got {rej_text!r}"
    )
    assert served_during_burst, (
        f"a throttle that sheds EVERY request in the burst is not throttling, it is broken; "
        f"got rejection-only results for {url}"
    )
    assert all(json.loads(t) == {"backend": "served"} for t in served_during_burst), (
        f"every non-throttled request during the burst must still reach the backend, "
        f"got {served_during_burst[:3]!r}"
    )

    # Control: once the rate-limit bucket refills, the stage serves normally again.
    status, _headers, text = _poll(
        ctx, lambda: _http("GET", url, verify=ctx.http_verify), lambda s, h, t: s == 200,
        timeout_s=30.0, interval_s=1.0,
        description=f"GET {url} to recover once the throttle bucket refills",
    )
    assert status == 200 and json.loads(text) == {"backend": "served"}, (
        f"control: the stage must serve again once the throttle bucket refills, got "
        f"{status!r}: {text!r}"
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
