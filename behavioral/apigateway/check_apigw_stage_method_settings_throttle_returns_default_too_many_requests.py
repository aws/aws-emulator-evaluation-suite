"""apigw-stage-method-settings-throttle-returns-default-too-many-requests."""
from __future__ import annotations

import concurrent.futures
import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-stage-method-settings-throttle-returns-default-too-many-requests"
GROUP = "throttling"
SERVICES = ["apigateway"]


# ===== helpers (self-contained) =====
def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    This guards the CONTROL plane (apigateway's per-account mutation limit), a
    different limiter from the stage throttle this check sets up."""
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
    """A stage's wildcard method-settings throttle (rate 1, burst 1) sheds part of a
    concurrent burst at a MOCK method with the exact default THROTTLED envelope, before
    the integration runs, while the call still succeeds outside the burst."""
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

    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    stage_name = "test"
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage_name, deploymentId=deployment_id,
        tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage_name)))

    _retry_throttled(lambda: ag.update_stage(
        restApiId=api_id, stageName=stage_name, patchOperations=[
            {"op": "replace", "path": "/*/*/throttling/rateLimit", "value": "1.0"},
            {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "1"},
        ]))

    url = f"{ctx.rest_api_url(api_id, stage_name)}/"

    status, _headers, text = _poll(
        ctx, lambda: _http("GET", url, verify=ctx.http_verify), lambda s, h, t: s == 200,
        description=f"GET {url} to be served before the burst",
    )
    assert json.loads(text) == {"served": True}, (
        f"precondition: an unburst call must reach the MOCK integration, got {text!r}"
    )

    # The throttle setting propagates to the edge asynchronously; poll bursts of concurrent
    # requests until one is shed, rather than a single burst that might race the propagation.
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
                f"a wildcard method-settings throttle of rate=1/burst=1 never shed a single request "
                f"out of repeated 40-way concurrent bursts against {url}"
                f" within {budget:.0f}s; last burst statuses {sorted(r[0] or 0 for r in results)!r}"
            )
        time.sleep(5.0)
    # Only the burst that shed a request shows the throttle partially serving it.
    served_during_burst = [t for st, _h, t in results if st == 200]
    _rej_status, rej_headers, rej_text = shed[0]
    assert rej_text == '{"message":"Too Many Requests"}', (
        f"expected the exact default THROTTLED body, got {rej_text!r}"
    )
    assert rej_headers.get("x-amzn-errortype") == "TooManyRequestsException", (
        f"expected x-amzn-ErrorType: TooManyRequestsException, got "
        f"{rej_headers.get('x-amzn-errortype')!r} (all headers {rej_headers!r})"
    )
    assert served_during_burst, (
        f"a throttle that sheds EVERY request in the burst is not throttling, it is broken; "
        f"got rejection-only results for {url}"
    )
    assert all(json.loads(t) == {"served": True} for t in served_during_burst), (
        f"every non-throttled request during the burst must still reach the MOCK integration, "
        f"got {served_during_burst[:3]!r}"
    )

    # Control: once the rate-limit bucket refills, the stage serves normally again.
    status, _headers, text = _poll(
        ctx, lambda: _http("GET", url, verify=ctx.http_verify), lambda s, h, t: s == 200,
        timeout_s=30.0, interval_s=1.0,
        description=f"GET {url} to recover once the throttle bucket refills",
    )
    assert status == 200 and json.loads(text) == {"served": True}, (
        f"control: a request issued after the burst must still be served, got "
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
