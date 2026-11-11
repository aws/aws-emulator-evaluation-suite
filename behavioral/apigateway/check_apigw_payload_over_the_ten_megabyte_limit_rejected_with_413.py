"""apigw-payload-over-the-ten-megabyte-limit-rejected-with-413."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-payload-over-the-ten-megabyte-limit-rejected-with-413"
GROUP = "methods-integrations"
SERVICES = ["apigateway"]

# A FIXED, NON-ADJUSTABLE service quota ("API Payload Size — Each supported Region: 10
# Megabytes — Adjustable: No", docs.aws.amazon.com/general/latest/gr/apigateway.html), so
# pinning it is part of the contract rather than an account-specific quota. It is not
# read from Service Quotas precisely because it cannot vary by account.
_LIMIT_BYTES = 10 * 1024 * 1024          # 10485760
_SLACK_BYTES = 64 * 1024                 # keeps both legs clear of the boundary itself
_PROPAGATION_S = 150.0
_LARGE_TIMEOUT_S = 180.0                 # a ~10 MB upload needs more than the default


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
    raise AssertionError(f"root ('/') resource not found on restApiId={api_id!r}")


def _create_api(ctx, ag, scenario):
    """A REGIONAL REST API registered for teardown, marked in name/description/tag."""
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        description=f"sim2real {scenario}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)))
    return resource_id


def _http(method, url, body=None, headers=None, timeout=20.0):
    """HTTP request; returns (status, lowercased response headers, body text).

    A transport failure (reset mid-upload, DNS, TLS) returns status -1 and the exception
    text as the body, so the caller's assertion FAILS naming what actually happened instead
    of the check dying with an opaque traceback. -1 is never a passing value anywhere."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode(errors="replace"))
    except urllib.error.URLError as exc:
        return (-1, {}, f"transport failure before any HTTP response: {exc!r}")


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage. Transport/hostname only."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=_PROPAGATION_S, interval_s=4.0, request_timeout=20.0,
               description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds; RAISE on the
    deadline rather than returning the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers,
                                           timeout=request_timeout)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; "
                f"last=(status={status}, body={text[:200]!r})"
            )
        time.sleep(interval_s)


def _json_body_of_size(total_bytes, marker):
    """A syntactically valid JSON object of EXACTLY total_bytes bytes, padded with 'a'."""
    envelope = json.dumps({"marker": marker, "pad": ""}).encode()
    pad = total_bytes - len(envelope)
    if pad < 0:
        raise AssertionError(
            f"cannot build a {total_bytes}-byte JSON body: the envelope alone is "
            f"{len(envelope)} bytes"
        )
    body = json.dumps({"marker": marker, "pad": "a" * pad}).encode()
    if len(body) != total_bytes:
        raise AssertionError(
            f"body construction is off by {len(body) - total_bytes} bytes: wanted "
            f"{total_bytes}, built {len(body)}"
        )
    return body
# ===== end helpers =====


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A body just under 10485760 bytes is served and one just over is refused with 413 and AWS's
    fixed built-in body, never reaching the integration nor the REQUEST_TOO_LARGE gateway
    response customised on the same API (the 10 MB payload limit is not adjustable)."""
    ag = ctx.client("apigateway")
    marker = f"sim2real-{_unique_token()}"
    gw_marker = f"sim2real-gw-{_unique_token()}"

    api_id = _create_api(ctx, ag, "payload-size-limit-413")
    resource = _child(ctx, ag, api_id, "upload")
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource, httpMethod="POST",
        authorizationType="NONE"))
    # A LITERAL request template: the integration must not spend time parsing ~10 MB of
    # JSON, and the response must not echo it, so what is graded is the size decision alone.
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource, httpMethod="POST", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource, httpMethod="POST", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource, httpMethod="POST", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"integration":"%s"}' % marker}))
    _retry_throttled(lambda: ag.put_gateway_response(
        restApiId=api_id, responseType="REQUEST_TOO_LARGE",
        responseTemplates={"application/json":
                           '{"gw":"%s","type":"$context.error.responseType"}' % gw_marker}))

    stage = f"s{_unique_token()}"
    deployment = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage)))

    url = _apigw_url(ctx, api_id, stage, "/upload")
    hdrs = {"Content-Type": "application/json"}

    # A small request first, only to establish that the freshly deployed stage is servable —
    # so the multi-megabyte legs below are single, unretried observations.
    _poll_http(
        url, lambda s, h, t: s == 200 and marker in t, method="POST",
        body=json.dumps({"marker": marker}).encode(), headers=hdrs,
        description=f"POST {url} to become servable and return marker {marker!r}",
    )

    # ---- demonstrated control: just UNDER the documented limit --------------------------
    under_bytes = _LIMIT_BYTES - _SLACK_BYTES
    under_status, _uh, under_text = _http(
        "POST", url, body=_json_body_of_size(under_bytes, marker), headers=hdrs,
        timeout=_LARGE_TIMEOUT_S)
    assert under_status == 200, (
        f"control: a {under_bytes}-byte body ({_SLACK_BYTES} bytes under the documented "
        f"{_LIMIT_BYTES}-byte payload limit) must be accepted, got {under_status} with body "
        f"{under_text[:200]!r} — without this leg the 413 below could just be 'refuses "
        f"everything large'"
    )
    assert marker in under_text, (
        f"control: the accepted {under_bytes}-byte body must reach the integration and come "
        f"back with marker {marker!r}, got {under_text[:200]!r}"
    )

    # ---- the refusal: just OVER the documented limit ------------------------------------
    over_bytes = _LIMIT_BYTES + _SLACK_BYTES
    over_status, over_headers, over_text = _http(
        "POST", url, body=_json_body_of_size(over_bytes, marker), headers=hdrs,
        timeout=_LARGE_TIMEOUT_S)
    assert over_status == 413, (
        f"expected 413 for a {over_bytes}-byte body ({_SLACK_BYTES} bytes over the "
        f"documented, non-adjustable {_LIMIT_BYTES}-byte payload limit), got {over_status} "
        f"with body {over_text[:200]!r} (headers={over_headers!r}); status -1 means the "
        f"connection failed before any HTTP response arrived"
    )
    assert marker not in over_text, (
        f"effect-absent: the oversized request must be refused BEFORE the integration, so "
        f"the response must not carry {marker!r}; got {over_text[:200]!r}"
    )
    # A payload-size 413 is a front-door
    # rejection that never reaches the REST API's gateway-response substitution pipeline, so the
    # REQUEST_TOO_LARGE customisation configured above (marker gw_marker) is NEVER served here —
    # even though the very same customisation is live on this method. AWS instead returns its
    # fixed built-in body naming the documented byte limit, so the customisation's absence and
    # the exact fixed body are asserted.
    assert gw_marker not in over_text, (
        f"the REQUEST_TOO_LARGE gateway response customisation (marker {gw_marker!r}) must NOT "
        f"be served for a payload-size rejection — confirmed against real AWS, this refusal "
        f"happens before the gateway-response substitution pipeline ever runs; got body "
        f"{over_text[:300]!r}"
    )
    assert over_headers.get("content-type") == "text; charset=utf-8", (
        f"expected AWS's fixed content-type for a payload-size 413 ('text; charset=utf-8'), "
        f"got {over_headers.get('content-type')!r} (headers={over_headers!r})"
    )
    expected_body = f"HTTP content length exceeded {_LIMIT_BYTES} bytes."
    assert over_text == expected_body, (
        f"expected AWS's fixed built-in 413 body naming the documented {_LIMIT_BYTES}-byte "
        f"limit ({expected_body!r}), got {over_text[:300]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
