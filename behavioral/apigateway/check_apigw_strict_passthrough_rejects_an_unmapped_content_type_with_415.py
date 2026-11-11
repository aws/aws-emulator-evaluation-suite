"""apigw-strict-passthrough-rejects-an-unmapped-content-type-with-415."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-strict-passthrough-rejects-an-unmapped-content-type-with-415"
GROUP = "methods-integrations"
SERVICES = ["apigateway"]

_PROPAGATION_S = 150.0


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


def _http(method, url, body=None, headers=None, timeout=20):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode(errors="replace"))


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=_PROPAGATION_S, interval_s=4.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds; RAISE on the
    deadline rather than returning the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; "
                f"last=(status={status}, body={text[:200]!r})"
            )
        time.sleep(interval_s)


def _mock_post(ag, api_id, resource_id, *, passthrough, marker):
    """A POST method with a MOCK integration whose ONLY requestTemplate is
    application/json, so `passthrough` decides what happens to any other Content-Type.

    Used ONLY for the backend `/echo` resource below: a MOCK integration has no execution
    path for a passthrough-forwarded (un-templated) body, so it answers 500
    API_CONFIGURATION_ERROR, not 200, when passthrough hands it a Content-Type it has no
    template for. The backend is always called with Content-Type
    forced to application/json (see `_http_post`), so its own `passthrough` value here never
    actually has to fire; it exists only to complete the method."""
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST",
        authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", type="MOCK",
        passthroughBehavior=passthrough,
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"integration":"%s"}' % marker}))


def _http_post(ag, api_id, resource_id, *, backend_url, passthrough):
    """A POST method with an HTTP integration to `backend_url`, whose ONLY requestTemplate
    is application/json, so `passthrough` alone decides what happens to any other
    Content-Type — and, unlike MOCK, an HTTP integration has a real backend to execute a
    passthrough-forwarded body against. The downstream Content-Type is forced to
    application/json via a static `requestParameters` override, so the backend (itself a
    MOCK keyed only on application/json) always accepts what passthrough hands it; only the
    FRONT integration's own template match/no-match — governed by `passthrough` — decides
    whether the request reaches the backend at all."""
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST",
        authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", type="HTTP",
        integrationHttpMethod="POST", uri=backend_url,
        passthroughBehavior=passthrough,
        requestTemplates={"application/json": "$input.body"},
        requestParameters={"integration.request.header.Content-Type": "'application/json'"}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200",
        selectionPattern=""))


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With passthroughBehavior=NEVER, a body whose Content-Type matches no request template is refused 415
    with the customised UNSUPPORTED_MEDIA_TYPE gateway response and never reaches the integration, while a
    twin WHEN_NO_MATCH resource serves it, as does the strict one once patched to WHEN_NO_MATCH."""
    ag = ctx.client("apigateway")
    marker = f"sim2real-{_unique_token()}"
    gw_marker = f"sim2real-gw-{_unique_token()}"

    # A real backend for `strict` and `lax` to call through an HTTP integration. MOCK
    # cannot serve as that backend (see `_mock_post`'s docstring), so it is used ONLY here.
    backend_api_id = _create_api(ctx, ag, "strict-passthrough-415-backend")
    backend_resource = _child(ctx, ag, backend_api_id, "echo")
    _mock_post(ag, backend_api_id, backend_resource, passthrough="WHEN_NO_MATCH", marker=marker)
    backend_stage = f"s{_unique_token()}"
    backend_deployment = _retry_throttled(
        lambda: ag.create_deployment(restApiId=backend_api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=backend_api_id, stageName=backend_stage, deploymentId=backend_deployment,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=backend_api_id, stageName=backend_stage)))
    backend_url = _apigw_url(ctx, backend_api_id, backend_stage, "/echo")

    api_id = _create_api(ctx, ag, "strict-passthrough-415")
    strict = _child(ctx, ag, api_id, "strict")
    lax = _child(ctx, ag, api_id, "lax")
    _http_post(ag, api_id, strict, backend_url=backend_url, passthrough="NEVER")
    _http_post(ag, api_id, lax, backend_url=backend_url, passthrough="WHEN_NO_MATCH")

    # The body embeds $context.error.responseType, which API Gateway substitutes only when it
    # classified the failure as this type. $context.error.messageString is left out: its value
    # carries literal double quotes, which would make the JSON body invalid.
    _retry_throttled(lambda: ag.put_gateway_response(
        restApiId=api_id, responseType="UNSUPPORTED_MEDIA_TYPE",
        responseTemplates={
            "application/json": '{"gw":"%s","type":"$context.error.responseType"}' % gw_marker,
        }))

    stage = f"s{_unique_token()}"
    deployment = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage)))

    strict_url = _apigw_url(ctx, api_id, stage, "/strict")
    lax_url = _apigw_url(ctx, api_id, stage, "/lax")
    payload = json.dumps({"probe": marker}).encode()

    # ---- beat 1: positive control on the strict resource -------------------------------
    ok_status, _oh, ok_text = _poll_http(
        strict_url, lambda s, h, t: s == 200 and marker in t, method="POST", body=payload,
        headers={"Content-Type": "application/json"},
        description=(
            f"POST {strict_url} with a MATCHING application/json Content-Type to be served "
            f"200 with marker {marker!r}"
        ),
    )
    assert ok_status == 200 and marker in ok_text, (
        f"positive control: the strict resource must serve a matching Content-Type; got "
        f"{ok_status} with body {ok_text[:200]!r}"
    )

    # ---- beats 2-4: break exactly one thing — the Content-Type -------------------------
    bad_status, bad_headers, bad_text = _poll_http(
        strict_url, lambda s, h, t: s == 415, method="POST", body=payload,
        headers={"Content-Type": "text/plain"},
        description=(
            f"POST {strict_url} with an UNMAPPED text/plain Content-Type to be refused 415 "
            f"under passthroughBehavior=NEVER"
        ),
    )
    assert bad_status == 415, (
        f"expected 415 for an unmapped Content-Type under passthroughBehavior=NEVER, got "
        f"{bad_status} with body {bad_text[:200]!r} (headers={bad_headers!r})"
    )
    assert marker not in bad_text, (
        f"effect-absent: the 415 must be produced BEFORE the integration, so the response "
        f"must not carry the integration marker {marker!r}; got {bad_text[:200]!r}"
    )
    refused = json.loads(bad_text)
    assert refused.get("gw") == gw_marker, (
        f"expected the customised UNSUPPORTED_MEDIA_TYPE gateway response (marker "
        f"{gw_marker!r}) to be served, got {refused!r} — a 415 rendered from the built-in "
        f"body means the refusal was not classified as UNSUPPORTED_MEDIA_TYPE"
    )
    assert refused.get("type") == "UNSUPPORTED_MEDIA_TYPE", (
        f"expected $context.error.responseType to substitute to 'UNSUPPORTED_MEDIA_TYPE' in "
        f"the gateway response body, got {refused.get('type')!r} (full body {refused!r})"
    )

    # ---- beat 5: twin control in the same instant, differing ONLY in passthrough --------
    # A single request, not a poll: the strict resource above already proved this stage is
    # live, so the twin is observed in the same instant and its own asserts carry the
    # expected-vs-actual message.
    lax_status, _lh, lax_text = _http(
        "POST", lax_url, body=payload, headers={"Content-Type": "text/plain"})
    assert lax_status == 200, (
        f"twin control: the resource differing ONLY in passthroughBehavior=WHEN_NO_MATCH "
        f"must serve the same text/plain request, so the 415 above is the flag and not the "
        f"payload; got {lax_status} with body {lax_text[:200]!r}"
    )
    assert marker in lax_text, (
        f"twin control: the WHEN_NO_MATCH resource must reach its integration and return "
        f"marker {marker!r}, got {lax_text[:200]!r}"
    )

    # ---- beat 6: restore — the strict resource becomes lax and serves the same bytes ----
    _retry_throttled(lambda: ag.update_integration(
        restApiId=api_id, resourceId=strict, httpMethod="POST",
        patchOperations=[{"op": "replace", "path": "/passthroughBehavior",
                          "value": "WHEN_NO_MATCH"}]))
    stored = ag.get_integration(restApiId=api_id, resourceId=strict, httpMethod="POST")
    assert stored.get("passthroughBehavior") == "WHEN_NO_MATCH", (
        f"expected GetIntegration to report passthroughBehavior=WHEN_NO_MATCH after the "
        f"patch, got {stored.get('passthroughBehavior')!r}"
    )
    redeployed = _retry_throttled(
        lambda: ag.create_deployment(restApiId=api_id, stageName=stage))["id"]
    assert redeployed != deployment, (
        f"expected a NEW deployment id for the restore redeploy, got {redeployed!r}"
    )
    restored_status, _sh, restored_text = _poll_http(
        strict_url, lambda s, h, t: s == 200 and marker in t, method="POST", body=payload,
        headers={"Content-Type": "text/plain"},
        description=(
            f"POST {strict_url} with the IDENTICAL text/plain request to be served once "
            f"passthroughBehavior is relaxed and the API redeployed"
        ),
    )
    assert restored_status == 200 and marker in restored_text, (
        f"restore: the identical text/plain request must succeed once passthrough is "
        f"WHEN_NO_MATCH, got {restored_status} with body {restored_text[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
