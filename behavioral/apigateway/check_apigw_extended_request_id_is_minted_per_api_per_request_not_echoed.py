"""apigw-extended-request-id-is-minted-per-api-per-request-not-echoed."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-extended-request-id-is-minted-per-api-per-request-not-echoed"
GROUP = "methods-integrations"
SERVICES = ["apigateway"]

_PROPAGATION_S = 150.0


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
    """Invoke URL for a deployed stage. Transport/hostname only."""
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


def _deploy(ctx, ag, api_id):
    """CreateDeployment + a uniquely named stage (registered for teardown)."""
    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    stage = f"s{_unique_token()}"
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment_id,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage)))
    return stage


def _trace_fields(text):
    """Parse the front API's JSON trace body, hard-subscripting every field."""
    data = json.loads(text)
    missing = {"frontRequestId", "frontExtended", "backendExtended"} - set(data)
    if missing:
        raise AssertionError(
            f"the front API's response template must render frontRequestId, frontExtended "
            f"and backendExtended; missing {sorted(missing)} in {data!r}"
        )
    return data["frontRequestId"], data["frontExtended"], data["backendExtended"]
# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """`$context.extendedRequestId` is minted fresh by each API on every request and matches the
    `x-amz-apigw-id` response header, while `$context.requestId` is the client-supplied value, so
    the two ids never coincide and one request's front and backend APIs report different ones."""
    ag = ctx.client("apigateway")
    client_token = f"sim2real-{_unique_token(16)}"

    # ---- backend API: renders its OWN extendedRequestId -------------------------------
    backend_id = _create_api(ctx, ag, "extended-request-id-backend")
    backend_res = _child(ctx, ag, backend_id, "echo")
    _retry_throttled(lambda: ag.put_method(
        restApiId=backend_id, resourceId=backend_res, httpMethod="GET",
        authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=backend_id, resourceId=backend_res, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=backend_id, resourceId=backend_res, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=backend_id, resourceId=backend_res, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json":
                           '{"backendExtended":"$context.extendedRequestId"}'}))
    backend_stage = _deploy(ctx, ag, backend_id)
    backend_url = _apigw_url(ctx, backend_id, backend_stage, "/echo").rstrip("/")

    _poll_http(
        backend_url, lambda s, h, t: s == 200 and "backendExtended" in t,
        description=f"GET {backend_url} to serve the backend trace body",
    )

    # ---- front API: renders its own identifiers and lifts the backend's ----------------
    front_id = _create_api(ctx, ag, "extended-request-id-front")
    front_res = _child(ctx, ag, front_id, "trace")
    _retry_throttled(lambda: ag.put_method(
        restApiId=front_id, resourceId=front_res, httpMethod="GET",
        authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=front_id, resourceId=front_res, httpMethod="GET", type="HTTP",
        integrationHttpMethod="GET", uri=backend_url))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=front_id, resourceId=front_res, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=front_id, resourceId=front_res, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": (
            '{"frontRequestId":"$context.requestId",'
            '"frontExtended":"$context.extendedRequestId",'
            '"backendExtended":"$input.path(\'$.backendExtended\')"}'
        )}))
    front_stage = _deploy(ctx, ag, front_id)
    front_url = _apigw_url(ctx, front_id, front_stage, "/trace")

    override = {"x-amzn-RequestId": client_token}
    _poll_http(
        front_url, lambda s, h, t: s == 200 and "frontExtended" in t, headers=override,
        description=f"GET {front_url} to serve the two-hop trace body",
    )

    # ---- leg 1: the client supplies the request id ------------------------------------
    s1, h1, t1 = _http("GET", front_url, headers=override)
    assert s1 == 200, f"expected 200 from {front_url}, got {s1} with body {t1[:200]!r}"
    req1, ext1, back1 = _trace_fields(t1)
    assert req1 == client_token, (
        f"expected $context.requestId to be the client-supplied x-amzn-RequestId "
        f"{client_token!r}, got {req1!r} — clients are documented as able to override this id"
    )
    assert ext1 and ext1 != client_token, (
        f"expected $context.extendedRequestId to be a non-empty SERVER-minted id distinct "
        f"from the client's {client_token!r}, got {ext1!r}"
    )
    assert h1.get("x-amz-apigw-id") == ext1, (
        f"expected the x-amz-apigw-id response header to carry the same value the VTL "
        f"template rendered for $context.extendedRequestId ({ext1!r}), got "
        f"{h1.get('x-amz-apigw-id')!r} — two channels for one identifier must agree"
    )
    assert back1 and back1 != ext1, (
        f"expected the BACKEND api to mint its own extendedRequestId, distinct from the "
        f"front api's {ext1!r} for the same client request, got {back1!r} — equal values mean "
        f"the identifier is being echoed along the chain rather than minted per API"
    )

    # ---- leg 2: identical request; the server-minted ids must ADVANCE ------------------
    s2, h2, t2 = _http("GET", front_url, headers=override)
    assert s2 == 200, f"expected 200 from {front_url}, got {s2} with body {t2[:200]!r}"
    req2, ext2, back2 = _trace_fields(t2)
    assert req2 == client_token, (
        f"expected the client override to be honoured deterministically: $context.requestId "
        f"should be {client_token!r} on the second identical request too, got {req2!r}"
    )
    assert ext2 != ext1, (
        f"expected a FRESH front-api extendedRequestId on the second request; both requests "
        f"reported {ext1!r} — a constant server-minted id destroys log correlation"
    )
    assert back2 != back1, (
        f"expected a FRESH backend-api extendedRequestId on the second request; both "
        f"reported {back1!r}"
    )
    assert h2.get("x-amz-apigw-id") == ext2, (
        f"expected the x-amz-apigw-id response header to track the second request's "
        f"extendedRequestId {ext2!r}, got {h2.get('x-amz-apigw-id')!r}"
    )

    # ---- leg 3: no client override; the request id must be server-minted ---------------
    s3, _h3, t3 = _http("GET", front_url)
    assert s3 == 200, f"expected 200 from {front_url}, got {s3} with body {t3[:200]!r}"
    req3, ext3, _back3 = _trace_fields(t3)
    assert req3 and req3 != client_token, (
        f"with no x-amzn-RequestId header the service must mint $context.requestId itself, "
        f"and it must not be the token from the earlier legs; got {req3!r}"
    )
    assert req3 != ext3, (
        f"$context.requestId and $context.extendedRequestId are two different identifiers "
        f"and must not collapse to one value; both were {req3!r}"
    )
    distinct = {ext1, ext2, ext3}
    assert len(distinct) == 3, (
        f"expected three distinct server-minted extendedRequestId values across three "
        f"requests, got {len(distinct)}: {sorted(distinct)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
