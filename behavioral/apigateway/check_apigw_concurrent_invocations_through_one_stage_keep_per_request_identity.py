"""apigw-concurrent-invocations-through-one-stage-keep-per-request-identity."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "apigw-concurrent-invocations-through-one-stage-keep-per-request-identity"
GROUP = 'concurrency'
SERVICES = ['apigateway']

_N = 12


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

    A REST API's only handle is a server-minted id, so the name, the description AND the
    tag all carry the sim2real marker."""
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
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, timeout_s=150.0, interval_s=3.0,
               headers=None, description="stage response"):
    """Re-issue a GET until predicate(status, headers, text) holds, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http("GET", url, headers=headers)
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
    """Twelve simultaneous invocations of one deployed stage each get back their OWN query and
    header values and twelve distinct request ids (x-amzn-RequestId matching $context.requestId),
    so concurrent requests never bleed into each other; no ordering or latency is asserted."""
    ag = ctx.client("apigateway")

    api_id = _create_api(ctx, ag, "concurrent-request-identity")
    echo_id = _child(ctx, ag, api_id, "echo")
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=echo_id, httpMethod="GET", authorizationType="NONE",
        requestParameters={"method.request.querystring.id": False,
                           "method.request.header.X-Req": False},
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=echo_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode":200}'},
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=echo_id, httpMethod="GET", statusCode="200",
    ))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=echo_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": (
            '{"id":"$input.params(\'id\')",'
            '"hdr":"$input.params().header.get(\'X-Req\')",'
            '"context_request_id":"$context.requestId"}'
        )},
    ))

    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName="test", deploymentId=deployment_id,
        tags={"sim2real": "concurrent-request-identity"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName="test")))

    base = _apigw_url(ctx, api_id, "test", "/echo")
    warm_id = f"warm{_unique_token()}"
    _poll_http(
        f"{base}?id={warm_id}", lambda s, h, t: s == 200,
        headers={"X-Req": warm_id},
        description=f"GET {base} to be served by the deployed stage",
    )

    sent = [f"id{i:02d}{_unique_token()}" for i in range(_N)]

    def _one(value):
        status, headers, text = _http(
            "GET", f"{base}?id={value}", headers={"X-Req": f"h-{value}"})
        return {"sent": value, "status": status, "text": text,
                "header_request_id": headers.get("x-amzn-requestid")}

    with ThreadPoolExecutor(max_workers=_N) as pool:
        results = list(pool.map(_one, sent))

    statuses = {r["status"] for r in results}
    assert statuses == {200}, (
        f"expected all {_N} concurrent invocations to be served 200, got "
        f"{sorted(statuses)!r}; bodies {[r['text'][:80] for r in results]!r}"
    )

    bodies = [json.loads(r["text"]) for r in results]
    echoed_ids = [b["id"] for b in bodies]
    assert echoed_ids == sent, (
        f"cross-request bleed: sent {sent!r} but the concurrent responses echoed "
        f"{echoed_ids!r}"
    )
    echoed_headers = [b["hdr"] for b in bodies]
    assert echoed_headers == [f"h-{v}" for v in sent], (
        f"cross-request header bleed: expected {[f'h-{v}' for v in sent]!r}, got "
        f"{echoed_headers!r}"
    )

    context_ids = [b["context_request_id"] for b in bodies]
    assert len(set(context_ids)) == _N, (
        f"expected {_N} distinct $context.requestId values across the concurrent batch, "
        f"got {len(set(context_ids))} distinct: {context_ids!r}"
    )

    mismatched = [(r["header_request_id"], b["context_request_id"])
                  for r, b in zip(results, bodies)
                  if r["header_request_id"] != b["context_request_id"]]
    assert not mismatched, (
        f"the x-amzn-RequestId response header and $context.requestId must name the same "
        f"request; {len(mismatched)} of {_N} disagreed: {mismatched!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
