"""canary-fifty-percent-split-serves-both-versions-within-tolerance."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "canary-fifty-percent-split-serves-both-versions-within-tolerance"
GROUP = "deployments-stages"
SERVICES = ["apigateway"]

_BASE_TEXT = "canary-test-text-base"
_CANARY_TEXT = "canary-test-text-canary"
_SAMPLE_SIZE = 40
_MIN_PER_VERSION = 8


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _root_id(ag, api_id: str) -> str:
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _ssl_context(verify) -> ssl.SSLContext:
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    ssl_ctx = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    if verify is False:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    return ssl_ctx


def _http(url: str, verify) -> tuple[int, str]:
    """(status, body text) of one GET."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, context=_ssl_context(verify), timeout=35) as resp:  # noqa: S310 - fixed https scheme
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _poll_http(ctx, url: str, predicate, *, timeout_s: float = 120.0, interval_s: float = 3.0,
               description: str = "stage response") -> tuple[int, str]:
    """Re-issue a GET until predicate(status, text) holds; raise on deadline."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status, text = _http(url, ctx.http_verify)
        if predicate(status, text):
            return status, text
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} not observed within {timeout_s}s; last=({status}, {text!r})")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A stage with a 50% canary samples both the base and canary deployments: over 40 requests
    each version is served at least 8 times, and every response is one of the two fixed bodies."""
    ag = ctx.client("apigateway")
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(_teardown(lambda: ag.delete_rest_api(restApiId=api_id), "NotFoundException"))

    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="release")["id"]
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": f'"{_BASE_TEXT}"'},
    )

    base_deployment = ag.create_deployment(restApiId=api_id)["id"]
    stage = ctx.unique_name("s")
    ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=base_deployment, tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage), "NotFoundException",
    ))

    url = f"{ctx.rest_api_url(api_id, stage)}/release"
    _poll_http(
        ctx, url, lambda s, t: s == 200 and t == f'"{_BASE_TEXT}"',
        description=f"GET {url} to serve the base deployment",
    )

    # Snapshot a changed integration response as a CANARY deployment, splitting traffic 50/50.
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": f'"{_CANARY_TEXT}"'},
    )
    canary_deployment = ag.create_deployment(
        restApiId=api_id, stageName=stage,
        canarySettings={"percentTraffic": 50.0, "useStageCache": False},
    )["id"]
    stage_now = ag.get_stage(restApiId=api_id, stageName=stage)
    canary = stage_now.get("canarySettings") or {}
    assert canary.get("deploymentId") == canary_deployment, (
        f"expected canarySettings.deploymentId={canary_deployment!r}, got {canary!r}"
    )
    assert canary.get("percentTraffic") == 50.0, (
        f"expected canarySettings.percentTraffic=50.0, got {canary.get('percentTraffic')!r}"
    )
    assert stage_now["deploymentId"] == base_deployment, (
        f"attaching a canary must not move the stage's own deploymentId: expected "
        f"{base_deployment!r}, got {stage_now.get('deploymentId')!r}"
    )

    # Warm up until both deployments have each answered several requests: right after a canary
    # attaches, a short burst can land lopsided before the split settles, so the official sample
    # below only starts once both sides are clearly live.
    _WARMUP_MIN_EACH = 5
    warmup_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + warmup_s
    warmup_counts = {_BASE_TEXT: 0, _CANARY_TEXT: 0}
    while time.monotonic() < deadline and (
        warmup_counts[_BASE_TEXT] < _WARMUP_MIN_EACH or warmup_counts[_CANARY_TEXT] < _WARMUP_MIN_EACH
    ):
        status, text = _http(url, ctx.http_verify)
        assert status == 200, f"GET {url} returned {status}, body {text!r}"
        if text == f'"{_BASE_TEXT}"':
            warmup_counts[_BASE_TEXT] += 1
        elif text == f'"{_CANARY_TEXT}"':
            warmup_counts[_CANARY_TEXT] += 1
        else:
            raise AssertionError(f"response body matched neither fixed text: {text!r}")
    if min(warmup_counts.values()) < _WARMUP_MIN_EACH and _budget_spent(ctx):
        raise TimeoutError("the canary warm-up: the run budget ended first; not graded")
    assert warmup_counts[_BASE_TEXT] >= _WARMUP_MIN_EACH and warmup_counts[_CANARY_TEXT] >= _WARMUP_MIN_EACH, (
        f"a 50% canary must route to both deployments within the warm-up window; got {warmup_counts!r}"
    )

    # The statistical sample: 40 requests, each version served at least 8 times (a tolerance
    # band around the 50/50 split, not an exact ratio), and nothing but the two fixed bodies.
    counts = {_BASE_TEXT: 0, _CANARY_TEXT: 0}
    for _ in range(_SAMPLE_SIZE):
        status, text = _http(url, ctx.http_verify)
        assert status == 200, f"GET {url} returned {status}, body {text!r}"
        if text == f'"{_BASE_TEXT}"':
            counts[_BASE_TEXT] += 1
        elif text == f'"{_CANARY_TEXT}"':
            counts[_CANARY_TEXT] += 1
        else:
            raise AssertionError(f"response body matched neither fixed text: {text!r}")

    total = counts[_BASE_TEXT] + counts[_CANARY_TEXT]
    assert total == _SAMPLE_SIZE, f"expected {_SAMPLE_SIZE} classified responses, got {total}: {counts!r}"
    assert counts[_BASE_TEXT] >= _MIN_PER_VERSION, (
        f"expected the base deployment served at least {_MIN_PER_VERSION}/{_SAMPLE_SIZE} times, "
        f"got {counts!r}"
    )
    assert counts[_CANARY_TEXT] >= _MIN_PER_VERSION, (
        f"expected the canary deployment served at least {_MIN_PER_VERSION}/{_SAMPLE_SIZE} times, "
        f"got {counts!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
