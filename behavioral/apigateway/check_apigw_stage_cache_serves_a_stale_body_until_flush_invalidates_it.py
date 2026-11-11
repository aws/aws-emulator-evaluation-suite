"""apigw-stage-cache-serves-a-stale-body-until-flush-invalidates-it."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-stage-cache-serves-a-stale-body-until-flush-invalidates-it"
GROUP = 'deployments-stages'
SERVICES = ['apigateway']

_CACHE_SIZE = "0.5"
_TTL_S = 300


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


def _http(method, url):
    """HTTP request; returns (status, body text)."""
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_body(url, predicate, *, timeout_s, interval_s=5.0, description="stage response"):
    """Re-issue a GET until predicate(status, text) holds, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, text = _http("GET", url)
        if predicate(status, text):
            return status, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status}, {text!r})"
            )
        time.sleep(interval_s)


def _poll_cache_status(ag, api_id, stage, *, timeout_s, interval_s=15.0):
    """Poll GetStage until cacheClusterStatus settles, returning the last value seen.

    Bounded and observable — never a bare sleep. A status that is not AVAILABLE by the
    deadline is returned so the caller can FAIL on it rather than skip."""
    deadline = time.monotonic() + timeout_s
    status = None
    while True:
        status = ag.get_stage(restApiId=api_id, stageName=stage).get("cacheClusterStatus")
        if status == "AVAILABLE":
            return status
        if time.monotonic() >= deadline:
            return status
        time.sleep(interval_s)


def _backend_route(ctx, ag, api_id, resource_id, marker):
    """(Re)point the backend's GET integration response at a literal carrying *marker*."""
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"version":"%s"}' % marker},
    ))
# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """With a stage cache cluster AVAILABLE and method caching on, a repeated GET keeps returning
    the cached body after the backend API (proved directly) serves a new one, and FlushStageCache
    makes the very next GET return the new body; the front API is never changed after deployment."""
    ag = ctx.client("apigateway")
    v1 = f"v1-{_unique_token()}"
    v2 = f"v2-{_unique_token()}"

    # ---- backend API: no cache, and its body changes under the front API's feet ----
    backend_id = _create_api(ctx, ag, "stage-cache-backend")
    backend_resource = _child(ctx, ag, backend_id, "b")
    _retry_throttled(lambda: ag.put_method(
        restApiId=backend_id, resourceId=backend_resource, httpMethod="GET",
        authorizationType="NONE",
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=backend_id, resourceId=backend_resource, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode":200}'},
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=backend_id, resourceId=backend_resource, httpMethod="GET",
        statusCode="200",
    ))
    _backend_route(ctx, ag, backend_id, backend_resource, v1)
    backend_deployment = _retry_throttled(
        lambda: ag.create_deployment(restApiId=backend_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=backend_id, stageName="b", deploymentId=backend_deployment,
        tags={"sim2real": "stage-cache-backend"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=backend_id, stageName="b")))
    backend_url = _apigw_url(ctx, backend_id, "b", "/b")
    _poll_body(
        backend_url, lambda s, t: s == 200 and v1 in t, timeout_s=150.0,
        description=f"GET {backend_url} to serve {v1!r}",
    )

    # ---- front API: HTTP integration to the backend, with a stage cache ----
    front_id = _create_api(ctx, ag, "stage-cache-front")
    front_resource = _child(ctx, ag, front_id, "c")
    _retry_throttled(lambda: ag.put_method(
        restApiId=front_id, resourceId=front_resource, httpMethod="GET",
        authorizationType="NONE",
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=front_id, resourceId=front_resource, httpMethod="GET", type="HTTP",
        integrationHttpMethod="GET", uri=backend_url,
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=front_id, resourceId=front_resource, httpMethod="GET", statusCode="200",
    ))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=front_id, resourceId=front_resource, httpMethod="GET", statusCode="200",
        selectionPattern="",
    ))
    front_deployment = _retry_throttled(
        lambda: ag.create_deployment(restApiId=front_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=front_id, stageName="test", deploymentId=front_deployment,
        cacheClusterEnabled=True, cacheClusterSize=_CACHE_SIZE,
        tags={"sim2real": "stage-cache-front"},
    ))
    # Registered HERE, before the multi-minute AVAILABLE poll below: an orphaned cache
    # cluster bills hourly, and the poll is exactly where this check can die.
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=front_id, stageName="test")))

    _retry_throttled(lambda: ag.update_stage(
        restApiId=front_id, stageName="test",
        patchOperations=[
            {"op": "replace", "path": "/c/GET/caching/enabled", "value": "true"},
            {"op": "replace", "path": "/c/GET/caching/ttlInSeconds", "value": str(_TTL_S)},
        ],
    ))

    stage_status = _poll_cache_status(ag, front_id, "test", timeout_s=900.0)
    assert stage_status == "AVAILABLE", (
        f"the {_CACHE_SIZE}GB cache cluster never became AVAILABLE; last "
        f"cacheClusterStatus was {stage_status!r} — a cluster that does not provision is a "
        f"failure, not a reason to skip"
    )
    method_settings = ag.get_stage(
        restApiId=front_id, stageName="test").get("methodSettings", {})
    assert method_settings.get("c/GET", {}).get("cachingEnabled") is True, (
        f"precondition: per-method caching must be ON before staleness can be graded, got "
        f"methodSettings {method_settings!r}"
    )

    front_url = _apigw_url(ctx, front_id, "test", "/c")
    _s1, body1 = _poll_body(
        front_url, lambda s, t: s == 200 and v1 in t, timeout_s=180.0,
        description=f"GET {front_url} to serve {v1!r} and prime the cache",
    )
    _s2, body2 = _http("GET", front_url)
    assert body2 == body1, (
        f"two identical GETs must return the byte-identical cached body, got {body1!r} "
        f"then {body2!r}"
    )
    assert json.loads(body1)["version"] == v1, (
        f"expected the backend's {v1!r} to be cached, got {body1!r}"
    )

    # Change the BACKEND and redeploy it. The front API is not touched at all.
    _backend_route(ctx, ag, backend_id, backend_resource, v2)
    new_backend_deployment = _retry_throttled(lambda: ag.create_deployment(
        restApiId=backend_id, stageName="b"))["id"]
    assert new_backend_deployment != backend_deployment, (
        f"the backend redeploy must mint a new deployment, got "
        f"{new_backend_deployment!r} == {backend_deployment!r}"
    )
    # Control: the backend really is serving the new body now, directly and uncached.
    _bs, backend_now = _poll_body(
        backend_url, lambda s, t: s == 200 and v2 in t, timeout_s=180.0,
        description=f"the BACKEND itself to serve {v2!r} after its redeploy",
    )
    assert json.loads(backend_now)["version"] == v2, (
        f"the configuration underneath the cache really must have changed; the backend "
        f"returned {backend_now!r}"
    )

    _s3, body3 = _http("GET", front_url)
    assert json.loads(body3)["version"] == v1, (
        f"the stage cache must keep serving the stale {v1!r} while the backend already "
        f"returns {v2!r}, got {body3!r}"
    )

    _retry_throttled(lambda: ag.flush_stage_cache(restApiId=front_id, stageName="test"))
    _s4, body4 = _poll_body(
        front_url, lambda s, t: s == 200 and v2 in t, timeout_s=180.0,
        description=f"GET {front_url} to serve {v2!r} after FlushStageCache",
    )
    assert json.loads(body4)["version"] == v2, (
        f"FlushStageCache must invalidate the entry so the next GET reaches the backend, "
        f"got {body4!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
