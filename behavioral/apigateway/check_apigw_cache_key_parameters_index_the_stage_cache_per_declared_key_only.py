"""apigw-cache-key-parameters-index-the-stage-cache-per-declared-key-only."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-cache-key-parameters-index-the-stage-cache-per-declared-key-only"
GROUP = "deployments-stages"
SERVICES = ["apigateway"]

_CACHE_SIZE = "0.5"
_TTL_S = 300
_CLUSTER_S = 900.0              # AWS documents up to 4 minutes for the cluster to provision
_HIT_WINDOW_S = 120.0           # caching is best-effort, so a hit is polled for, bounded
_PROPAGATION_S = 150.0


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account."""
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


def _await_cache_available(ag, api_id, stage):
    """Bounded poll for cacheClusterStatus == AVAILABLE; RAISES on the deadline.

    A cluster that never provisions is a FAIL, never a skip."""
    deadline = time.monotonic() + _CLUSTER_S
    last = None
    while time.monotonic() < deadline:
        last = ag.get_stage(restApiId=api_id, stageName=stage).get("cacheClusterStatus")
        if last == "AVAILABLE":
            return last
        time.sleep(2)
    raise AssertionError(
        f"the {_CACHE_SIZE}GB cache cluster never became AVAILABLE within {_CLUSTER_S}s; "
        f"last cacheClusterStatus was {last!r}"
    )


def _backend_id_of(text):
    """The backend's per-hit identifier, lifted out of the front API's body."""
    data = json.loads(text)
    if "backend" not in data:
        raise AssertionError(
            f"the front API's response template must render a 'backend' field carrying the "
            f"backend's per-hit id; got {data!r}"
        )
    value = data["backend"]
    if not value:
        raise AssertionError(f"the backend id must be non-empty; got {value!r} in {data!r}")
    return value


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A stage cache is keyed only by `cacheKeyParameters`: an undeclared query parameter hits the
    existing entry, the declared one misses, and FlushStageCache sends the original to the backend.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html
    """
    ag = ctx.client("apigateway")

    # ---- backend API: a new identifier on every hit ------------------------------------
    backend_id = _create_api(ctx, ag, "cache-key-parameters-backend")
    backend_res = _child(ctx, ag, backend_id, "vary")
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
        responseTemplates={"application/json": '{"hit":"$context.extendedRequestId"}'}))
    backend_deployment = _retry_throttled(
        lambda: ag.create_deployment(restApiId=backend_id))["id"]
    backend_stage = f"s{_unique_token()}"
    _retry_throttled(lambda: ag.create_stage(
        restApiId=backend_id, stageName=backend_stage, deploymentId=backend_deployment,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=backend_id, stageName=backend_stage)))
    backend_url = _apigw_url(ctx, backend_id, backend_stage, "/vary").rstrip("/")

    # Precondition, not the claim: the backend really does answer differently every time, so
    # equality downstream can only mean a cache.
    _poll_http(backend_url, lambda s, h, t: s == 200 and "hit" in t,
               description=f"GET {backend_url} to serve the backend's per-hit id")
    b_first = json.loads(_http("GET", backend_url)[2])["hit"]
    b_second = json.loads(_http("GET", backend_url)[2])["hit"]
    assert b_first != b_second, (
        f"precondition: the uncached backend must answer with a NEW id on every hit, "
        f"otherwise cache equality below proves nothing; got {b_first!r} twice"
    )

    # ---- front API: caches, keyed on `k` only ------------------------------------------
    front_id = _create_api(ctx, ag, "cache-key-parameters-front")
    front_res = _child(ctx, ag, front_id, "vary")
    _retry_throttled(lambda: ag.put_method(
        restApiId=front_id, resourceId=front_res, httpMethod="GET",
        authorizationType="NONE",
        requestParameters={"method.request.querystring.k": True,
                           "method.request.querystring.other": False}))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=front_id, resourceId=front_res, httpMethod="GET", type="HTTP",
        integrationHttpMethod="GET", uri=backend_url,
        cacheKeyParameters=["method.request.querystring.k"]))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=front_id, resourceId=front_res, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=front_id, resourceId=front_res, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json":
                           '{"backend":"$input.path(\'$.hit\')"}'}))

    stored = ag.get_integration(restApiId=front_id, resourceId=front_res, httpMethod="GET")
    assert stored.get("cacheKeyParameters") == ["method.request.querystring.k"], (
        f"expected GetIntegration to report exactly the declared cache key "
        f"['method.request.querystring.k'], got {stored.get('cacheKeyParameters')!r}"
    )

    front_deployment = _retry_throttled(
        lambda: ag.create_deployment(restApiId=front_id))["id"]
    front_stage = f"s{_unique_token()}"
    _retry_throttled(lambda: ag.create_stage(
        restApiId=front_id, stageName=front_stage, deploymentId=front_deployment,
        cacheClusterEnabled=True, cacheClusterSize=_CACHE_SIZE,
        tags={"sim2real": CHECK}))
    # Registered HERE, before the multi-minute AVAILABLE poll: an orphaned cache cluster
    # bills for as long as it exists.
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=front_id, stageName=front_stage)))
    _retry_throttled(lambda: ag.update_stage(
        restApiId=front_id, stageName=front_stage,
        patchOperations=[
            {"op": "replace", "path": "/~1vary/GET/caching/enabled", "value": "true"},
            {"op": "replace", "path": "/~1vary/GET/caching/ttlInSeconds",
             "value": str(_TTL_S)},
        ]))
    cluster_status = _await_cache_available(ag, front_id, front_stage)
    assert cluster_status == "AVAILABLE", (
        f"expected cacheClusterStatus AVAILABLE before probing the cache, got "
        f"{cluster_status!r}"
    )

    front_base = _apigw_url(ctx, front_id, front_stage, "/vary")
    url_a1 = f"{front_base}?k=alpha&other=1"
    url_a2 = f"{front_base}?k=alpha&other=2"      # undeclared param differs
    url_b1 = f"{front_base}?k=beta&other=1"       # declared param differs
    url_b9 = f"{front_base}?k=beta&other=9"

    # ---- populate the alpha entry, and poll for a HIT on it -----------------------------
    _poll_http(url_a1, lambda s, h, t: s == 200 and "backend" in t,
               description=f"GET {url_a1} to be served by the cached front stage")
    # Two consecutive identical GETs returning the same backend id is the cache HIT. Bounded
    # by a deadline and a FAIL on expiry; the baseline is re-taken each round because until
    # the entry settles every request is a miss with a new id.
    baseline = _backend_id_of(_http("GET", url_a1)[2])
    hit_observed = False
    last_pair = None
    deadline = time.monotonic() + _HIT_WINDOW_S
    while time.monotonic() < deadline:
        probe = _backend_id_of(_http("GET", url_a1)[2])
        last_pair = (baseline, probe)
        if probe == baseline:
            hit_observed = True
            break
        baseline = probe
        time.sleep(5.0)
    assert hit_observed, (
        f"no cache HIT observed within {_HIT_WINDOW_S}s: consecutive identical GETs of "
        f"{url_a1} kept returning different backend ids (last pair {last_pair!r}). Caching is "
        f"best-effort but a stage with a provisioned, AVAILABLE cluster and caching enabled "
        f"must eventually serve a repeat from cache"
    )
    cached_value = baseline

    # ---- the claim: an UNDECLARED parameter does not create a new cache entry -----------
    a2 = _backend_id_of(_http("GET", url_a2)[2])
    assert a2 == cached_value, (
        f"expected ?k=alpha&other=2 to be served the SAME cache entry as ?k=alpha&other=1 "
        f"because 'other' is not in cacheKeyParameters: expected backend id {cached_value!r}, got "
        f"{a2!r} — a different id means the cache is keyed on the whole URI"
    )

    # ---- the twin, same instant: the DECLARED parameter does create a new entry ---------
    b1 = _backend_id_of(_http("GET", url_b1)[2])
    assert b1 != cached_value, (
        f"expected ?k=beta to MISS the alpha cache entry and reach the backend, because 'k' "
        f"IS in cacheKeyParameters: got the alpha entry's backend id {cached_value!r} again — a "
        f"cache that keys on the path alone would serve one caller's data to another"
    )
    b9 = _backend_id_of(_http("GET", url_b9)[2])
    assert b9 == b1, (
        f"expected ?k=beta&other=9 to be served the beta cache entry {b1!r} (only 'k' is a "
        f"cache key), got {b9!r}"
    )

    # ---- attribution: flushing the cache must free the ORIGINAL request -----------------
    _retry_throttled(lambda: ag.flush_stage_cache(
        restApiId=front_id, stageName=front_stage))
    flushed = _poll_http(
        url_a1, lambda s, h, t: s == 200 and _backend_id_of(t) != cached_value,
        description=(
            f"GET {url_a1} to reach the backend again after FlushStageCache, proving the "
            f"three equal answers above came from the cache and not from a constant backend"
        ),
    )[2]
    assert _backend_id_of(flushed) != cached_value, (
        f"expected a NEW backend id for {url_a1} after FlushStageCache, still got {cached_value!r} "
        f"— without this the equalities above are consistent with a backend that never varies"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
