"""obs-apigateway-3-per-method-metrics-only-for-the-enabled-method."""

# The patch path for resource `/ok` escapes the slash (`/~1ok/GET/metrics/enabled`) and GetStage
# reports it under methodSettings key `~1ok/GET`. A MOCK integration emits no IntegrationLatency,
# so both methods proxy over HTTP to a second backend API (whose metrics carry another ApiName).
from __future__ import annotations

import datetime
import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "obs-apigateway-3-per-method-metrics-only-for-the-enabled-method"
GROUP = "observability"
SERVICES = ["apigateway", "cloudwatch"]

_NAMESPACE = "AWS/ApiGateway"
_METRIC_DEADLINE_S = 480.0
_LIST_DEADLINE_S = 480.0
_PROPAGATION_S = 150.0
_QUIET_BEFORE_S = 65.0
_SETTLE_AFTER_S = 15.0
_WARMUP_INTERVAL_S = 5.0
_OK_CALLS = 10
_OTHER_CALLS = 6
# Every metric API Gateway publishes for a REST API with no cache, as ListMetrics reported it.
_EXPECTED_METRICS = frozenset({"4XXError", "5XXError", "Count", "IntegrationLatency", "Latency"})


# ===== helpers (self-contained) =====
def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, budget_s=90.0):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff for up to
    `budget_s`.

    The apigateway control plane rate-limits mutating calls per account (DeleteRestApi is the
    tightest) and the pool is shared, so a sibling suite's burst can surface as a throttle
    unrelated to the claim — and a teardown that gives up early leaks the API."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + budget_s
    attempt = 0
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(min(8.0, 0.25 * (2 ** attempt)) + random.uniform(0, 0.5))
            attempt += 1


def _rest_api(ctx, ag, name):
    """A REGIONAL REST API, its teardown registered at once."""
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=name, description=f"sim2real {CHECK}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK}))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_rest_api(restApiId=api_id), budget_s=180.0))
    return api_id


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"root ('/') resource not found on restApiId={api_id!r}")


def _child(ag, api_id, path_part):
    """A child resource off root. Deleted with its API (teardown registered by _rest_api)."""
    return _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part))["id"]


def _mock_get(ag, api_id, resource_id, marker):
    """A GET method with a MOCK integration returning `marker` on 200."""
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"marker":"%s"}' % marker}))


def _proxy_get(ag, api_id, resource_id, backend_url):
    """A GET method proxied (HTTP_PROXY) to `backend_url` — a real integration hop, so the
    method has an IntegrationLatency to report."""
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="HTTP_PROXY",
        integrationHttpMethod="GET", uri=backend_url))


def _deploy_stage(ag, api_id, stage):
    """Deploy the API to a new stage (deleted with its API)."""
    deployment = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment,
        tags={"sim2real": CHECK}))


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage. Transport/hostname only."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


class _Counter:
    """Counts every HTTP request this check sends to the FRONTEND stage, per path.

    The API- and stage-level expectations are DERIVED from this counter rather than pinned,
    because the servability poll and the warm-up make an unpredictable number of requests."""

    def __init__(self):
        self.total = 0
        self.by_path = {}

    def get(self, url, path, timeout=20.0):
        req = urllib.request.Request(url, method="GET")
        self.total += 1
        self.by_path[path] = self.by_path.get(path, 0) + 1
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(errors="replace")


def _dims(pairs):
    return [{"Name": k, "Value": v} for k, v in pairs]


def _stat(cw, metric_name, dimensions, start, statistic, *, pad=True):
    """One statistic of one AWS/ApiGateway metric over 1-minute periods: (sum, datapoints).

    `pad=False` reads from `start` EXACTLY — used only with a minute-aligned `start`."""
    resp = cw.get_metric_statistics(
        Namespace=_NAMESPACE, MetricName=metric_name, Dimensions=_dims(dimensions),
        StartTime=start - datetime.timedelta(minutes=3) if pad else start,
        EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=3),
        Period=60, Statistics=[statistic],
    )
    points = resp["Datapoints"]
    return sum(point[statistic] for point in points), points


def _poll_stat_to(cw, metric_name, dimensions, start, target, *, pad=True):
    """Poll a SampleCount until it reaches `target` or the deadline; return the last read."""
    deadline = time.monotonic() + _METRIC_DEADLINE_S
    while True:
        total, points = _stat(cw, metric_name, dimensions, start, "SampleCount", pad=pad)
        if total >= target or time.monotonic() >= deadline:
            return total, points
        time.sleep(15.0)


def _quiet_period_boundary(last_request):
    """Return the first 1-minute period boundary at least `_QUIET_BEFORE_S` after
    `last_request`, having waited until `_SETTLE_AFTER_S` past it.

    API Gateway does NOT bucket a request by its wall-clock minute: requests sent at :10 and :50
    land in their own minute, those sent at :57 and :59 in the NEXT one — so its buckets are offset
    by an amount between 3s and 10s. A boundary with only a few seconds' margin therefore lets a
    request from before it land in the period after it (the count then exceeds what was sent). So
    the method under count stays QUIET for over a minute before the boundary (covers any offset
    below 60s) and counted traffic starts well after it (covers an offset as low as -10s). There is
    no state to poll for: the clock is the condition, so this sleep IS the wait."""
    earliest = last_request + datetime.timedelta(seconds=_QUIET_BEFORE_S)
    boundary = earliest.replace(second=0, microsecond=0)
    if boundary < earliest:
        boundary += datetime.timedelta(minutes=1)
    settle_at = boundary + datetime.timedelta(seconds=_SETTLE_AFTER_S)
    time.sleep(max(0.0, (settle_at - datetime.datetime.now(datetime.timezone.utc))
                   .total_seconds()))
    return boundary


def _combos(cw, api_name):
    """ListMetrics filtered to Dimensions=[ApiName=<this run's api>], paginated, as
    {frozenset(dimension pairs): set(metric names)}."""
    out = {}
    paginator = cw.get_paginator("list_metrics")
    for page in paginator.paginate(Namespace=_NAMESPACE,
                                   Dimensions=[{"Name": "ApiName", "Value": api_name}]):
        for metric in page["Metrics"]:
            key = frozenset((d["Name"], d["Value"]) for d in metric["Dimensions"])
            out.setdefault(key, set()).add(metric["MetricName"])
    return out


def _show(combos):
    return sorted((sorted(k), sorted(v)) for k, v in combos.items())
# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-metrics-and-dimensions.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:metrics",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """Detailed metrics on one method (`/~1ok/GET/metrics/enabled`) yield an exact per-method Count
    for `/ok` only and none for `/other`; API- and stage-level Counts equal all requests on both,
    and ListMetrics for this ApiName lists exactly those three combinations."""
    ag = ctx.client("apigateway")
    cw = ctx.client("cloudwatch")
    marker = f"sim2real-{_unique_token()}"

    # ---- backend: a MOCK REST API the frontend proxies to ------------------------------
    backend_id = _rest_api(ctx, ag, ctx.unique_name("sim2real-behav-apigw-be-"))
    pong = _child(ag, backend_id, "pong")
    _mock_get(ag, backend_id, pong, marker)
    backend_stage = f"b{_unique_token()}"
    _deploy_stage(ag, backend_id, backend_stage)
    backend_url = _apigw_url(ctx, backend_id, backend_stage, "/pong")

    # ---- frontend: exactly two GET methods, detailed metrics on /ok/GET only -----------
    api_name = ctx.unique_name("sim2real-behav-apigw-")
    api_id = _rest_api(ctx, ag, api_name)
    for part in ("ok", "other"):
        _proxy_get(ag, api_id, _child(ag, api_id, part), backend_url)
    stage = f"s{_unique_token()}"
    _deploy_stage(ag, api_id, stage)

    methods = sorted(
        (item["path"], verb)
        for item in ag.get_resources(restApiId=api_id)["items"]
        for verb in (item.get("resourceMethods") or {})
    )
    assert methods == [("/ok", "GET"), ("/other", "GET")], (
        f"precondition: the frontend API must have exactly two methods, GET /ok and GET "
        f"/other, got {methods!r}"
    )

    _retry_throttled(lambda: ag.update_stage(
        restApiId=api_id, stageName=stage,
        patchOperations=[{"op": "replace", "path": "/~1ok/GET/metrics/enabled",
                          "value": "true"}]))
    settings = ag.get_stage(restApiId=api_id, stageName=stage).get("methodSettings") or {}
    assert set(settings) == {"~1ok/GET"} and settings["~1ok/GET"].get("metricsEnabled") is True, (
        f"expected GetStage to report exactly one method setting, '~1ok/GET' with "
        f"metricsEnabled=True (no '*/*' and no '~1other/GET'), got methodSettings={settings!r}"
    )

    ok_url = _apigw_url(ctx, api_id, stage, "/ok")
    other_url = _apigw_url(ctx, api_id, stage, "/other")
    counter = _Counter()
    window_start = datetime.datetime.now(datetime.timezone.utc)

    # Servability through BOTH hops (frontend stage -> backend stage), polled on /other so the
    # unpredictable attempt count never touches the per-method series under exact assertion.
    deadline = time.monotonic() + _PROPAGATION_S
    while True:
        status, text = counter.get(other_url, "/other")
        if status == 200 and marker in text:
            break
        assert time.monotonic() < deadline, (
            f"GET {other_url} did not return 200 with the backend marker {marker!r} within "
            f"{_PROPAGATION_S}s; last=(status={status}, body={text[:200]!r})"
        )
        time.sleep(4.0)

    ok_dims = [("ApiName", api_name), ("Method", "GET"), ("Resource", "/ok"), ("Stage", stage)]
    other_dims = [("ApiName", api_name), ("Method", "GET"), ("Resource", "/other"),
                  ("Stage", stage)]
    api_dims = [("ApiName", api_name)]
    stage_dims = [("ApiName", api_name), ("Stage", stage)]

    # ---- warm-up: until the /ok setting is OBSERVED live in CloudWatch -----------------
    deadline = time.monotonic() + _METRIC_DEADLINE_S
    while True:
        for url, path in ((ok_url, "/ok"), (other_url, "/other")):
            status, text = counter.get(url, path)
            assert status == 200 and marker in text, (
                f"expected 200 with marker {marker!r} from {url} during warm-up, got "
                f"{status} body {text[:200]!r}"
            )
        warm_seen, warm_points = _stat(cw, "Count", ok_dims, window_start, "SampleCount")
        if warm_seen > 0 or time.monotonic() >= deadline:
            break
        time.sleep(_WARMUP_INTERVAL_S)
    last_warmup = datetime.datetime.now(datetime.timezone.utc)
    assert 0 < warm_seen <= counter.by_path["/ok"], (
        f"expected the per-method Count series on {ok_dims!r} to appear for the method whose "
        f"detailed metrics were enabled, carrying at most the {counter.by_path['/ok']} /ok "
        f"call(s) made, got {warm_seen} within {_METRIC_DEADLINE_S}s (datapoints "
        f"{json.dumps(warm_points, default=str)[:200]})"
    )

    # ---- the counted window: exactly _OK_CALLS on /ok after a quiet period boundary ----
    counted_start = _quiet_period_boundary(last_warmup)
    for i in range(max(_OK_CALLS, _OTHER_CALLS)):
        if i < _OK_CALLS:
            status, text = counter.get(ok_url, "/ok")
            assert status == 200 and marker in text, (
                f"expected 200 with marker {marker!r} from {ok_url}, got {status} body "
                f"{text[:200]!r}"
            )
        if i < _OTHER_CALLS:
            status, text = counter.get(other_url, "/other")
            assert status == 200 and marker in text, (
                f"expected 200 with marker {marker!r} from {other_url}, got {status} body "
                f"{text[:200]!r}"
            )
    total = counter.total

    ok_count, ok_points = _poll_stat_to(cw, "Count", ok_dims, counted_start, _OK_CALLS,
                                        pad=False)
    assert ok_count == _OK_CALLS, (
        f"expected Count on {ok_dims!r}, read from the period boundary "
        f"{counted_start.isoformat()}, to be exactly the {_OK_CALLS} /ok requests sent after it, "
        f"got {ok_count} within {_METRIC_DEADLINE_S}s (datapoints "
        f"{json.dumps(ok_points, default=str)[:300]})"
    )
    assert all(p.get("Unit") == "Count" for p in ok_points), (
        f"expected every per-method Count datapoint in Unit 'Count', got "
        f"{sorted({p.get('Unit') for p in ok_points})!r}"
    )

    api_count, api_points = _poll_stat_to(cw, "Count", api_dims, window_start, total)
    assert api_count == total, (
        f"expected Count on {api_dims!r} (ApiName alone) to equal the {total} requests sent "
        f"to the stage on both methods ({counter.by_path!r}), got {api_count} (datapoints "
        f"{json.dumps(api_points, default=str)[:300]})"
    )
    stage_count, stage_points = _poll_stat_to(cw, "Count", stage_dims, window_start, total)
    assert stage_count == total, (
        f"expected Count on {stage_dims!r} (ApiName, Stage) to equal the {total} requests sent "
        f"on both methods ({counter.by_path!r}), got {stage_count} (datapoints "
        f"{json.dumps(stage_points, default=str)[:300]})"
    )

    # ---- the withheld series: /other was served throughout and never published --------
    other_count, other_points = _stat(cw, "Count", other_dims, window_start, "SampleCount")
    assert other_count == 0 and other_points == [], (
        f"expected NO per-method Count datapoints on {other_dims!r} — detailed metrics were "
        f"never enabled for GET /other, though it served {counter.by_path['/other']} requests "
        f"in the same window /ok's series arrived in — got a total of {other_count} over "
        f"{json.dumps(other_points, default=str)[:300]}"
    )

    # ---- units ----------------------------------------------------------------------
    for metric in ("Latency", "IntegrationLatency"):
        for dims in (api_dims, ok_dims):
            _, points = _stat(cw, metric, dims, window_start, "Average")
            units = sorted({p.get("Unit") for p in points})
            assert points and units == ["Milliseconds"], (
                f"expected {metric} on {dims!r} to have datapoints, every one in Unit "
                f"'Milliseconds', got units {units!r} over {len(points)} datapoint(s)"
            )

    # ---- the catalogue: exactly three dimension combinations under this ApiName -----------
    expected = {
        frozenset(api_dims): _EXPECTED_METRICS,
        frozenset(stage_dims): _EXPECTED_METRICS,
        frozenset(ok_dims): _EXPECTED_METRICS,
    }
    deadline = time.monotonic() + _LIST_DEADLINE_S
    while True:
        listed = _combos(cw, api_name)
        complete = all(listed.get(k, set()) >= v for k, v in expected.items())
        if complete or time.monotonic() >= deadline:
            break
        time.sleep(15.0)
    assert listed == expected, (
        f"expected ListMetrics(Dimensions=[ApiName={api_name!r}]) to list exactly the "
        f"{{ApiName}}, {{ApiName, Stage}} and {{ApiName, Method=GET, Resource=/ok, Stage}} "
        f"combinations, each carrying {sorted(_EXPECTED_METRICS)!r}, got {_show(listed)!r} "
        f"(complete={complete} after up to {_LIST_DEADLINE_S}s) — an extra combination with "
        f"Resource=/other is the per-method setting leaking to a method it was never set on"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
