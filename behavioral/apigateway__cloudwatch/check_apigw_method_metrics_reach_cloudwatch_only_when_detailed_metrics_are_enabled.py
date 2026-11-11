"""apigw-method-metrics-reach-cloudwatch-only-when-detailed-metrics-are-enabled."""
from __future__ import annotations

import datetime
import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-method-metrics-reach-cloudwatch-only-when-detailed-metrics-are-enabled"
GROUP = "observability"
SERVICES = ["apigateway", "cloudwatch"]

_NAMESPACE = "AWS/ApiGateway"
_METRIC_DEADLINE_S = 480.0
_PROPAGATION_S = 150.0
_OK_CALLS = 5
_DENIED_CALLS = 3
_STAGE_CATCHUP_S = 240.0


# ===== helpers (self-contained) =====
def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account, so
    other activity in the same account can surface as a throttle unrelated to the claim."""
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


def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)))
    return resource_id


def _mock_get(ag, api_id, resource_id, marker, *, api_key_required=False):
    """A GET method with a MOCK integration returning `marker` on 200."""
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="NONE", apiKeyRequired=api_key_required))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"marker":"%s"}' % marker}))


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage. Transport/hostname only."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


class _Counter:
    """Counts every HTTP request this check sends to the stage, and how many were 4xx.

    The expected metric values are DERIVED from this counter rather than pinned, because the
    servability poll below makes an unpredictable number of requests (the expectation
    comes from what this run measured, not from a constant)."""

    def __init__(self):
        self.total = 0
        self.four_xx = 0

    def get(self, url, headers=None, timeout=20.0):
        req = urllib.request.Request(url, method="GET", headers=headers or {})
        self.total += 1
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                status, text = resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as exc:
            status, text = exc.code, exc.read().decode(errors="replace")
        if 400 <= status < 500:
            self.four_xx += 1
        return status, text

    def poll(self, url, predicate, *, timeout_s=_PROPAGATION_S, interval_s=4.0,
             description="stage response"):
        """Bounded retry; RAISES on the deadline. Every attempt is counted."""
        deadline = time.monotonic() + timeout_s
        while True:
            status, text = self.get(url)
            if predicate(status, text):
                return status, text
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not observed within {timeout_s}s; "
                    f"last=(status={status}, body={text[:200]!r})"
                )
            time.sleep(interval_s)


def _sum_stat(cw, metric_name, dimensions, start, statistic):
    """Sum one statistic of one AWS/ApiGateway metric over 1-minute periods."""
    resp = cw.get_metric_statistics(
        Namespace=_NAMESPACE, MetricName=metric_name,
        Dimensions=[{"Name": k, "Value": v} for k, v in dimensions],
        StartTime=start - datetime.timedelta(minutes=3),
        EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=3),
        Period=60, Statistics=[statistic],
    )
    return sum(point[statistic] for point in resp["Datapoints"]), resp["Datapoints"]


def _series_total(cw, metric_name, dimensions, start, stat):
    """The same total through GetMetricData — a DIFFERENT operation, so absence is observed
    on two independent read paths rather than one."""
    resp = cw.get_metric_data(
        MetricDataQueries=[{
            "Id": "q1",
            "MetricStat": {
                "Metric": {
                    "Namespace": _NAMESPACE, "MetricName": metric_name,
                    "Dimensions": [{"Name": k, "Value": v} for k, v in dimensions],
                },
                "Period": 60, "Stat": stat,
            },
            "ReturnData": True,
        }],
        StartTime=start - datetime.timedelta(minutes=3),
        EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=3),
    )
    results = resp["MetricDataResults"]
    if not results:
        raise AssertionError(
            f"GetMetricData returned no MetricDataResults at all for {metric_name} "
            f"{dimensions!r}; it must return one result per query even when empty"
        )
    values = results[0]["Values"]
    return sum(values), values
# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-metrics-and-dimensions.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """Real HTTP traffic through a REST API stage lands in `AWS/ApiGateway` as an exact request
    and 4xx count on (ApiName, Stage), while (ApiName, Method, Resource, Stage) stays empty until
    `metricsEnabled` is turned on and then carries exactly the calls made after that."""
    ag = ctx.client("apigateway")
    cw = ctx.client("cloudwatch")
    marker = f"sim2real-{_unique_token()}"

    api_name = ctx.unique_name("sim2real-behav-apigw-")
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=api_name, description=f"sim2real {CHECK}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK}))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))

    ok_res = _child(ctx, ag, api_id, "ok")
    denied_res = _child(ctx, ag, api_id, "denied")
    _mock_get(ag, api_id, ok_res, marker)
    # apiKeyRequired with no key sent is a deterministic, ROUTED 403 — so it is attributed to
    # this API and stage, unlike an unrouted path.
    _mock_get(ag, api_id, denied_res, marker, api_key_required=True)

    stage = f"s{_unique_token()}"
    deployment = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage)))

    fresh = ag.get_stage(restApiId=api_id, stageName=stage)
    default_settings = (fresh.get("methodSettings") or {}).get("*/*") or {}
    assert not default_settings.get("metricsEnabled"), (
        f"precondition: a stage created without methodSettings must start with detailed "
        f"metrics OFF, but GetStage reported methodSettings={fresh.get('methodSettings')!r}"
    )

    ok_url = _apigw_url(ctx, api_id, stage, "/ok")
    denied_url = _apigw_url(ctx, api_id, stage, "/denied")
    counter = _Counter()
    window_start = datetime.datetime.now(datetime.timezone.utc)

    counter.poll(
        ok_url, lambda s, t: s == 200 and marker in t,
        description=f"GET {ok_url} to become servable and return marker {marker!r}",
    )
    for _ in range(_OK_CALLS):
        status, text = counter.get(ok_url)
        assert status == 200 and marker in text, (
            f"expected 200 with marker {marker!r} from {ok_url} while driving traffic, got "
            f"{status} body {text[:200]!r}"
        )
    for _ in range(_DENIED_CALLS):
        status, text = counter.get(denied_url)
        assert status == 403, (
            f"expected 403 from {denied_url} (apiKeyRequired, no x-api-key sent) so the run "
            f"produces a known number of 4xx responses, got {status} body {text[:200]!r}"
        )
    expected_total = counter.total
    expected_4xx = counter.four_xx
    # A lower bound, not an equality: a freshly deployed stage can legitimately 4xx during
    # the servability poll, and those requests count too. The metric expectation below is the
    # MEASURED counter, so it stays exact either way.
    assert expected_4xx >= _DENIED_CALLS, (
        f"the counter must have recorded at least the {_DENIED_CALLS} deliberate "
        f"apiKeyRequired refusals, got {expected_4xx}"
    )

    stage_dims = [("ApiName", api_name), ("Stage", stage)]
    method_dims = [("ApiName", api_name), ("Method", "GET"), ("Resource", "/ok"),
                   ("Stage", stage)]

    # ---- the demonstrated control: stage-level Count, and the latency L it took ---------
    t_calib = time.monotonic()
    deadline = time.monotonic() + _METRIC_DEADLINE_S
    observed, points = 0, []
    while time.monotonic() < deadline:
        observed, points = _sum_stat(cw, "Count", stage_dims, window_start, "SampleCount")
        if observed >= expected_total:
            break
        time.sleep(15.0)
    latency_s = time.monotonic() - t_calib
    sum_stat, _ = _sum_stat(cw, "Count", stage_dims, window_start, "Sum")
    assert observed == expected_total, (
        f"expected AWS/ApiGateway Count on {stage_dims!r} to sum (SampleCount) to exactly "
        f"{expected_total} — the number of HTTP requests this run sent to the stage — got "
        f"{observed} within {_METRIC_DEADLINE_S}s (Sum statistic was {sum_stat}; datapoints "
        f"{json.dumps(points, default=str)[:200]})"
    )
    errors, error_points = _sum_stat(cw, "4XXError", stage_dims, window_start, "Sum")
    assert errors == expected_4xx, (
        f"expected AWS/ApiGateway 4XXError on {stage_dims!r} to sum to exactly "
        f"{expected_4xx} (the deliberate apiKeyRequired refusals), got {errors} (datapoints "
        f"{json.dumps(error_points, default=str)[:200]})"
    )

    # ---- the withheld series: absent while metricsEnabled is off ------------------------
    # Bounded by the control's own measured latency: the two dimension sets are published by
    # the same pipeline, so if the per-method series were being emitted it would have arrived
    # by now. Held for >= 2L, floored so a very fast account still gets a real window.
    window_s = min(max(2.0 * latency_s, 60.0), 240.0)
    absence_deadline = time.monotonic() + window_s
    samples = 0
    while time.monotonic() < absence_deadline:
        withheld, withheld_points = _sum_stat(cw, "Count", method_dims, window_start,
                                              "SampleCount")
        assert withheld == 0, (
            f"expected NO per-method Count datapoints on {method_dims!r} while detailed "
            f"metrics are off, got a total of {withheld} after {samples} clean sample(s) "
            f"(datapoints {json.dumps(withheld_points, default=str)[:200]}) — publishing the "
            f"detailed dimension set unconditionally is a real divergence, and a billed one"
        )
        samples += 1
        time.sleep(min(10.0, max(1.0, absence_deadline - time.monotonic())))
    assert samples >= 2, (
        f"the absence window took too few samples to be meaningful: {samples} (window "
        f"{window_s:.1f}s, measured control latency {latency_s:.1f}s)"
    )
    # Second, independent read path for the same absence.
    md_total, md_values = _series_total(cw, "Count", method_dims, window_start, "SampleCount")
    assert md_total == 0, (
        f"GetMetricData must agree with GetMetricStatistics that the per-method series is "
        f"empty while detailed metrics are off; it returned a total of {md_total} over values "
        f"{md_values[:10]!r}"
    )

    # ---- turn it on and DEMAND the withheld series -------------------------------------
    _retry_throttled(lambda: ag.update_stage(
        restApiId=api_id, stageName=stage,
        patchOperations=[{"op": "replace", "path": "/*/*/metrics/enabled",
                          "value": "true"}]))
    enabled = ag.get_stage(restApiId=api_id, stageName=stage)
    assert ((enabled.get("methodSettings") or {}).get("*/*") or {}).get("metricsEnabled") \
        is True, (
            f"expected GetStage to report metricsEnabled=True on the '*/*' method setting "
            f"after the patch, got methodSettings={enabled.get('methodSettings')!r}"
        )

    # The stage setting reaches the serving path only after a lag nothing reports, so traffic
    # repeats until the per-method series appears; every datapoint must come from a call made
    # after enabling.
    enabled_from = counter.total
    detailed_start = datetime.datetime.now(datetime.timezone.utc)
    deadline = time.monotonic() + _METRIC_DEADLINE_S
    detailed, detailed_points = 0, []
    while True:
        status, text = counter.get(ok_url)
        assert status == 200 and marker in text, (
            f"expected 200 with marker {marker!r} from {ok_url} after enabling detailed "
            f"metrics, got {status} body {text[:200]!r}"
        )
        detailed, detailed_points = _sum_stat(cw, "Count", method_dims, detailed_start,
                                              "SampleCount")
        if detailed > 0 or time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    sent_after = counter.total - enabled_from
    assert 0 < detailed <= sent_after, (
        f"expected the per-method Count series on {method_dims!r} to appear once detailed "
        f"metrics are enabled, carrying at most the {sent_after} calls made after enabling, "
        f"got {detailed} within {_METRIC_DEADLINE_S}s (datapoints "
        f"{json.dumps(detailed_points, default=str)[:200]}) — 0 here means the negative above "
        f"was satisfied by a target with no delivery path at all"
    )

    # ListMetrics registers a new metric some minutes after its first datapoint.
    deadline = time.monotonic() + _STAGE_CATCHUP_S
    while True:
        listed = cw.list_metrics(
            Namespace=_NAMESPACE, MetricName="Count",
            Dimensions=[{"Name": k, "Value": v} for k, v in method_dims])["Metrics"]
        if listed or time.monotonic() >= deadline:
            break
        time.sleep(15.0)
    assert listed, (
        f"expected ListMetrics to register the per-method Count metric for {method_dims!r} "
        f"once it has datapoints, got no metrics — a datapoint whose metric is not listed "
        f"cannot be found by an alarm or a dashboard"
    )

    # The stage-level series must have advanced by exactly the calls made after enabling: the
    # detailed set must not double-count or replace the aggregate one.
    deadline = time.monotonic() + _STAGE_CATCHUP_S
    while True:
        stage_after, stage_after_points = _sum_stat(cw, "Count", stage_dims, window_start,
                                                   "SampleCount")
        if stage_after >= counter.total or time.monotonic() >= deadline:
            break
        time.sleep(15.0)
    assert stage_after == counter.total, (
        f"expected the (ApiName, Stage) Count series to total {counter.total} — every request "
        f"this run sent — after the detailed series was enabled, got {stage_after} "
        f"(datapoints {json.dumps(stage_after_points, default=str)[:200]}); enabling the "
        f"per-method dimension set must neither replace nor double-count the aggregate"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
