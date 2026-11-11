"""obs-apigateway-1-cache-hit-miss-metrics-track-flush-uncached-stage-has-none."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-apigateway-1-cache-hit-miss-metrics-track-flush-uncached-stage-has-none"
GROUP = "metrics-and-alarms"
SERVICES = ["apigateway", "cloudwatch", "lambda"]

_CACHE_SIZE = "0.5"
_TTL_S = 300
_N_CTL = 3
_MAX_TRIES = 5

_TAG_KEY = "sim2real"
_NS = "AWS/ApiGateway"

#: Every invocation answers with its own request id, so a response body names the invocation
#: that produced it: a body seen before is a cache hit, a new one is a miss that reached Lambda.
_HANDLER = r'''
def handler(event, context):
    return {"statusCode": 200, "body": "inv-" + context.aws_request_id}
'''


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Bounded retry. RAISES on timeout, quoting the last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _unless_gone(fn):
    """Teardown: a role or function that is already deleted is fine; any other error raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
                raise
    return _wrapped


def _throttled(fn, attempts=12):
    """API Gateway mutating calls are rate limited account-wide; retry only that code."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyRequestsException" or \
                    attempt == attempts - 1:
                raise
            time.sleep(min(10.0, 0.5 * (2 ** attempt)))
    raise AssertionError("unreachable")


def _teardown(fn):
    """Teardown: retry throttles, tolerate NotFound, and raise on anything else."""
    def _wrapped():
        for _ in range(12):
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NotFoundException":
                    return
                if code != "TooManyRequestsException":
                    raise RuntimeError(f"teardown failed: {code}") from exc
                time.sleep(10)
        raise RuntimeError("teardown still throttled after 12 attempts")
    return _wrapped


def _http(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def _lambda(ctx):
    """A python3.12 function whose role has NO logs permissions, so no log group is ever made."""
    iam, lam = ctx.client("iam"), ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-cm-")
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                 "Principal": {"Service": "lambda.amazonaws.com"}}]}),
        Tags=[{"Key": _TAG_KEY, "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_unless_gone(lambda: iam.delete_role(RoleName=name)))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _HANDLER)

    def _create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=10, Tags={_TAG_KEY: CHECK})
        except ClientError as exc:
            # A freshly created role is not assumable for a few seconds (IAM propagation).
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    fn = _poll_until(_create, lambda r: r is not None, timeout_s=90, interval_s=5,
                     description="lambda.create_function accepting the new role")
    ctx.on_cleanup(_unless_gone(lambda: lam.delete_function(FunctionName=name)))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name, fn["FunctionArn"]


def _rest_api(ctx, name):
    apigw = ctx.client("apigateway")
    api_id = _throttled(lambda: apigw.create_rest_api(
        name=name, description=f"sim2real {CHECK}",
        endpointConfiguration={"types": ["REGIONAL"]}, tags={_TAG_KEY: CHECK}))["id"]
    ctx.on_cleanup(_teardown(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root


def _lambda_get(ctx, api_id, root, path_part, fn_arn):
    """GET /<path_part> -> AWS_PROXY lambda."""
    apigw = ctx.client("apigateway")
    res = _throttled(lambda: apigw.create_resource(
        restApiId=api_id, parentId=root, pathPart=path_part))["id"]
    _throttled(lambda: apigw.put_method(restApiId=api_id, resourceId=res, httpMethod="GET",
                                        authorizationType="NONE"))
    _throttled(lambda: apigw.put_integration(
        restApiId=api_id, resourceId=res, httpMethod="GET", type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}"
             f"/invocations")))


def _mock_get(ctx, api_id, root, path_part):
    """GET /<path_part> -> MOCK 200. Readiness traffic goes here so it never reaches Lambda."""
    apigw = ctx.client("apigateway")
    res = _throttled(lambda: apigw.create_resource(
        restApiId=api_id, parentId=root, pathPart=path_part))["id"]
    _throttled(lambda: apigw.put_method(restApiId=api_id, resourceId=res, httpMethod="GET",
                                        authorizationType="NONE"))
    _throttled(lambda: apigw.put_integration(
        restApiId=api_id, resourceId=res, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _throttled(lambda: apigw.put_method_response(
        restApiId=api_id, resourceId=res, httpMethod="GET", statusCode="200"))
    _throttled(lambda: apigw.put_integration_response(
        restApiId=api_id, resourceId=res, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": '{"ready": true}'}))


def _ready_then_align(urls, quiet_s=40, deadline_s=240):
    """Stage propagation is eventual per node, so wait for `quiet_s` of only 200s, keep probing to
    :25-:40 of a UTC minute, and return the next minute; requests in a minute's last ~3 s can be
    counted in the next minute, so the gap keeps readiness traffic out of the measured window."""
    deadline = time.monotonic() + deadline_s
    streak_from = None
    last = None
    while time.monotonic() < deadline:
        last = [(u, _http(u)[0]) for u in urls]
        now = time.monotonic()
        if all(code == 200 for _u, code in last):
            streak_from = streak_from if streak_from is not None else now
        else:
            streak_from = None
        wall = datetime.now(timezone.utc)
        if streak_from is not None and now - streak_from >= quiet_s and 25 <= wall.second <= 40:
            minute = wall.replace(second=0, microsecond=0) + timedelta(minutes=1)
            while datetime.now(timezone.utc) < minute + timedelta(seconds=3):
                time.sleep(0.5)
            return minute
        time.sleep(0.5)
    raise AssertionError(f"no {quiet_s}s window of 200s from {urls!r} within {deadline_s}s; "
                         f"last round {last!r}")


def _dims(**kv):
    return [{"Name": k, "Value": v} for k, v in kv.items()]


def _gms(ctx, ns, metric, dims, start, statistic="Sum"):
    """GetMetricStatistics: (total of `statistic`, datapoint count) from `start` to now+3 min."""
    pts = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=ns, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=3), Period=60,
        Statistics=[statistic])["Datapoints"]
    return sum(p[statistic] for p in pts), len(pts)


def _gmd(ctx, ns, metric, dims, start, statistic="Sum"):
    """GetMetricData over the same window: (total, value count), following NextToken."""
    cw = ctx.client("cloudwatch")
    kw = {"MetricDataQueries": [{"Id": "m", "ReturnData": True, "MetricStat": {
        "Metric": {"Namespace": ns, "MetricName": metric, "Dimensions": dims},
        "Period": 60, "Stat": statistic}}],
        "StartTime": start, "EndTime": datetime.now(timezone.utc) + timedelta(minutes=3)}
    values = []
    while True:
        resp = cw.get_metric_data(**kw)
        for r in resp["MetricDataResults"]:
            values.extend(r["Values"])
        if not resp.get("NextToken"):
            return sum(values), len(values)
        kw["NextToken"] = resp["NextToken"]


def _await_sum(ctx, ns, metric, dims, start, want, timeout_s=300):
    got, _n = _poll_until(lambda: _gms(ctx, ns, metric, dims, start),
                          lambda r: r[0] >= want, timeout_s=timeout_s, interval_s=10,
                          description=f"{metric} Sum {dims!r} reaching {want}")
    return got


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-metrics-and-dimensions.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A cached stage's CacheMissCount / CacheHitCount equal the client-observed misses and hits
    (including the flush-forced miss), Count equals all requests, Lambda Invocations equals misses,
    and an uncached stage of the same API publishes Count but no cache series.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-metrics-and-dimensions.html
    """
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-xsvc-cachem-")
    fn_name, fn_arn = _lambda(ctx)
    fn_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    api_id, root = _rest_api(ctx, api_name)
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId="apigw", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{acct}:{api_id}/*")
    _lambda_get(ctx, api_id, root, "c", fn_arn)
    _mock_get(ctx, api_id, root, "ready")
    dep = _throttled(lambda: apigw.create_deployment(restApiId=api_id))["id"]

    _throttled(lambda: apigw.create_stage(
        restApiId=api_id, stageName="cached", deploymentId=dep, cacheClusterEnabled=True,
        cacheClusterSize=_CACHE_SIZE, tags={_TAG_KEY: CHECK}))
    # Registered HERE, before the AVAILABLE poll: the cluster bills hourly.
    ctx.on_cleanup(_teardown(lambda: apigw.delete_stage(restApiId=api_id, stageName="cached")))
    _throttled(lambda: apigw.create_stage(
        restApiId=api_id, stageName="ctl", deploymentId=dep, tags={_TAG_KEY: CHECK}))
    ctx.on_cleanup(_teardown(lambda: apigw.delete_stage(restApiId=api_id, stageName="ctl")))
    _throttled(lambda: apigw.update_stage(restApiId=api_id, stageName="cached", patchOperations=[
        {"op": "replace", "path": "/c/GET/caching/enabled", "value": "true"},
        {"op": "replace", "path": "/c/GET/caching/ttlInSeconds", "value": str(_TTL_S)},
        {"op": "replace", "path": "/ready/GET/caching/enabled", "value": "false"},
    ]))

    status = _poll_until(
        lambda: apigw.get_stage(restApiId=api_id, stageName="cached").get("cacheClusterStatus"),
        lambda s: s == "AVAILABLE", timeout_s=900, interval_s=15,
        description=f"{_CACHE_SIZE}GB cache cluster reaching AVAILABLE")
    assert status == "AVAILABLE", f"cacheClusterStatus {status!r}"
    cached = apigw.get_stage(restApiId=api_id, stageName="cached")
    assert cached.get("methodSettings", {}).get("c/GET", {}).get("cachingEnabled") is True, (
        f"precondition: GET /c caching must be ON, methodSettings {cached.get('methodSettings')!r}")
    ctl = apigw.get_stage(restApiId=api_id, stageName="ctl")
    assert (ctl.get("cacheClusterEnabled"), ctl.get("methodSettings", {})) == (False, {}), (
        f"control stage must have no cache: cacheClusterEnabled={ctl.get('cacheClusterEnabled')!r}"
        f" methodSettings={ctl.get('methodSettings')!r}")

    cached_base, ctl_base = ctx.rest_api_url(api_id, "cached"), ctx.rest_api_url(api_id, "ctl")
    t0 = _ready_then_align([f"{cached_base}/ready", f"{ctl_base}/ready"])

    seen: set[bytes] = set()
    tally = {"hit": 0, "miss": 0}

    def _get_cached():
        st, _h, body = _http(f"{cached_base}/c")
        assert st == 200 and body.startswith(b"inv-"), f"cached GET /c -> {st} {body[:120]!r}"
        kind = "hit" if body in seen else "miss"
        seen.add(body)
        tally[kind] += 1
        return kind

    assert _get_cached() == "miss", f"the first GET on a cold cache must miss; tally {tally!r}"
    for _ in range(_MAX_TRIES):
        if _get_cached() == "hit":
            break
    else:
        raise AssertionError(f"no cache hit in {_MAX_TRIES} repeat GETs; tally {tally!r} — the "
                             f"stage cache is not serving the cached body")
    pre_flush = dict(tally)
    _throttled(lambda: apigw.flush_stage_cache(restApiId=api_id, stageName="cached"))
    # The flush is asynchronous (measured: 5 back-to-back GETs right after it were all hits), so
    # wait on the observable condition — cacheClusterStatus back to AVAILABLE — before the GET.
    # Any stale hit still served after that is counted, because the tally is the expectation.
    _poll_until(
        lambda: apigw.get_stage(restApiId=api_id, stageName="cached").get("cacheClusterStatus"),
        lambda s: s == "AVAILABLE", timeout_s=300, interval_s=3,
        description="cacheClusterStatus returning to AVAILABLE after FlushStageCache")
    flush_deadline = time.monotonic() + 180
    while _get_cached() != "miss":
        if time.monotonic() >= flush_deadline:
            raise AssertionError(f"FlushStageCache never forced a miss within 180s; tally "
                                 f"{tally!r}, before the flush {pre_flush!r}")
        time.sleep(5)

    ctl_bodies = []
    for i in range(_N_CTL):
        st, _h, body = _http(f"{ctl_base}/c")
        assert st == 200 and body.startswith(b"inv-"), f"ctl GET /c {i} -> {st} {body[:120]!r}"
        ctl_bodies.append(body)
    t_ctl_sent = time.monotonic()
    assert len(set(ctl_bodies)) == _N_CTL, (
        f"every control-stage GET must reach Lambda (no cache), got bodies {ctl_bodies!r}")

    total = tally["hit"] + tally["miss"]
    stage = _dims(ApiName=api_name, Stage="cached")
    ctl_dims = _dims(ApiName=api_name, Stage="ctl")

    # Control-stage latency first: it sizes the absence window below.
    ctl_count = _await_sum(ctx, _NS, "Count", ctl_dims, t0, _N_CTL)
    latency_s = time.monotonic() - t_ctl_sent

    count = _await_sum(ctx, _NS, "Count", stage, t0, total)
    misses = _await_sum(ctx, _NS, "CacheMissCount", stage, t0, tally["miss"])
    hits = _await_sum(ctx, _NS, "CacheHitCount", stage, t0, tally["hit"])
    assert (count, misses, hits) == (total, tally["miss"], tally["hit"]), (
        f"cached stage Count/CacheMissCount/CacheHitCount were {count}/{misses}/{hits}; the "
        f"client measured {total}/{tally['miss']}/{tally['hit']}")
    gmd = tuple(_gmd(ctx, _NS, m, stage, t0)[0] for m in ("Count", "CacheMissCount",
                                                          "CacheHitCount"))
    assert gmd == (total, tally["miss"], tally["hit"]), (
        f"GetMetricData disagrees with the measured {total}/{tally['miss']}/{tally['hit']}: "
        f"{gmd!r}")

    # Hits never reach the backend: Lambda saw exactly the cached-stage misses + control GETs.
    want_inv = tally["miss"] + _N_CTL
    inv = _await_sum(ctx, "AWS/Lambda", "Invocations", _dims(FunctionName=fn_name), fn_start,
                     want_inv)
    assert inv == want_inv, (
        f"Lambda Invocations = {inv}, expected {tally['miss']} misses + {_N_CTL} control GETs; "
        f"a cache hit must not invoke the integration")

    # Effect-absent: the uncached stage has NO cache series, held for >= 2x its Count latency.
    hold_s = max(2 * latency_s, 60.0)
    hold_end = time.monotonic() + hold_s
    early = t0 - timedelta(minutes=15)
    reads = 0
    while True:
        for metric in ("CacheHitCount", "CacheMissCount"):
            for reader in (_gms, _gmd):
                total_v, n = reader(ctx, _NS, metric, ctl_dims, early)
                assert n == 0, (
                    f"uncached stage 'ctl' must publish no {metric} series, but "
                    f"{reader.__name__} returned {n} points (sum {total_v}) after "
                    f"{reads} clean reads")
        reads += 1
        if time.monotonic() >= hold_end:
            break
        time.sleep(15)
    ctl_final, ctl_pts = _gms(ctx, _NS, "Count", ctl_dims, t0)
    assert (ctl_count, ctl_final) == (_N_CTL, _N_CTL) and ctl_pts > 0, (
        f"control stage Count must be exactly {_N_CTL}: first {ctl_count}, final {ctl_final} "
        f"over {ctl_pts} points (held {hold_s:.0f}s = max(2 x {latency_s:.0f}s, 60s))")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
