"""obs-apigateway-1-cache-control-invalidation-rejected-403-when-unauthorized."""
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

CHECK = "obs-apigateway-1-cache-control-invalidation-rejected-403-when-unauthorized"
GROUP = "metrics-and-alarms"
SERVICES = ["apigateway", "cloudwatch", "lambda"]

_CACHE_SIZE = "0.5"
_TTL_S = 300
_MAX_TRIES = 5
_INVALIDATE = {"Cache-Control": "max-age=0"}

# ===== helpers =====
_TAG_KEY = "sim2real"

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


#: Not-found codes of the deletes wrapped by _quiet: IAM and Lambda.
_GONE = {"NoSuchEntity", "ResourceNotFoundException"}


def _quiet(fn):
    """Teardown: a resource that is already gone is clean; any other failure raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _GONE:
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
    name = ctx.unique_name("sim2real-xsvc-cc-")
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                 "Principal": {"Service": "lambda.amazonaws.com"}}]}),
        Tags=[{"Key": _TAG_KEY, "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_quiet(lambda: iam.delete_role(RoleName=name)))
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
    ctx.on_cleanup(_quiet(lambda: lam.delete_function(FunctionName=name)))
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


def _ready(url, quiet_s=30, deadline_s=240):
    """Stage propagation is eventual and per-node: wait for a quiet window of only 200s."""
    deadline = time.monotonic() + deadline_s
    streak_from = None
    last = None
    while time.monotonic() < deadline:
        last = _http(url)[0]
        now = time.monotonic()
        streak_from = (streak_from or now) if last == 200 else None
        if streak_from is not None and now - streak_from >= quiet_s:
            return
        time.sleep(0.5)
    raise AssertionError(f"no {quiet_s}s window of 200s from {url} within {deadline_s}s; "
                         f"last {last!r}")


def _invocations(ctx, fn_name, start):
    pts = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/Lambda", MetricName="Invocations",
        Dimensions=[{"Name": "FunctionName", "Value": fn_name}], StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=3), Period=60,
        Statistics=["Sum"])["Datapoints"]
    return sum(p["Sum"] for p in pts)
# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """With requireAuthorizationForCacheControl and FAIL_WITH_403, an unsigned `Cache-Control: max-age=0`
    request gets 403, leaves the cache entry intact and never reaches the Lambda; a sibling method
    without the requirement honours the same header with a fresh invocation."""
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-xsvc-cachectl-")
    fn_name, fn_arn = _lambda(ctx)
    fn_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    api_id, root = _rest_api(ctx, api_name)
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId="apigw", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{acct}:{api_id}/*")
    _lambda_get(ctx, api_id, root, "locked", fn_arn)
    _lambda_get(ctx, api_id, root, "open", fn_arn)
    _mock_get(ctx, api_id, root, "ready")
    dep = _throttled(lambda: apigw.create_deployment(restApiId=api_id))["id"]
    _throttled(lambda: apigw.create_stage(
        restApiId=api_id, stageName="cached", deploymentId=dep, cacheClusterEnabled=True,
        cacheClusterSize=_CACHE_SIZE, tags={_TAG_KEY: CHECK}))
    # Registered HERE, before the AVAILABLE poll: the cluster bills hourly.
    ctx.on_cleanup(_teardown(lambda: apigw.delete_stage(restApiId=api_id, stageName="cached")))
    ops = [{"op": "replace", "path": "/ready/GET/caching/enabled", "value": "false"}]
    for path, require in (("locked", "true"), ("open", "false")):
        ops += [
            {"op": "replace", "path": f"/{path}/GET/caching/enabled", "value": "true"},
            {"op": "replace", "path": f"/{path}/GET/caching/ttlInSeconds", "value": str(_TTL_S)},
            {"op": "replace", "path": f"/{path}/GET/caching/requireAuthorizationForCacheControl",
             "value": require},
            {"op": "replace", "path": f"/{path}/GET/caching/unauthorizedCacheControlHeaderStrategy",
             "value": "FAIL_WITH_403"},
        ]
    _throttled(lambda: apigw.update_stage(restApiId=api_id, stageName="cached",
                                          patchOperations=ops))

    status = _poll_until(
        lambda: apigw.get_stage(restApiId=api_id, stageName="cached").get("cacheClusterStatus"),
        lambda s: s == "AVAILABLE", timeout_s=900, interval_s=15,
        description=f"{_CACHE_SIZE}GB cache cluster reaching AVAILABLE")
    assert status == "AVAILABLE", f"cacheClusterStatus {status!r}"
    ms = apigw.get_stage(restApiId=api_id, stageName="cached").get("methodSettings", {})
    got = {p: (ms.get(f"{p}/GET", {}).get("cachingEnabled"),
               ms.get(f"{p}/GET", {}).get("requireAuthorizationForCacheControl"),
               ms.get(f"{p}/GET", {}).get("unauthorizedCacheControlHeaderStrategy"))
           for p in ("locked", "open")}
    assert got == {"locked": (True, True, "FAIL_WITH_403"),
                   "open": (True, False, "FAIL_WITH_403")}, (
        f"precondition: the two methods must differ ONLY in requireAuthorizationForCacheControl; "
        f"methodSettings {ms!r}")

    base = ctx.rest_api_url(api_id, 'cached')
    _ready(f"{base}/ready")

    seen: set[bytes] = set()
    misses = {"n": 0}

    def _get(path, headers=None):
        st, _h, body = _http(f"{base}/{path}", headers)
        assert st == 200 and body.startswith(b"inv-"), (
            f"GET /{path} {headers!r} -> {st} {body[:160]!r}")
        if body not in seen:
            misses["n"] += 1
        seen.add(body)
        return body

    def _prime(path):
        """GET until the same invocation id comes back twice: the entry is cached."""
        prev = _get(path)
        for _ in range(_MAX_TRIES):
            body = _get(path)
            if body == prev:
                return body
            prev = body
        raise AssertionError(f"GET /{path} never served a cached body in {_MAX_TRIES} tries")

    locked = _prime("locked")
    opened = _prime("open")

    # The one broken thing: an unauthorized client asks to bypass/invalidate a gated cache.
    st, _h, body = _http(f"{base}/locked", _INVALIDATE)
    assert st == 403, (
        f"unsigned Cache-Control: max-age=0 on a method requiring authorization for cache "
        f"control with FAIL_WITH_403 must be rejected 403, got {st} {body[:200]!r}")
    assert body not in seen, f"the 403 must not carry a Lambda invocation body: {body[:200]!r}"
    # Effect absent: the entry survived.
    after = _get("locked")
    assert after == locked, (
        f"a rejected invalidation must leave the cache entry intact; cached {locked!r}, "
        f"next GET {after!r}")

    # Positive control: the same header on the ungated sibling DOES invalidate.
    fresh = _get("open", _INVALIDATE)
    assert fresh != opened, (
        f"Cache-Control: max-age=0 on a method with requireAuthorizationForCacheControl=false "
        f"must reach the integration; got the cached body {opened!r} again")
    cached_again = _get("open")
    assert cached_again == fresh, (
        f"the invalidating GET must re-populate the entry; got {cached_again!r}, want {fresh!r}")

    # Effect absent across the boundary: Lambda saw only the client-observed misses.
    want = misses["n"]
    inv = _poll_until(lambda: _invocations(ctx, fn_name, fn_start), lambda v: v >= want,
                      timeout_s=300, interval_s=10,
                      description=f"Lambda Invocations reaching {want}")
    assert inv == want, (
        f"Lambda Invocations = {inv}, client observed {want} misses; the rejected 403 (or a "
        f"cache hit) must not invoke the integration")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
