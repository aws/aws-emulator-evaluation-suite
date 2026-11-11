"""metrics-elbv2-apigw-rest-api-lambda-authorizer-denied-403-counts-4xx-not-5xx."""
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

CHECK = "metrics-elbv2-apigw-rest-api-lambda-authorizer-denied-403-counts-4xx-not-5xx"
GROUP = "metrics-and-alarms"
SERVICES = ["apigateway", "cloudwatch", "lambda"]

_N_ALLOW = 5
_N_DENY = 7
_DENY_BODY = (b'{"Message":"User is not authorized to access this resource with an explicit deny'
              b' in an identity-based policy"}')

_TAG_KEY = "sim2real"
_NS = "AWS/ApiGateway"

#: One function serves every role these checks need: REST TOKEN authorizer, HTTP API REQUEST
#: authorizer (payload 2.0, simple responses), and the proxy integration itself.
_HANDLER = r'''
def handler(event, context):
    if event.get("type") == "TOKEN":
        effect = "Allow" if event.get("authorizationToken") == "allow" else "Deny"
        return {"principalId": "sim2real", "policyDocument": {"Version": "2012-10-17",
                "Statement": [{"Action": "execute-api:Invoke", "Effect": effect,
                               "Resource": event["methodArn"]}]}}
    if event.get("type") == "REQUEST" and "routeArn" in event:
        return {"isAuthorized": (event.get("headers") or {}).get("x-sim-auth") == "allow"}
    path = event.get("path") or event.get("rawPath") or ""
    if path.endswith("/boom"):
        return {"statusCode": 500, "body": "LAMBDA-500"}
    return {"statusCode": 200, "body": "LAMBDA-200"}
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


def _retry_throttled(fn):
    """Teardown: API Gateway deletes are rate limited account-wide; retry, then report."""
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
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def _lambda(ctx):
    """A python3.12 function whose role has NO logs permissions, so no log group is ever made."""
    iam, lam = ctx.client("iam"), ctx.client("lambda")
    name = ctx.unique_name("sim2real-mgw-")
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
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    return name, fn["FunctionArn"]


def _allow_invoke(ctx, fn_name, api_id):
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId="apigw", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{acct}:{api_id}/*")


def _invoke_uri(ctx, fn_arn):
    return (f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}"
            f"/invocations")


def _rest_api(ctx, name):
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=name, endpointConfiguration={"types": ["REGIONAL"]},
                                tags={_TAG_KEY: CHECK})
    api_id = api["id"]
    ctx.on_cleanup(_retry_throttled(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root


def _rest_proxy(ctx, api_id, root, fn_arn, authorizer_id=None):
    """ANY /{proxy+} -> AWS_PROXY lambda, optionally behind a CUSTOM authorizer."""
    apigw = ctx.client("apigateway")
    res = apigw.create_resource(restApiId=api_id, parentId=root, pathPart="{proxy+}")["id"]
    kw = {"authorizationType": "CUSTOM", "authorizerId": authorizer_id} if authorizer_id else {
        "authorizationType": "NONE"}
    apigw.put_method(restApiId=api_id, resourceId=res, httpMethod="ANY", **kw)
    apigw.put_integration(restApiId=api_id, resourceId=res, httpMethod="ANY", type="AWS_PROXY",
                          integrationHttpMethod="POST", uri=_invoke_uri(ctx, fn_arn))


def _rest_stage(ctx, api_id):
    apigw = ctx.client("apigateway")
    apigw.create_deployment(restApiId=api_id, stageName="live")
    return ctx.rest_api_url(api_id, 'live')


def _ready_then_align(base, probes, quiet_s=40, deadline_s=200):
    """Stage propagation across the execute-api fleet is eventual and per-node: measured on a new
    HTTP API, scattered requests on EVERY route answered 404 {"message":"Not Found"} for ~53 s
    after the stage was created, then none in the next 1500+. So readiness is a QUIET WINDOW:
    probe every (path, headers, want) until `quiet_s` seconds pass with no wrong answer, keep
    probing until :25-:40 of a UTC minute, then stop and return the NEXT minute, which the
    measured batch starts in. The >= 20 s gap is measured, not cosmetic: readiness requests sent
    in the last ~3 s before a boundary were counted in the NEXT minute's Count on a clock-synced
    host, so a short gap leaks readiness traffic into the measured window."""
    deadline = time.monotonic() + deadline_s
    streak_from = None
    last = None
    while time.monotonic() < deadline:
        last = [(p, want, _http(f"{base}{p}", h)[0]) for p, h, want in probes]
        now = time.monotonic()
        if all(got == want for _p, want, got in last):
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
    raise AssertionError(f"no {quiet_s}s window of correct answers from {probes!r} within "
                         f"{deadline_s}s; last round {last!r}")


def _dims(**kv):
    return [{"Name": k, "Value": v} for k, v in kv.items()]


def _stat(ctx, metric, dims, start, statistic):
    """Total of one statistic over every 60 s datapoint from `start` to now+3 min."""
    pts = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=_NS, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=3), Period=60,
        Statistics=[statistic])["Datapoints"]
    return sum(p[statistic] for p in pts), len(pts)


def _await(ctx, metric, dims, start, statistic, want, timeout_s=240):
    got, _ = _poll_until(lambda: _stat(ctx, metric, dims, start, statistic),
                         lambda r: r[0] >= want, timeout_s=timeout_s, interval_s=10,
                         description=f"{metric} {statistic} {dims!r} reaching {want}")
    return got


def _invocations(ctx, fn_name, start):
    pts = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/Lambda", MetricName="Invocations",
        Dimensions=[{"Name": "FunctionName", "Value": fn_name}], StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=3), Period=60,
        Statistics=["Sum"])["Datapoints"]
    return sum(p["Sum"] for p in pts)


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-metrics-and-dimensions.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A request denied by a Lambda TOKEN authorizer is refused with 403 AccessDeniedException, counts in 4XXError
    and not 5XXError, and never reaches the integration, while allowed requests do; Count counts both."""
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-mrest-")
    auth_fn, auth_arn = _lambda(ctx)  # the authorizer ...
    int_fn, int_arn = _lambda(ctx)    # ... and the integration: separate, so each is countable
    api_id, root = _rest_api(ctx, api_name)
    _allow_invoke(ctx, auth_fn, api_id)
    _allow_invoke(ctx, int_fn, api_id)
    auth_id = apigw.create_authorizer(
        restApiId=api_id, name="sim2real-token", type="TOKEN",
        authorizerUri=_invoke_uri(ctx, auth_arn),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0)["id"]
    _rest_proxy(ctx, api_id, root, int_arn, authorizer_id=auth_id)
    base = _rest_stage(ctx, api_id)
    t0 = _ready_then_align(base, [("/ok", {"Authorization": "allow"}, 200),
                                  ("/ok", {"Authorization": "deny"}, 403)])

    for i in range(_N_ALLOW):
        status, _h, body = _http(f"{base}/ok", {"Authorization": "allow"})
        assert (status, body) == (200, b"LAMBDA-200"), f"allow {i}: {status} {body[:80]!r}"
    for i in range(_N_DENY):
        status, headers, body = _http(f"{base}/ok", {"Authorization": "deny"})
        etype = {k.lower(): v for k, v in headers.items()}.get("x-amzn-errortype")
        assert (status, body) == (403, _DENY_BODY), (
            f"deny {i}: {status} {body[:120]!r}, expected 403 {_DENY_BODY!r}")
        assert etype == "AccessDeniedException", (
            f"deny {i}: x-amzn-ErrorType {etype!r}, expected 'AccessDeniedException'")
    total = _N_ALLOW + _N_DENY

    stage = _dims(ApiName=api_name, Stage="live")
    count = _await(ctx, "Count", stage, t0, "Sum", total)
    e4 = _await(ctx, "4XXError", stage, t0, "Sum", _N_DENY)
    assert (count, e4) == (total, _N_DENY), (
        f"Count/4XXError were {count}/{e4}, expected {total}/{_N_DENY}: every denied request is "
        f"a request, and a client error")
    e5, e5_pts = _stat(ctx, "5XXError", stage, t0, "Sum")
    assert (e5, e5_pts > 0) == (0, True), (
        f"an authorizer Deny is a client error: 5XXError must be published and read 0, got sum "
        f"{e5} over {e5_pts} datapoints")
    lat = _await(ctx, "Latency", stage, t0, "SampleCount", total)
    assert lat == total, f"Latency SampleCount was {lat}, expected one sample per request ({total})"

    # Effect-absent: the authorizer ran for every request, the integration only for the allowed.
    n_auth = _poll_until(lambda: _invocations(ctx, auth_fn, t0), lambda n: n >= total,
                         timeout_s=240, interval_s=10,
                         description=f"authorizer Invocations reaching {total}")
    n_int = _invocations(ctx, int_fn, t0)
    assert (n_auth, n_int) == (total, _N_ALLOW), (
        f"authorizer/integration Invocations were {n_auth}/{n_int}, expected {total}/{_N_ALLOW}: "
        f"the {_N_DENY} denied requests must never reach the integration")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
