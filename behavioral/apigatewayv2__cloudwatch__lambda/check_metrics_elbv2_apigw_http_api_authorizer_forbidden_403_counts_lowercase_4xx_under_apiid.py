"""metrics-elbv2-apigw-http-api-authorizer-forbidden-403-counts-lowercase-4xx-under-apiid."""
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

CHECK = "metrics-elbv2-apigw-http-api-authorizer-forbidden-403-counts-lowercase-4xx-under-apiid"
GROUP = "metrics-and-alarms"
SERVICES = ["apigatewayv2", "cloudwatch", "lambda"]

_N_OK = 6
_N_BOOM = 3
_N_ALLOW = 4
_N_DENY = 5

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


def _quiet(fn):
    """Teardown: tolerate only the resource's not-found; anything else raises."""
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
    return ctx.rest_api_url(api_id, "live")


def _ready_then_align(base, probes, quiet_s=40, deadline_s=200):
    """Probe until `quiet_s` seconds pass with every answer right, then return the next UTC minute.

    Stage propagation is eventual per node: a new HTTP API can answer 404 on every route for ~53 s.
    """
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
        # Stop by :40 so >= 20 s separate readiness traffic from the measured minute: requests in
        # the last ~3 s before a boundary are counted in the next minute's Count.
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


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-metrics.html
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
    """An HTTP API request a REQUEST authorizer refuses returns 403 Forbidden and counts in lowercase
    ``4xx`` under ApiId + Stage, while integration 500s count in ``5xx``; unlike a REST API,
    nothing is published under ``4XXError``/``5XXError`` or ApiName."""
    v2 = ctx.client("apigatewayv2")
    api_name = ctx.unique_name("sim2real-mhttp-")
    fn_name, fn_arn = _lambda(ctx)
    http_api = v2.create_api(Name=api_name, ProtocolType="HTTP", Tags={_TAG_KEY: CHECK})
    api_id = http_api["ApiId"]
    ctx.on_cleanup(_retry_throttled(lambda: v2.delete_api(ApiId=api_id)))
    _allow_invoke(ctx, fn_name, api_id)
    integ = v2.create_integration(ApiId=api_id, IntegrationType="AWS_PROXY", IntegrationUri=fn_arn,
                                  PayloadFormatVersion="2.0")["IntegrationId"]
    auth = v2.create_authorizer(
        ApiId=api_id, Name="sim2real-req", AuthorizerType="REQUEST",
        AuthorizerUri=_invoke_uri(ctx, fn_arn), IdentitySource=["$request.header.x-sim-auth"],
        AuthorizerPayloadFormatVersion="2.0", EnableSimpleResponses=True,
        AuthorizerResultTtlInSeconds=0)["AuthorizerId"]
    for key in ("GET /ok", "GET /boom"):
        v2.create_route(ApiId=api_id, RouteKey=key, Target=f"integrations/{integ}")
    v2.create_route(ApiId=api_id, RouteKey="GET /secure", Target=f"integrations/{integ}",
                    AuthorizationType="CUSTOM", AuthorizerId=auth)
    dep = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    _poll_until(lambda: v2.get_deployment(ApiId=api_id, DeploymentId=dep)["DeploymentStatus"],
                lambda s: s != "PENDING", timeout_s=60, interval_s=2,
                description="the HTTP API deployment leaving PENDING")
    v2.create_stage(ApiId=api_id, StageName="live", DeploymentId=dep)
    base = ctx.stage_url(http_api["ApiEndpoint"], "live")
    t0 = _ready_then_align(base, [("/ok", None, 200), ("/boom", None, 500),
                                  ("/secure", {"x-sim-auth": "allow"}, 200),
                                  ("/secure", {"x-sim-auth": "deny"}, 403)])

    for i in range(_N_OK):
        status, _h, body = _http(f"{base}/ok")
        assert (status, body) == (200, b"LAMBDA-200"), f"ok {i}: {status} {body[:80]!r}"
    for i in range(_N_BOOM):
        status, _h, body = _http(f"{base}/boom")
        assert (status, body) == (500, b"LAMBDA-500"), f"boom {i}: {status} {body[:80]!r}"
    for i in range(_N_ALLOW):
        status, _h, body = _http(f"{base}/secure", {"x-sim-auth": "allow"})
        assert (status, body) == (200, b"LAMBDA-200"), f"allow {i}: {status} {body[:80]!r}"
    for i in range(_N_DENY):
        status, _h, body = _http(f"{base}/secure", {"x-sim-auth": "deny"})
        assert (status, body) == (403, b'{"message":"Forbidden"}'), (
            f"deny {i}: {status} {body[:120]!r}, expected 403 {{\"message\":\"Forbidden\"}}")
    total = _N_OK + _N_BOOM + _N_ALLOW + _N_DENY
    reached = _N_OK + _N_BOOM + _N_ALLOW

    stage = _dims(ApiId=api_id, Stage="live")
    count = _await(ctx, "Count", stage, t0, "Sum", total)
    e4 = _await(ctx, "4xx", stage, t0, "Sum", _N_DENY)
    e5 = _await(ctx, "5xx", stage, t0, "Sum", _N_BOOM)
    assert (count, e4, e5) == (total, _N_DENY, _N_BOOM), (
        f"Count/4xx/5xx were {count}/{e4}/{e5}, expected {total}/{_N_DENY}/{_N_BOOM}: the "
        f"authorizer's 403s are client errors, the integration's 500s server errors")
    lat = _await(ctx, "Latency", stage, t0, "SampleCount", total)
    ilat = _await(ctx, "IntegrationLatency", stage, t0, "SampleCount", reached)
    assert (lat, ilat) == (total, reached), (
        f"Latency/IntegrationLatency SampleCount were {lat}/{ilat}, expected {total}/{reached}: "
        f"the {_N_DENY} forbidden requests never reached the integration")

    # Effect-absent: the REST vocabulary and key are not used for an HTTP API.
    absent = {
        "4XXError{ApiId,Stage}": _stat(ctx, "4XXError", stage, t0, "Sum")[1],
        "5XXError{ApiId,Stage}": _stat(ctx, "5XXError", stage, t0, "Sum")[1],
        "Count{ApiName,Stage}": _stat(ctx, "Count", _dims(ApiName=api_name, Stage="live"), t0,
                                      "Sum")[1],
    }
    assert set(absent.values()) == {0}, (
        f"an HTTP API publishes lowercase 4xx/5xx under ApiId only; datapoints found: {absent!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
