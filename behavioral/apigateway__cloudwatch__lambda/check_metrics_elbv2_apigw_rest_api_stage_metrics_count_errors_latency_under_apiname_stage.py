"""metrics-elbv2-apigw-rest-api-stage-metrics-count-errors-latency-under-apiname-stage."""
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

CHECK = "metrics-elbv2-apigw-rest-api-stage-metrics-count-errors-latency-under-apiname-stage"
GROUP = "metrics-and-alarms"
SERVICES = ["apigateway", "cloudwatch", "lambda"]

_N_OK = 10
_N_BOOM = 4

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
    return ctx.rest_api_url(api_id, 'live')


def _ready_then_align(base, probes, quiet_s=40, deadline_s=200):
    """Probe every route until `quiet_s` pass with no wrong answer (a new stage 404s for ~a minute),
    then stop at :25-:40 of a UTC minute and return the next minute; the >= 20 s gap keeps
    readiness traffic, sometimes counted a few seconds late, out of the measured minute."""
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
    """REST API stage requests land in AWS/ApiGateway under ApiName + Stage as exact counts: Count,
    5XXError = the Lambda's 500s, 4XXError = 0, one Latency/IntegrationLatency sample per request.
    The same series keyed by ApiId (the HTTP API dimension) do not exist for a REST API."""
    api_name = ctx.unique_name("sim2real-mrest-")
    fn_name, fn_arn = _lambda(ctx)
    api_id, root = _rest_api(ctx, api_name)
    _allow_invoke(ctx, fn_name, api_id)
    _rest_proxy(ctx, api_id, root, fn_arn)
    base = _rest_stage(ctx, api_id)
    t0 = _ready_then_align(base, [("/ok", None, 200), ("/boom", None, 500)])

    for i in range(_N_OK):
        status, _h, body = _http(f"{base}/ok")
        assert (status, body) == (200, b"LAMBDA-200"), f"ok {i}: {status} {body[:80]!r}"
    for i in range(_N_BOOM):
        status, _h, body = _http(f"{base}/boom")
        assert (status, body) == (500, b"LAMBDA-500"), (
            f"boom {i}: {status} {body[:80]!r}, expected the integration's own 500 passed through")
    total = _N_OK + _N_BOOM

    stage = _dims(ApiName=api_name, Stage="live")
    count = _await(ctx, "Count", stage, t0, "Sum", total)
    assert count == total, f"Count{{ApiName,Stage=live}} summed to {count}, expected {total}"
    e5 = _await(ctx, "5XXError", stage, t0, "Sum", _N_BOOM)
    assert e5 == _N_BOOM, f"5XXError = {e5}, expected exactly the {_N_BOOM} integration 500s"
    e4, e4_pts = _stat(ctx, "4XXError", stage, t0, "Sum")
    assert (e4, e4_pts > 0) == (0, True), (
        f"4XXError must be published and read 0 for a batch with no 4xx; got sum {e4} over "
        f"{e4_pts} datapoints")
    lat = _await(ctx, "Latency", stage, t0, "SampleCount", total)
    ilat = _await(ctx, "IntegrationLatency", stage, t0, "SampleCount", total)
    assert (lat, ilat) == (total, total), (
        f"Latency/IntegrationLatency SampleCount were {lat}/{ilat}, expected one sample per "
        f"request ({total}) — every request reached the integration")

    # Effect-absent: the REST stage is keyed by ApiName, never by ApiId.
    by_id, by_id_pts = _stat(ctx, "Count", _dims(ApiId=api_id, Stage="live"), t0, "Sum")
    assert by_id_pts == 0, (
        f"a REST API's Count must not be published under ApiId={api_id}; got {by_id_pts} "
        f"datapoints (sum {by_id})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
