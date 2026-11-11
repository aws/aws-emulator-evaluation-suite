"""http-api-route-throttle-zero-rejected-429-counted-in-4xx."""

from __future__ import annotations

import datetime as dt
import json
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-route-throttle-zero-rejected-429-counted-in-4xx"

GROUP = "observability"

SERVICES = ["apigatewayv2", "cloudwatch"]

# Setup plus two metric waits of up to 240 s each, and teardown.
_CHECK_BUDGET_S = 600

_STAGE = "thr"
_NAMESPACE = "AWS/ApiGateway"
_THROTTLED_REQUESTS = 5
_OPEN_REQUESTS = 3
_METRIC_TIMEOUT_S = 240.0
_METRIC_INTERVAL_S = 2.0

_HANDLER = """
import os


def lambda_handler(event, context):
    return {"statusCode": 200, "headers": {"Content-Type": "text/plain"},
            "body": os.environ["MARKER"]}
"""


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-metrics.html
@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A route throttled to zero is rejected with 429 before the integration runs while a sibling route
    serves; each 429 counts in the stage Count and 4xx, Lambda Invocations equals the 200s alone,
    and lifting the limits makes the route serve.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-throttling.html
    """
    marker = ctx.unique_name("sim2real-xsvc-thr-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_xname(ctx, "httpapi-thr"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id, api_endpoint = api["ApiId"], api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    for key in ("GET /closed", "GET /open"):
        agw.create_route(ApiId=api_id, RouteKey=key, Target=f"integrations/{integration_id}")
    stage = agw.create_stage(
        ApiId=api_id,
        StageName=_STAGE,
        AutoDeploy=True,
        RouteSettings={"GET /closed": {"ThrottlingBurstLimit": 0, "ThrottlingRateLimit": 0.0}},
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=_STAGE)
    )
    closed_settings = stage.get("RouteSettings", {}).get("GET /closed", {})
    assert closed_settings.get("ThrottlingBurstLimit") == 0, (
        f"CreateStage must echo the zero burst limit for GET /closed, got {stage.get('RouteSettings')!r}"
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    )

    closed_url = _v2_invoke_url(ctx, api_endpoint, _STAGE, "/closed")
    open_url = _v2_invoke_url(ctx, api_endpoint, _STAGE, "/open")
    # Every metric bound is derived from the statuses actually observed, not the intended counts.
    seen = {"404": 0, "429": 0, "200": 0, "other": []}

    def _get(url):
        status, text = _http("GET", url)
        if str(status) in seen:
            seen[str(status)] += 1
        else:
            seen["other"].append((status, text[:200]))
        return status, text

    window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)

    # AutoDeploy publishes asynchronously; traffic waits for the stage's first deployment so a
    # run rarely sees a pre-deployment 404.
    _poll_until(
        lambda: agw.get_stage(ApiId=api_id, StageName=_STAGE).get("DeploymentId"),
        bool,
        timeout_s=_budget_s(ctx, 120.0),
        ctx=ctx,
        interval_s=1.0,
        description=f"AutoDeploy stage {_STAGE} reporting its first DeploymentId",
    )

    # The positive control first: the open route must serve before the closed one is judged.
    opened = _poll_until(
        lambda: _get(open_url),
        lambda r: r[0] == 200,
        timeout_s=_budget_s(ctx, 150.0),
        ctx=ctx,
        interval_s=1.0,
        description=f"GET /open on stage {_STAGE} serving the backend",
    )
    assert opened[1] == marker, f"GET /open must serve this check's marker, got {opened!r}"

    # Throttle settings take a few seconds to bite; wait for the first 429, tallying every status.
    _poll_until(
        lambda: _get(closed_url),
        lambda r: r[0] == 429,
        timeout_s=_budget_s(ctx, 90.0),
        ctx=ctx,
        interval_s=1.0,
        description="GET /closed being throttled with 429 under burst 0 / rate 0",
    )
    for _ in range(_THROTTLED_REQUESTS - 1):
        status, text = _get(closed_url)
        assert status == 429, (
            f"once enforced, a zero-limit route must reject every request with 429, got {status}: "
            f"{text[:200]!r}"
        )
    for _ in range(_OPEN_REQUESTS):
        status, text = _get(open_url)
        assert status == 200 and text == marker, (
            f"the sibling route must be unaffected by GET /closed's limits, got {status}: "
            f"{text[:200]!r}"
        )
    assert not seen["other"], f"only 404/429/200 were expected, also saw {seen['other']!r}"

    cw = ctx.client("cloudwatch")
    stage_dims = [{"Name": "ApiId", "Value": api_id}, {"Name": "Stage", "Value": _STAGE}]
    four_xx = _poll_until(
        lambda: _metric_sum(cw, _NAMESPACE, "4xx", stage_dims, window_start),
        lambda total: total >= seen["429"],
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description=f"(ApiId={api_id}, Stage={_STAGE}) 4xx reaching the {seen['429']} observed 429s",
    )
    assert four_xx == seen["429"], (
        f"4xx summed to {four_xx}; this check observed exactly {seen['429']} 429s and no other 4xx "
        f"from a deployed route"
    )
    count = _poll_until(
        lambda: _metric_sum(cw, _NAMESPACE, "Count", stage_dims, window_start),
        lambda total: total >= seen["429"] + seen["200"],
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description=(
            f"(ApiId, Stage) Count reaching {seen['429']} throttled + {seen['200']} served requests"
        ),
    )
    assert count == seen["429"] + seen["200"], (
        f"Count summed to {count}; observed {seen['429']} 429s and {seen['200']} 200s (the "
        f"{seen['404']} pre-deployment 404s are never counted)"
    )
    five_xx = _metric_sum(cw, _NAMESPACE, "5xx", stage_dims, window_start)
    assert five_xx == 0, f"a throttle is a client-side rejection; 5xx must be 0, got {five_xx}"
    fn_dims = [{"Name": "FunctionName", "Value": fn["name"]}]
    invocations = _poll_until(
        lambda: _metric_sum(cw, "AWS/Lambda", "Invocations", fn_dims, window_start),
        lambda total: total >= seen["200"],
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description=f"AWS/Lambda Invocations reaching the {seen['200']} served requests",
    )
    assert invocations == seen["200"], (
        f"the backend was invoked {invocations} times for {seen['200']} served requests — a 429 "
        f"must be refused before the integration runs"
    )

    # Positive control: lifting the closed route's limits makes the same URL serve.
    agw.update_stage(
        ApiId=api_id,
        StageName=_STAGE,
        RouteSettings={"GET /closed": {"ThrottlingBurstLimit": 50, "ThrottlingRateLimit": 50.0}},
    )
    repaired = _poll_until(
        lambda: _get(closed_url),
        lambda r: r[0] == 200,
        timeout_s=_budget_s(ctx, 90.0),
        ctx=ctx,
        interval_s=1.0,
        description="GET /closed serving 200 once its limits are lifted",
    )
    assert repaired[1] == marker, f"the repaired route must serve the marker, got {repaired!r}"


_XSVC_PREFIX = "sim2real-xsvc-"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _metric_sum(cw, namespace, metric_name, dimensions, window_start):
    """Sum of every 60 s datapoint since window_start; 0.0 when the series has none."""
    response = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=list(dimensions),
        StartTime=window_start,
        EndTime=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5),
        Period=60,
        Statistics=["Sum"],
    )
    return float(sum(point["Sum"] for point in response.get("Datapoints", [])))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition", ctx=None):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, timeout_s=20):
    """(status, text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _v2_invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of `path` on an HTTP API stage."""
    return f"{ctx.stage_url(api_endpoint, stage)}/{path.lstrip('/')}"


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _reap_log_group(ctx, name):
    """Delete /aws/lambda/<fn> in a loop: a buffered flush can recreate it after one delete."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    absent_reads = 0
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            logs.delete_log_group(logGroupName=group)
            absent_reads = 0
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g.get("logGroupName") == group for g in found):
            absent_reads += 1
            if absent_reads >= 3:
                return
        time.sleep(5)
    raise RuntimeError(f"log group {group} still present after the reap window")


def _create_lambda(ctx, handler_code, env=None, timeout=15):
    """Create a Lambda (role scoped to its own logs) once its role is assumable, then wait for
    Active; registers teardown for the role, log group and function.
    """
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role-lambda")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )

    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": 128,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None  # brand-new role not yet assumable by Lambda
            raise

    created = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=_budget_s(ctx, 120.0),
        ctx=ctx,
        interval_s=2.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
