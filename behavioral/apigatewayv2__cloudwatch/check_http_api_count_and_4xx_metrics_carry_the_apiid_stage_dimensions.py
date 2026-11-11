"""http-api-count-and-4xx-metrics-carry-the-apiid-stage-dimensions."""

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

CHECK = "http-api-count-and-4xx-metrics-carry-the-apiid-stage-dimensions"

GROUP = "observability"

SERVICES = ["apigatewayv2", "cloudwatch"]

_HANDLER = """
import os


def lambda_handler(event, context):
    if event.get("rawPath", "").endswith("/missing"):
        return {"statusCode": 404, "headers": {"Content-Type": "text/plain"}, "body": "missing"}
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": os.environ["MARKER"],
    }
"""

_BUSY_STAGE = "busy"
_QUIET_STAGE = "quiet"
_OK_REQUESTS = 5
_INTEGRATION_4XX_REQUESTS = 3
_ROUTE_MISS_REQUESTS = 3


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-metrics.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Matched-route traffic through an HTTP API stage reaches CloudWatch as ``AWS/ApiGateway`` ``Count`` and ``4xx``
    dimensioned by (ApiId, Stage): Count equals the matched requests, 4xx the integration-returned 404s, and
    unrouted requests and a quiet second stage contribute 0, so datapoints are attributed per stage."""
    marker = ctx.unique_name("sim2real-xsvc-metrics-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_xname(ctx, "httpapi-metrics"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
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
    agw.create_route(
        ApiId=api_id, RouteKey="GET /ping", Target=f"integrations/{integration_id}"
    )
    agw.create_route(
        ApiId=api_id, RouteKey="GET /missing", Target=f"integrations/{integration_id}"
    )
    for stage_name in (_BUSY_STAGE, _QUIET_STAGE):
        agw.create_stage(ApiId=api_id, StageName=stage_name, AutoDeploy=True)
        ctx.on_cleanup(
            lambda name=stage_name: ctx.client("apigatewayv2").delete_stage(
                ApiId=api_id, StageName=name
            )
        )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    )

    quiet = agw.get_stage(ApiId=api_id, StageName=_QUIET_STAGE)
    assert quiet.get("StageName") == _QUIET_STAGE and quiet.get("AutoDeploy") is True, (
        f"the control stage must exist and be deployed (so 'no datapoints' means 'no traffic', not "
        f"'no stage'); GetStage returned {quiet!r}"
    )

    ping_url = _v2_invoke_url(ctx, api_endpoint, _BUSY_STAGE, "/ping")
    missing_url = _v2_invoke_url(ctx, api_endpoint, _BUSY_STAGE, "/missing")
    route_miss_url = _v2_invoke_url(ctx, api_endpoint, _BUSY_STAGE, "/no-such-route")
    counters = {"routed": 0, "integration_404": 0, "route_miss": 0}

    def _get_routed(url):
        counters["routed"] += 1
        status, _, text = _http("GET", url)
        if status == 404:
            counters["integration_404"] += 1
        return status, text

    def _get_route_miss(url):
        counters["route_miss"] += 1
        status, _, text = _http("GET", url)
        return status, text

    # Settle the stage. Every request made here is counted too, which is what keeps the upper bound
    # honest: the assertion compares against what this check actually sent, not against a guess.
    settled = _poll_until(
        lambda: _get_routed(ping_url),
        lambda r: r[0] == 200,
        timeout_s=150.0,
        interval_s=4.0,
        description=f"GET /ping on stage {_BUSY_STAGE} serving its backend",
    )
    assert settled[1] == marker, (
        f"the busy stage must serve this check's backend (marker {marker!r}), got {settled[1]!r}"
    )

    window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    for _ in range(_OK_REQUESTS):
        status, text = _get_routed(ping_url)
        assert status == 200 and text == marker, (
            f"every counted request must be a 200 from the backend, got {status}: {text[:200]!r}"
        )
    for _ in range(_INTEGRATION_4XX_REQUESTS):
        status, text = _get_routed(missing_url)
        assert status == 404, (
            f"the /missing route's own integration must answer 404 so it is attributable to the "
            f"4xx metric, got {status}: {text[:200]!r}"
        )
    for _ in range(_ROUTE_MISS_REQUESTS):
        status, _text = _get_route_miss(route_miss_url)
        assert status == 404, (
            f"a path with no configured route must itself be refused with a 404 by the gateway, "
            f"got {status}"
        )

    routed_requests = counters["routed"]
    integration_404s = counters["integration_404"]
    assert integration_404s >= _INTEGRATION_4XX_REQUESTS, (
        f"internal bookkeeping: expected at least {_INTEGRATION_4XX_REQUESTS} integration-returned "
        f"404s, got {integration_404s}"
    )

    cw = ctx.client("cloudwatch")
    busy_dims = [
        {"Name": "ApiId", "Value": api_id},
        {"Name": "Stage", "Value": _BUSY_STAGE},
    ]

    count_sum = _poll_until(
        lambda: _metric_sum(cw, "Count", busy_dims, window_start),
        lambda total: total >= _OK_REQUESTS + _INTEGRATION_4XX_REQUESTS,
        timeout_s=240.0,
        interval_s=15.0,
        description=(
            f"AWS/ApiGateway Count for (ApiId={api_id}, Stage={_BUSY_STAGE}) reaching at least the "
            f"{_OK_REQUESTS + _INTEGRATION_4XX_REQUESTS} matched-route requests this check "
            f"deliberately made"
        ),
    )
    assert count_sum <= routed_requests, (
        f"Count for (ApiId={api_id}, Stage={_BUSY_STAGE}) summed to {count_sum}, more than the "
        f"{routed_requests} matched-route requests this check made to that stage — a metric cannot "
        f"count traffic that did not happen, and it must not count the "
        f"{counters['route_miss']} additional requests this check sent to a path with no route"
    )

    four_xx_sum = _poll_until(
        lambda: _metric_sum(cw, "4xx", busy_dims, window_start),
        lambda total: total >= _INTEGRATION_4XX_REQUESTS,
        timeout_s=240.0,
        interval_s=15.0,
        description=(
            f"AWS/ApiGateway 4xx for (ApiId={api_id}, Stage={_BUSY_STAGE}) accounting for the "
            f"{_INTEGRATION_4XX_REQUESTS} integration-returned 404s"
        ),
    )
    assert four_xx_sum <= integration_404s, (
        f"4xx summed to {four_xx_sum} but this check only ever received {integration_404s} 4xx "
        f"responses from an integration on that stage — a route-miss 404 must not be counted"
    )
    assert four_xx_sum <= count_sum, (
        f"4xx ({four_xx_sum}) cannot exceed Count ({count_sum}) for the same stage and window"
    )

    # The control: a stage of the SAME API that saw no traffic must have no volume attributed to it.
    quiet_sum = _metric_sum(
        cw,
        "Count",
        [{"Name": "ApiId", "Value": api_id}, {"Name": "Stage", "Value": _QUIET_STAGE}],
        window_start,
    )
    assert quiet_sum == 0, (
        f"stage {_QUIET_STAGE} received no requests, so its (ApiId, Stage) Count must sum to 0; got "
        f"{quiet_sum} — the target is attributing traffic to the wrong dimensions"
    )

    # The API-level rollup must include the busy stage's traffic.
    api_level_sum = _metric_sum(
        cw, "Count", [{"Name": "ApiId", "Value": api_id}], window_start
    )
    assert api_level_sum >= count_sum, (
        f"the (ApiId)-only Count rollup summed to {api_level_sum}, less than the "
        f"(ApiId, Stage={_BUSY_STAGE}) sum of {count_sum} — the per-API series must include every "
        f"stage's requests"
    )




_XSVC_PREFIX = "sim2real-xsvc-"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _metric_sum(cw, metric_name, dimensions, window_start):
    """The Sum of every 60s datapoint of AWS/ApiGateway <metric_name> since window_start.

    Returns 0.0 when the series has no datapoints, which is the correct reading for "nothing was
    published" — and is only ever used where the assertion's polarity makes the empty default the
    honest answer (an absence leg) or where a poll demands the value RISE first.
    """
    response = cw.get_metric_statistics(
        Namespace="AWS/ApiGateway",
        MetricName=metric_name,
        Dimensions=list(dimensions),
        StartTime=window_start,
        EndTime=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5),
        Period=60,
        Statistics=["Sum"],
    )
    return float(sum(point["Sum"] for point in response.get("Datapoints", [])))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=20):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                [(k.lower(), v) for k, v in resp.getheaders()],
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            [(k.lower(), v) for k, v in exc.headers.items()],
            exc.read().decode("utf-8", "replace"),
        )


def _v2_invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of `path` on an HTTP API stage."""
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{path.lstrip('/')}"


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


def _create_lambda(ctx, handler_code, env=None, permissions=None, timeout=30):
    """Create a Lambda (role scoped to logs plus `permissions`), retrying through the IAM
    role-propagation window, then wait for Active. Teardown registered for role, function and the
    auto-created /aws/lambda/<name> log group."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    statements.extend(permissions or [])
    role_arn = _create_role(
        ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )

    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
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
            if exc.response.get("Error", {}).get("Code") in (
                "InvalidParameterValueException",
                "AccessDeniedException",
            ):
                return None  # brand-new role not yet assumable by Lambda
            raise

    created = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    )
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
