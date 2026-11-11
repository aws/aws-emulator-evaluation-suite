"""http-api-missing-invoke-permission-rejected-as-5xx-metric."""

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

CHECK = "http-api-missing-invoke-permission-rejected-as-5xx-metric"

GROUP = "observability"

SERVICES = ["apigatewayv2", "cloudwatch"]

# Setup plus two metric waits of up to 240 s each, and teardown.
_CHECK_BUDGET_S = 600

_STAGE = "perm"
_NAMESPACE = "AWS/ApiGateway"
_DENIED_REQUESTS = 4
_ALLOWED_REQUESTS = 3
_METRIC_TIMEOUT_S = 240.0
_METRIC_INTERVAL_S = 15.0

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
    """An HTTP API Lambda-proxy route whose function grants API Gateway no invoke permission returns 500 without
    invoking the backend, and CloudWatch counts those 500s in ``5xx`` and none in ``4xx``; after the permission
    is granted the same route serves 200s counted in ``Count`` but not in ``5xx``."""
    marker = ctx.unique_name("sim2real-xsvc-perm-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_xname(ctx, "httpapi-perm"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
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
    agw.create_route(ApiId=api_id, RouteKey="GET /x", Target=f"integrations/{integration_id}")
    agw.create_stage(ApiId=api_id, StageName=_STAGE, AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=_STAGE)
    )

    url = _v2_invoke_url(ctx, api_endpoint, _STAGE, "/x")
    seen = {"404": 0, "500": 0, "200": 0, "other": []}

    def _get():
        status, text = _http("GET", url)
        if str(status) in seen:
            seen[str(status)] += 1
        else:
            seen["other"].append((status, text[:200]))
        return status, text

    window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)

    # Wait for the stage to route (a 404 here is "stage not live yet", which is not counted).
    first = _poll_until(
        _get,
        lambda r: r[0] != 404,
        timeout_s=150.0,
        interval_s=4.0,
        description=f"GET /x on stage {_STAGE} reaching the integration",
    )
    assert first[0] == 500, (
        f"with no lambda:InvokeFunction grant the gateway must reject with 500, got "
        f"{first[0]}: {first[1][:200]!r}"
    )
    for _ in range(_DENIED_REQUESTS - 1):
        status, text = _get()
        assert status == 500, (
            f"every request while the permission is missing must be a 500, got {status}: "
            f"{text[:200]!r}"
        )
    denied = seen["500"]
    assert denied == _DENIED_REQUESTS and not seen["other"], (
        f"expected exactly {_DENIED_REQUESTS} 500s and nothing else, saw {seen!r}"
    )

    cw = ctx.client("cloudwatch")
    stage_dims = [{"Name": "ApiId", "Value": api_id}, {"Name": "Stage", "Value": _STAGE}]
    five_xx = _poll_until(
        lambda: _metric_sum(cw, _NAMESPACE, "5xx", stage_dims, window_start),
        lambda total: total >= denied,
        timeout_s=_METRIC_TIMEOUT_S,
        interval_s=_METRIC_INTERVAL_S,
        description=f"(ApiId={api_id}, Stage={_STAGE}) 5xx reaching the {denied} rejected requests",
    )
    assert five_xx == denied, (
        f"5xx summed to {five_xx} but exactly {denied} requests were rejected with 500"
    )
    four_xx = _metric_sum(cw, _NAMESPACE, "4xx", stage_dims, window_start)
    assert four_xx == 0, (
        f"a missing invoke permission is a server-side integration failure; 4xx must be 0, "
        f"got {four_xx}"
    )
    fn_dims = [{"Name": "FunctionName", "Value": fn["name"]}]
    invoked = _metric_sum(cw, "AWS/Lambda", "Invocations", fn_dims, window_start)
    assert invoked == 0, (
        f"the function granted API Gateway nothing, yet AWS/Lambda Invocations for it summed to "
        f"{invoked} — the gateway invoked a backend it was not authorized to call"
    )
    groups = ctx.client("logs").describe_log_groups(
        logGroupNamePrefix=f"/aws/lambda/{fn['name']}"
    ).get("logGroups", [])
    assert not [g for g in groups if g["logGroupName"] == f"/aws/lambda/{fn['name']}"], (
        f"the function's log group exists, so it ran while unauthorized: {groups!r}"
    )

    # ---- Positive control: repair the one broken thing ----
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*",
    )
    # Resource-policy propagation: the first requests after the grant may still be 500 — each is
    # tallied, and the 5xx bound below uses the tally rather than the intent.
    served = _poll_until(
        _get,
        lambda r: r[0] == 200,
        timeout_s=90.0,
        interval_s=3.0,
        description="GET /x serving 200 once the invoke permission is granted",
    )
    assert served[1] == marker, f"the repaired route must serve this check's marker, got {served!r}"
    for _ in range(_ALLOWED_REQUESTS - 1):
        status, text = _get()
        assert status == 200 and text == marker, (
            f"after the grant every request must be served by the backend, got {status}: "
            f"{text[:200]!r}"
        )
    assert not seen["other"], f"only 404/500/200 were expected, also saw {seen['other']!r}"

    count = _poll_until(
        lambda: _metric_sum(cw, _NAMESPACE, "Count", stage_dims, window_start),
        lambda total: total >= seen["500"] + seen["200"],
        timeout_s=_METRIC_TIMEOUT_S,
        interval_s=_METRIC_INTERVAL_S,
        description=(
            f"(ApiId, Stage) Count reaching the {seen['500']} rejected + {seen['200']} served "
            f"requests"
        ),
    )
    assert count == seen["500"] + seen["200"], (
        f"Count summed to {count}; this check observed {seen['500']} 500s and {seen['200']} 200s "
        f"(the {seen['404']} pre-deployment 404s are never counted)"
    )
    five_xx_after = _metric_sum(cw, _NAMESPACE, "5xx", stage_dims, window_start)
    assert five_xx_after == seen["500"], (
        f"5xx summed to {five_xx_after} after the repair; served 200s must not raise it above the "
        f"{seen['500']} observed 500s"
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
    """Create a Lambda (role scoped to its own logs) through the IAM propagation window, then wait
    for Active. Teardown registered for role, log group (re-reaped after the delete) and function.
    Grants NO resource-policy statement: the caller decides who may invoke it."""
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
        timeout_s=120.0,
        interval_s=4.0,
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
