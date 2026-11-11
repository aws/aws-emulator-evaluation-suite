"""obs-apigatewayv2-2-http-api-detailed-metrics-opt-in-adds-method-resource-series."""

from __future__ import annotations

import datetime as dt
import http.client
import json
import textwrap
import time
import urllib.parse
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-apigatewayv2-2-http-api-detailed-metrics-opt-in-adds-method-resource-series"

GROUP = "observability"

SERVICES = ["apigatewayv2", "cloudwatch"]

# The whole check: setup, three metric waits of up to 240 s each, and teardown.
_CHECK_BUDGET_S = 900

_STAGE = "obs"
_NAMESPACE = "AWS/ApiGateway"
# Per-route response body sizes. Chosen so every route's payload is distinguishable and the
# DataProcessed lower bound is dominated by bytes this check controls.
_BODY_BYTES = {"/a": 4000, "/b": 1500, "/c": 64}
_PHASE1_A = 4
_PHASE1_B = 2
_PHASE2_A = 3
_METRIC_TIMEOUT_S = 240.0
_METRIC_INTERVAL_S = 2.0
_UA = "sim2real-obs-probe/1"

_HANDLER = """
import json

SIZES = json.loads(%r)


def lambda_handler(event, context):
    path = event.get("rawPath", "")
    for suffix, size in SIZES.items():
        if path.endswith(suffix):
            return {"statusCode": 200, "headers": {"Content-Type": "text/plain"},
                    "body": suffix[-1] * size}
    return {"statusCode": 404, "headers": {"Content-Type": "text/plain"}, "body": "none"}
""" % json.dumps(_BODY_BYTES)


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
    """With DetailedMetricsEnabled false only (ApiId, Stage) series exist; opting in adds route
    series that count only post-opt-in traffic, only for routes that received it.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-metrics.html
    """
    fn = _create_lambda(ctx, _HANDLER)

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_xname(ctx, "httpapi-obs2"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
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
    for path in _BODY_BYTES:
        agw.create_route(
            ApiId=api_id, RouteKey=f"GET {path}", Target=f"integrations/{integration_id}"
        )
    stage = agw.create_stage(
        ApiId=api_id,
        StageName=_STAGE,
        AutoDeploy=True,
        DefaultRouteSettings={"DetailedMetricsEnabled": False},
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=_STAGE)
    )
    assert stage.get("DefaultRouteSettings", {}).get("DetailedMetricsEnabled") is False, (
        f"the stage must start opted OUT of detailed metrics; CreateStage returned "
        f"DefaultRouteSettings={stage.get('DefaultRouteSettings')!r}"
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    )

    window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    tally = {"sent": 0, "ok": 0, "payload": 0, "wire": 0}

    def _get(path):
        status, body, wire_bytes = _http_get(_v2_invoke_url(ctx, api_endpoint, _STAGE, path))
        tally["sent"] += 1
        tally["wire"] += wire_bytes
        if status == 200:
            tally["ok"] += 1
            tally["payload"] += len(body)
        return status, body

    def _get_ok(path):
        status, body = _get(path)
        expect = path[-1] * _BODY_BYTES[path]
        assert status == 200 and body == expect, (
            f"GET {path} must return 200 with the {_BODY_BYTES[path]}-byte body this check "
            f"configured; got {status} with {len(body)} bytes: {body[:120]!r}"
        )

    # Settle the stage. Every request is tallied, so the bounds below cover these as well.
    _poll_until(
        lambda: _get("/a")[0],
        lambda status: status == 200,
        timeout_s=_budget_s(ctx, 150.0),
        ctx=ctx,
        interval_s=1.0,
        description=f"GET /a on stage {_STAGE} serving its Lambda backend",
    )

    # ---- Phase 1: detailed metrics OFF ----
    for _ in range(_PHASE1_A):
        _get_ok("/a")
    for _ in range(_PHASE1_B):
        _get_ok("/b")
    p1 = dict(tally)

    cw = ctx.client("cloudwatch")
    stage_dims = [{"Name": "ApiId", "Value": api_id}, {"Name": "Stage", "Value": _STAGE}]

    p1_count = _poll_until(
        lambda: _metric_sum(cw, "Count", stage_dims, window_start),
        lambda total: total >= p1["ok"],
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description=(
            f"(ApiId={api_id}, Stage={_STAGE}) Count reaching the {p1['ok']} 200s served while "
            f"detailed metrics were off"
        ),
    )
    assert p1_count <= p1["sent"], (
        f"(ApiId, Stage) Count summed to {p1_count} but this check sent only {p1['sent']} requests "
        f"to the stage — a metric cannot count traffic that did not happen"
    )

    p1_bytes = _poll_until(
        lambda: _metric_sum(cw, "DataProcessed", stage_dims, window_start),
        lambda total: total >= p1["payload"],
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description=(
            f"(ApiId={api_id}, Stage={_STAGE}) DataProcessed reaching the {p1['payload']} payload "
            f"bytes (0 request-body bytes sent + response-body bytes received) of the opt-out phase"
        ),
    )
    assert p1_bytes > 0, f"DataProcessed must never be zero after served traffic, got {p1_bytes}"
    assert p1_bytes <= p1["wire"], (
        f"DataProcessed summed to {p1_bytes} bytes, more than the {p1['wire']} bytes this check "
        f"put on the HTTP wire (request + response, headers included) — it cannot count data that "
        f"was never processed"
    )

    listed = _poll_until(
        lambda: _list_api_series(cw, api_id),
        lambda series: _has(series, "Count", {"ApiId", "Stage"})
        and _has(series, "DataProcessed", {"ApiId", "Stage"}),
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description=f"list_metrics showing the (ApiId, Stage) Count and DataProcessed for {api_id}",
    )
    route_level = [s for s in listed if set(s[1]) - {"ApiId", "Stage"}]
    assert not route_level, (
        f"with DetailedMetricsEnabled=false the stage must publish no series beyond (ApiId) and "
        f"(ApiId, Stage), yet the same list_metrics read that shows the stage series also lists "
        f"{route_level!r}"
    )

    # The opt-in is not effective at once, so a separate route (/c) is probed until its route
    # series appears; that proves the opt-in reached the data plane and yields the dimension names.
    updated = agw.update_stage(
        ApiId=api_id, StageName=_STAGE, DefaultRouteSettings={"DetailedMetricsEnabled": True}
    )
    assert updated.get("DefaultRouteSettings", {}).get("DetailedMetricsEnabled") is True, (
        f"UpdateStage must report detailed metrics enabled, returned "
        f"{updated.get('DefaultRouteSettings')!r}"
    )

    barrier = {"sent": 0}

    def _barrier_probe():
        _get_ok("/c")
        barrier["sent"] += 1
        return _route_series(_list_api_series(cw, api_id), "Count", "/c")

    # Each probe sends exactly one /c request, so an empty list_metrics page only costs a round.
    c_series = _poll_until(
        _barrier_probe,
        lambda found: len(found) == 1,
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description="a route-level Count series for GET /c after opting in (the propagation barrier)",
    )
    c_dims = c_series[0]
    route_dim_names = set(c_dims) - {"ApiId", "Stage"}
    assert route_dim_names, f"the /c route series carries no route dimension: {c_dims!r}"
    c_count = _metric_sum(cw, "Count", _as_dims(c_dims), window_start)
    assert c_count <= barrier["sent"], (
        f"route /c Count summed to {c_count} but only {barrier['sent']} requests were sent to /c"
    )

    # ---- Phase 2: detailed metrics ON, traffic to /a only ----
    for _ in range(_PHASE2_A):
        _get_ok("/a")

    a_series = _poll_until(
        lambda: _route_series(_list_api_series(cw, api_id), "Count", "/a"),
        lambda found: len(found) == 1,
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description="a route-level Count series for GET /a after the opt-in",
    )
    a_dims = a_series[0]
    assert set(a_dims) - {"ApiId", "Stage"} == route_dim_names, (
        f"/a and /c route series must use the same dimension names; /a has {sorted(a_dims)!r}, "
        f"/c has {sorted(c_dims)!r}"
    )
    a_count = _poll_until(
        lambda: _metric_sum(cw, "Count", _as_dims(a_dims), window_start),
        lambda total: total >= _PHASE2_A,
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description=f"route-level Count for /a ({a_dims!r}) reaching the {_PHASE2_A} opted-in requests",
    )
    assert a_count == _PHASE2_A, (
        f"route-level Count for /a over the whole window summed to {a_count}; exactly "
        f"{_PHASE2_A} requests were sent after the opt-in took effect, and the "
        f"{p1['ok'] - _PHASE1_B} opt-out requests to /a must not appear at route level"
    )

    # list_metrics can transiently return an EMPTY page for a series it listed seconds earlier,
    # so the /b absence is read only from a response that also contains the /a and stage series.
    final = _poll_until(
        lambda: _list_api_series(cw, api_id),
        lambda series: bool(_route_series(series, "Count", "/a"))
        and _has(series, "Count", {"ApiId", "Stage"}),
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description="a list_metrics read containing both the /a route series and the stage series",
    )
    b_listed = [s for s in final if _refers_to(s[1], "/b")]
    assert not b_listed, (
        f"GET /b received traffic only while detailed metrics were OFF, so no route-level series "
        f"may exist for it; list_metrics returned {b_listed!r}"
    )
    b_dims = {k: (_swap_path(v, "/a", "/b") if k in route_dim_names else v) for k, v in a_dims.items()}
    b_count = _metric_sum(cw, "Count", _as_dims(b_dims), window_start)
    assert b_count == 0, (
        f"route-level Count for /b under the discovered dimensions {b_dims!r} summed to {b_count}; "
        f"it received no requests after the opt-in"
    )

    total = _poll_until(
        lambda: _metric_sum(cw, "Count", stage_dims, window_start),
        lambda value: value >= tally["ok"],
        timeout_s=_budget_s(ctx, _METRIC_TIMEOUT_S),
        ctx=ctx,
        interval_s=_METRIC_INTERVAL_S,
        description=f"(ApiId, Stage) Count reaching all {tally['ok']} 200s served in the run",
    )
    assert total <= tally["sent"], (
        f"(ApiId, Stage) Count summed to {total} over {tally['sent']} requests sent — the stage-level "
        f"series must keep counting every route regardless of the opt-in"
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
    """Sum of every 60 s datapoint since window_start; 0.0 when the series has none."""
    response = cw.get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=list(dimensions),
        StartTime=window_start,
        EndTime=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5),
        Period=60,
        Statistics=["Sum"],
    )
    return float(sum(point["Sum"] for point in response.get("Datapoints", [])))


def _list_api_series(cw, api_id):
    """Every (MetricName, {dim: value}) in AWS/ApiGateway carrying ApiId=<api_id>, paginated."""
    out = []
    for page in cw.get_paginator("list_metrics").paginate(
        Namespace=_NAMESPACE, Dimensions=[{"Name": "ApiId", "Value": api_id}]
    ):
        for metric in page.get("Metrics", []):
            out.append(
                (metric["MetricName"], {d["Name"]: d["Value"] for d in metric["Dimensions"]})
            )
    return out


def _has(series, metric_name, dim_names):
    return any(name == metric_name and set(dims) == dim_names for name, dims in series)


def _refers_to(dims, path):
    """True if a non-ApiId/Stage dimension value names `path` (`/a` or `GET /a` form)."""
    return any(
        v == path or v.endswith(f" {path}")
        for k, v in dims.items()
        if k not in ("ApiId", "Stage")
    )


def _route_series(series, metric_name, path):
    return [
        dims
        for name, dims in series
        if name == metric_name and set(dims) - {"ApiId", "Stage"} and _refers_to(dims, path)
    ]


def _swap_path(value, old, new):
    if value == old:
        return new
    if value.endswith(f" {old}"):
        return value[: -len(old)] + new
    return value


def _as_dims(dims):
    return [{"Name": k, "Value": v} for k, v in sorted(dims.items())]


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


def _http_get(url, timeout_s=20):
    """(status, body_text, wire_bytes). wire_bytes counts the request and response as they cross
    the HTTP layer: request line + headers, status line + headers + body."""
    parts = urllib.parse.urlsplit(url)
    conn_cls = (
        http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    )
    conn = conn_cls(parts.netloc, timeout=timeout_s)
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    headers = {"User-Agent": _UA, "Connection": "close"}
    try:
        conn.request("GET", target, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        resp_headers = resp.getheaders()
    finally:
        conn.close()
    request_bytes = len(f"GET {target} HTTP/1.1\r\n") + len(f"Host: {parts.netloc}\r\n")
    request_bytes += len("Accept-Encoding: identity\r\n") + 2
    request_bytes += sum(len(k) + len(v) + 4 for k, v in headers.items())
    response_bytes = len(f"HTTP/1.1 {resp.status} {resp.reason}\r\n") + 2 + len(raw)
    response_bytes += sum(len(k) + len(v) + 4 for k, v in resp_headers)
    return resp.status, raw.decode("utf-8", "replace"), request_bytes + response_bytes


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


def _create_lambda(ctx, handler_code, timeout=15):
    """Create a Lambda (role scoped to its own logs) through the IAM propagation window, then wait
    for Active. Teardown registered for role, log group (re-reaped after the delete) and function."""
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
