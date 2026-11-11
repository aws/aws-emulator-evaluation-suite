"""access-log-record-joins-the-gateway-request-id."""

from __future__ import annotations

import json
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-log-record-joins-the-gateway-request-id"

GROUP = "observability"

SERVICES = ["apigatewayv2", "lambda", "logs"]

#: The integration reports the gateway's own request id back to the client. That makes the client a
#: SECOND independent observer of the same request, so the access log record can be joined to it
#: without trusting any response header name.
_HANDLER = """
import json
import os


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(
            {
                "marker": os.environ["MARKER"],
                "gwRequestId": rc.get("requestId"),
                "routeKey": rc.get("routeKey"),
                "rawPath": event.get("rawPath"),
            }
        ),
    }
"""

_ROUTE_KEY = "GET /items/{item}"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A stage's AccessLogSettings deliver one CloudWatch Logs record per matched request whose ``$context.requestId``,
    path, route key and status join the integration's own view of that request, and a request matching no route
    produces no access log record, measured against a later matched request that is delivered."""
    marker = ctx.unique_name("alog-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})

    logs = ctx.client("logs")
    log_group = f"/sim2real/xsvc/{_xname(ctx, 'accesslogs')}"
    logs.create_log_group(logGroupName=log_group, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=log_group))
    log_group_arn = f"arn:aws:logs:{ctx.region}:{_account_id(ctx)}:log-group:{log_group}"

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_xname(ctx, "httpapi-accesslog"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=api_id, RouteKey=_ROUTE_KEY, Target=f"integrations/{integration_id}"
    )
    # The static "marker" field is what isolates THIS check's records inside the group, and the
    # format is deliberately JSON so every field can be asserted rather than string-matched.
    log_format = json.dumps(
        {
            "marker": marker,
            "requestId": "$context.requestId",
            "routeKey": "$context.routeKey",
            "path": "$context.path",
            "status": "$context.status",
        }
    )
    agw.create_stage(
        ApiId=api_id,
        StageName="$default",
        AutoDeploy=True,
        AccessLogSettings={"DestinationArn": log_group_arn, "Format": log_format},
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    )

    stored = (agw.get_stage(ApiId=api_id, StageName="$default").get("AccessLogSettings")) or {}
    # Compared by log-group name rather than by exact ARN: API Gateway may normalise the destination
    # (e.g. append a ':*' stream qualifier), which would make an equality check a false failure.
    assert log_group in (stored.get("DestinationArn") or ""), (
        f"the stage must carry the access log destination before delivery means anything; GetStage "
        f"reports DestinationArn {stored.get('DestinationArn')!r}, which does not name log group "
        f"{log_group!r}"
    )
    assert stored.get("Format") == log_format, (
        f"the stage must store the authored access log format verbatim; GetStage reports "
        f"{stored.get('Format')!r}"
    )

    # Two requests to the same route, each with its own path so a record can be attributed to it.
    observed = {}
    for item in ("one", "two"):
        status, _, text = _poll_http(
            _v2_invoke_url(ctx, api_endpoint, "$default", f"/items/{item}"),
            accept=lambda s: s == 200,
            description=f"GET /items/{item}",
        )
        assert status == 200, f"expected 200 from GET /items/{item}, got {status}: {text[:300]!r}"
        payload = json.loads(text)
        assert payload.get("marker") == marker, (
            f"GET /items/{item} must reach this check's backend (marker {marker!r}), got "
            f"{text[:300]!r}"
        )
        request_id = payload.get("gwRequestId")
        assert request_id, (
            f"the integration event carried no requestContext.requestId for /items/{item}: "
            f"{payload!r}"
        )
        observed[item] = request_id

    assert observed["one"] != observed["two"], (
        f"two separate requests must carry two different gateway request ids, both were "
        f"{observed['one']!r}"
    )

    # A third request that matches no route: the gateway answers 404 without invoking anything.
    status, _, text = _http("GET", _v2_invoke_url(ctx, api_endpoint, "$default", "/nope"))
    assert status == 404, (
        f"expected 404 for a path matching no route, got {status}: {text[:300]!r}"
    )
    assert marker not in text, (
        f"the 404 must not come from the integration; body was {text[:300]!r}"
    )

    # Delivery, matched routes: poll until both integration-observed request ids have a record.
    # The elapsed time is this run's delivery latency on this wiring, which sets how long the
    # unmatched-route absence below must be held.
    wanted_ids = set(observed.values())
    _delivery_start = time.monotonic()
    records = _poll_until(
        lambda: _access_log_records(ctx, log_group, marker),
        lambda rs: wanted_ids.issubset({r.get("requestId") for r in rs}),
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            f"access log records in {log_group} for both integration-observed request ids "
            f"{sorted(wanted_ids)}"
        ),
    )
    positive_latency_s = time.monotonic() - _delivery_start

    for item, request_id in observed.items():
        matching = [r for r in records if r.get("requestId") == request_id]
        assert len(matching) == 1, (
            f"expected EXACTLY ONE access log record for the request the integration saw as "
            f"{request_id!r} (GET /items/{item}), got {len(matching)}: {matching!r}"
        )
        record = matching[0]
        assert record.get("status") == "200", (
            f"the record for {request_id!r} must report the status the client received (200), got "
            f"{record.get('status')!r}"
        )
        assert record.get("routeKey") == _ROUTE_KEY, (
            f"the record for {request_id!r} must report the matched route key {_ROUTE_KEY!r}, got "
            f"{record.get('routeKey')!r}"
        )
        assert record.get("path") == f"/items/{item}", (
            f"the record for {request_id!r} must report the REQUEST path '/items/{item}' rather "
            f"than the route template, got {record.get('path')!r}"
        )

    # Absence, unmatched route: no '/nope' record appears while the hold lasts at least 3x the
    # delivery latency just measured for the matched-route records on this same wiring.
    hold_s = min(max(3.0 * positive_latency_s, 15.0), 150.0)
    deadline = time.monotonic() + hold_s
    while True:
        current = _access_log_records(ctx, log_group, marker)
        leaked = [r for r in current if r.get("path") == "/nope"]
        assert not leaked, (
            f"a request matching no route must never appear in the access log (held "
            f"{hold_s:.0f}s, >= 3x the {positive_latency_s:.0f}s matched-route delivery latency "
            f"measured on this same wiring) — found {leaked!r}"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)

    # Delivery barrier: a matched request sent AFTER the unmatched one and after the hold is
    # delivered, so the absence proven is specific to '/nope', not a stalled pipeline that would
    # make every record (including the matched ones) equally absent.
    status, _, text = _poll_http(
        _v2_invoke_url(ctx, api_endpoint, "$default", "/items/after"),
        accept=lambda s: s == 200,
        description="GET /items/after (delivery barrier)",
    )
    barrier = json.loads(text)
    assert barrier.get("marker") == marker and barrier.get("gwRequestId"), (
        f"GET /items/after must reach this check's backend and carry a request id, got "
        f"{text[:300]!r}"
    )
    barrier_id = barrier["gwRequestId"]
    final = _poll_until(
        lambda: _access_log_records(ctx, log_group, marker),
        lambda rs: any(r.get("requestId") == barrier_id for r in rs),
        timeout_s=120.0,
        interval_s=5.0,
        description=f"the access log record for the barrier request {barrier_id!r}",
    )
    leaked = [r for r in final if r.get("path") == "/nope"]
    assert not leaked, (
        f"a request matching no route must never appear in the access log, even once a request "
        f"sent after it was delivered — found {leaked!r}"
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


def _access_log_records(ctx, log_group, marker):
    """Every JSON access log record in log_group carrying this check's static marker.

    A missing log group means "nothing delivered yet" — API Gateway creates the log streams
    asynchronously. A record that is not parseable JSON is kept as {"raw": ...} so a target that
    emits the format string un-expanded fails an assertion rather than being silently dropped.
    """
    logs = ctx.client("logs")
    out = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=log_group, limit=200
        ):
            for event in page.get("events", []):
                message = event.get("message", "")
                if marker not in message:
                    continue
                try:
                    parsed = json.loads(message)
                except ValueError:
                    parsed = {"raw": message}
                out.append(parsed)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return out


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


def _poll_http(
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=150.0,
    interval_s=4.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
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
