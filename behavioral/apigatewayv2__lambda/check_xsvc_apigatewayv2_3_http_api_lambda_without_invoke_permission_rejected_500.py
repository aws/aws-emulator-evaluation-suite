"""xsvc-apigatewayv2-3-http-api-lambda-without-invoke-permission-rejected-500."""

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

CHECK = "xsvc-apigatewayv2-3-http-api-lambda-without-invoke-permission-rejected-500"

GROUP = "permission-chain"

SERVICES = ["apigatewayv2", "lambda"]

#: Every route answers with the marker and the path it was reached on, so a 200 proves WHICH
#: route actually invoked the function.
_HANDLER = """
import os


def handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"content-type": "text/plain"},
        "body": os.environ["MARKER"] + ":" + (event.get("rawPath") or ""),
    }
"""

_INTERNAL_ERROR = '{"message":"Internal Server Error"}'


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An HTTP API route not covered by the Lambda's lambda:InvokeFunction grant is answered 500
    {"message":"Internal Server Error"} without reaching the handler, while a covered twin route on
    the same API and function serves 200, and adding the missing statement makes it succeed."""
    marker = _name(ctx, "perm")
    fn = _create_function(ctx, _HANDLER, env={"MARKER": marker})
    account = _account_id(ctx)

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_name(ctx, "httpapi"), ProtocolType="HTTP", Tags={"sim2real": CHECK}
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    for path in ("/granted", "/ungranted"):
        agw.create_route(
            ApiId=api_id, RouteKey=f"GET {path}", Target=f"integrations/{integration_id}"
        )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)

    # The ONLY statement: it covers GET /granted on any stage and nothing else.
    route_arn = f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/GET"
    _allow_invoke(ctx, fn["name"], "granted-only", f"{route_arn}/granted")

    granted_url = _invoke_url(ctx, api_endpoint, "/granted")
    ungranted_url = _invoke_url(ctx, api_endpoint, "/ungranted")

    # --- positive control: the granted twin serves (this is the propagation barrier)
    status, _, text, _ = _poll_http(
        granted_url,
        accept=lambda s, t: s == 200,
        description="GET /granted (covered by the resource-policy statement)",
    )
    assert text == f"{marker}:/granted", (
        f"the granted route must reach the function and return {marker + ':/granted'!r}, "
        f"got {status} {text[:300]!r}"
    )

    # --- the break: the same integration on a route no statement covers
    for attempt in range(3):
        status, headers, text, _ = _http("GET", ungranted_url)
        assert status == 500, (
            f"attempt {attempt + 1}: a route whose Lambda grants API Gateway no "
            f"lambda:InvokeFunction must be answered 500, got {status} with body {text[:300]!r} "
            f"(200 means the target never evaluated the function's resource policy)"
        )
        assert text == _INTERNAL_ERROR, (
            f"attempt {attempt + 1}: expected the exact body {_INTERNAL_ERROR!r}, got {text[:300]!r}"
        )
        assert headers.get("content-type", "").startswith("application/json"), (
            f"attempt {attempt + 1}: expected content-type application/json on the 500, got "
            f"{headers.get('content-type')!r}"
        )
        assert marker not in text, (
            f"effect-absent: the function must not have produced the response; marker "
            f"{marker!r} appeared in {text[:300]!r}"
        )

    # --- the twin still serves in the same instant: the API is healthy, only the grant differs
    status, _, text, _ = _http("GET", granted_url)
    assert (status, text) == (200, f"{marker}:/granted"), (
        f"the granted twin must keep serving beside the refused route, got {status} {text[:300]!r}"
    )

    policy = json.loads(ctx.client("lambda").get_policy(FunctionName=fn["name"])["Policy"])
    sids = sorted(stmt.get("Sid") for stmt in policy.get("Statement", []))
    assert sids == ["granted-only"], (
        f"the function's resource policy must hold exactly the one route-scoped statement during "
        f"the refusal, got Sids {sids!r}"
    )

    # --- repair the one broken thing; the IDENTICAL request now reaches the function
    _allow_invoke(ctx, fn["name"], "ungranted-repaired", f"{route_arn}/ungranted")
    status, _, text, _ = _poll_http(
        ungranted_url,
        accept=lambda s, t: s == 200,
        timeout_s=180.0,
        description="GET /ungranted once a statement covering it was added",
    )
    assert text == f"{marker}:/ungranted", (
        f"after the repair the previously refused route must reach the function and return "
        f"{marker + ':/ungranted'!r}, got {status} {text[:300]!r}"
    )


# ===== helpers (self-contained) =====

_PREFIX = "sim2real-xsvc-"


def _name(ctx, kind):
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")
        time.sleep(interval_s)


def _http(method, url, body=None, headers=None, timeout_s=40):
    """(status, {lower-name: value}, text, elapsed_s). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            text = resp.read().decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, hdrs, text, time.monotonic() - started
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace")
        hdrs = {k.lower(): v for k, v in exc.headers.items()}
        return exc.code, hdrs, text, time.monotonic() - started


def _poll_http(url, *, accept, timeout_s=150.0, interval_s=3.0, description="invoke URL"):
    """Poll a GET until accept(status, text); return (status, headers, text, elapsed)."""
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "", 0.0)
    while True:
        try:
            last = _http("GET", url)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, {}, f"connection error: {exc}", 0.0)
        else:
            if accept(last[0], last[2]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _invoke_url(ctx, api_endpoint, path):
    """The $default-stage invoke URL of an HTTP API, from ``ctx.stage_url``."""
    p = path.lstrip("/")
    return f"{ctx.stage_url(api_endpoint, '$default')}/{p}"


def _reap_log_group(ctx, fn_name):
    """Delete /aws/lambda/<fn> in a loop: a buffered stream can recreate it after a delete."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise RuntimeError(f"could not delete log group {group}: {exc}") from exc
        time.sleep(4)
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g.get("logGroupName") == group for g in found):
            return
    raise RuntimeError(f"log group {group} kept reappearing after its function was deleted")


def _create_function(ctx, code, *, env, timeout_s=10):
    """A python3.12 function behind a role with NO policies (so it writes no logs), retried
    through the role-propagation window, then waited to Active. Teardown for role, function and
    the /aws/lambda/<fn> log group is registered in the order LIFO needs."""
    iam = ctx.client("iam")
    role_name = _name(ctx, "role")
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
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    lam = ctx.client("lambda")
    name = _name(ctx, "fn")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "index.handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout_s,
        "MemorySize": 128,
        "Environment": {"Variables": env},
        "Tags": {"sim2real": CHECK},
    }

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None  # the brand-new role is not yet assumable by Lambda
            raise

    created = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"CreateFunction {name} once its execution role became assumable",
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


def _allow_invoke(ctx, fn_name, statement_id, source_arn):
    """One resource-policy statement letting API Gateway invoke fn_name from source_arn. It is
    removed with the function, so it needs no cleanup of its own."""
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
