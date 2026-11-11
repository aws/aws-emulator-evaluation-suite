"""xsvc-apigatewayv2-3-http-api-lambda-handler-raises-rejected-500."""

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

CHECK = "xsvc-apigatewayv2-3-http-api-lambda-handler-raises-rejected-500"

GROUP = "error-propagation"

SERVICES = ["apigatewayv2", "lambda"]

#: One handler behind both payload formats. Only the last path segment decides whether it
#: raises, and the exception message carries a secret that must never reach the HTTP client.
_HANDLER = """
import os


def handler(event, context):
    path = event.get("rawPath") or event.get("path") or ""
    if path.endswith("/boom"):
        raise RuntimeError("sim2real-secret:" + os.environ["MARKER"])
    return {"statusCode": 200, "body": os.environ["MARKER"] + ":" + path}
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
    """A Lambda proxy handler that raises surfaces to the HTTP API client as exactly 500
    {"message":"Internal Server Error"} at payload formats 1.0 and 2.0, withholding the error
    message and type, while the twin `/ok` route on the same function returns 200."""
    marker = _name(ctx, "raise")
    fn = _create_function(ctx, _HANDLER, env={"MARKER": marker})
    account = _account_id(ctx)

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_name(ctx, "httpapi"), ProtocolType="HTTP", Tags={"sim2real": CHECK}
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    for version, prefix in (("1.0", "/v1"), ("2.0", "/v2")):
        integration_id = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=fn["arn"],
            PayloadFormatVersion=version,
        )["IntegrationId"]
        for leaf in ("ok", "boom"):
            agw.create_route(
                ApiId=api_id,
                RouteKey=f"GET {prefix}/{leaf}",
                Target=f"integrations/{integration_id}",
            )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    _allow_invoke(
        ctx, fn["name"], "apigw-all-routes", f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*"
    )

    for prefix in ("/v1", "/v2"):
        # --- positive control: the twin route on the same integration serves
        status, _, text, _ = _poll_http(
            _invoke_url(ctx, api_endpoint, f"{prefix}/ok"),
            accept=lambda s, t: s == 200,
            description=f"GET {prefix}/ok (healthy twin)",
        )
        assert text == f"{marker}:{prefix}/ok", (
            f"the healthy twin {prefix}/ok must return {marker + ':' + prefix + '/ok'!r}, "
            f"got {status} {text[:300]!r}"
        )

        # --- the raising route: exact status, exact body, nothing of the error leaked
        status, headers, text, _ = _http("GET", _invoke_url(ctx, api_endpoint, f"{prefix}/boom"))
        assert status == 500, (
            f"a raising handler behind {prefix} must surface as 500, got {status} with body "
            f"{text[:300]!r}"
        )
        assert text == _INTERNAL_ERROR, (
            f"{prefix}: expected the exact body {_INTERNAL_ERROR!r}, got {text[:300]!r}"
        )
        assert headers.get("content-type", "").startswith("application/json"), (
            f"{prefix}: expected content-type application/json, got {headers.get('content-type')!r}"
        )
        for leaked in (marker, "RuntimeError", "errorMessage", "errorType"):
            assert leaked not in text, (
                f"{prefix}: the Lambda error document must not reach the client; found "
                f"{leaked!r} in {text[:300]!r}"
            )

    # --- the other side of the boundary: the function really raised, and carried the secret
    lam = ctx.client("lambda")
    for event in ({"path": "/v1/boom"}, {"rawPath": "/v2/boom"}):
        resp = lam.invoke(FunctionName=fn["name"], Payload=json.dumps(event).encode())
        payload = json.loads(resp["Payload"].read())
        assert resp.get("FunctionError") == "Unhandled", (
            f"direct Invoke of {event!r} must report FunctionError 'Unhandled', got "
            f"{resp.get('FunctionError')!r} with payload {payload!r}"
        )
        assert payload.get("errorType") == "RuntimeError", (
            f"direct Invoke of {event!r} must carry errorType 'RuntimeError', got {payload!r}"
        )
        assert payload.get("errorMessage") == f"sim2real-secret:{marker}", (
            f"direct Invoke of {event!r} must carry the secret the gateway withheld, got "
            f"{payload.get('errorMessage')!r}"
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
