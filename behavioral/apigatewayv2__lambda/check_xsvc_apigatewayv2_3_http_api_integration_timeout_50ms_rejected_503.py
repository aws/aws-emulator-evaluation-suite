"""xsvc-apigatewayv2-3-http-api-integration-timeout-50ms-rejected-503."""

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

CHECK = "xsvc-apigatewayv2-3-http-api-integration-timeout-50ms-rejected-503"

GROUP = "error-propagation"

SERVICES = ["apigatewayv2", "lambda"]

_SLEEP_S = 3.0          # how long the handler takes on EVERY route
_SHORT_MS = 50          # the modelled minimum TimeoutInMillis
_LONG_MS = 30000        # the modelled maximum, used for the twin and for the restore

_HANDLER = """
import os
import time


def handler(event, context):
    time.sleep(float(os.environ["SLEEP_S"]))
    path = event.get("rawPath") or event.get("path") or ""
    return {"statusCode": 200, "body": os.environ["MARKER"] + ":" + path}
"""

_UNAVAILABLE = '{"message":"Service Unavailable"}'


# timing:real-time — workflow: 1 s https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html
@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An HTTP API Lambda integration with TimeoutInMillis=50 before a 3 s handler answers exactly
    503 {"message":"Service Unavailable"} in under 3 s at both payload formats, while a twin at
    30000 serves 200 after at least 3 s, and raising the short one to 30000 makes it succeed."""
    marker = _name(ctx, "timeout")
    fn = _create_function(ctx, _HANDLER, env={"MARKER": marker, "SLEEP_S": str(_SLEEP_S)})
    account = _account_id(ctx)

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_name(ctx, "httpapi"), ProtocolType="HTTP", Tags={"sim2real": CHECK}
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    integrations = {}
    for key, version, timeout_ms, path in (
        ("twin", "2.0", _LONG_MS, "/twin"),
        ("short2", "2.0", _SHORT_MS, "/short2"),
        ("short1", "1.0", _SHORT_MS, "/short1"),
    ):
        integrations[key] = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=fn["arn"],
            PayloadFormatVersion=version,
            TimeoutInMillis=timeout_ms,
        )["IntegrationId"]
        agw.create_route(
            ApiId=api_id, RouteKey=f"GET {path}", Target=f"integrations/{integrations[key]}"
        )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    _allow_invoke(
        ctx, fn["name"], "apigw-all-routes", f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*"
    )

    stored = agw.get_integration(ApiId=api_id, IntegrationId=integrations["short2"])
    assert stored.get("TimeoutInMillis") == _SHORT_MS, (
        f"GetIntegration must report the configured TimeoutInMillis {_SHORT_MS}, got "
        f"{stored.get('TimeoutInMillis')!r}"
    )

    # --- positive control: the 30000 ms twin waits for the sleeping handler and serves
    status, _, text, elapsed = _poll_http(
        _invoke_url(ctx, api_endpoint, "/twin"),
        accept=lambda s, t: s == 200,
        description=f"GET /twin (TimeoutInMillis={_LONG_MS})",
    )
    assert text == f"{marker}:/twin", (
        f"the {_LONG_MS} ms twin must return {marker + ':/twin'!r}, got {status} {text[:300]!r}"
    )
    assert elapsed >= _SLEEP_S, (
        f"the handler sleeps {_SLEEP_S}s, so the twin's 200 must take at least that long; got "
        f"{elapsed:.2f}s, which means the backend did not really run"
    )

    # --- the break: the same function behind a 50 ms deadline, at both payload formats
    for path in ("/short2", "/short1"):
        status, headers, text, elapsed = _http("GET", _invoke_url(ctx, api_endpoint, path))
        assert status == 503, (
            f"GET {path}: a Lambda integration that outlives TimeoutInMillis={_SHORT_MS} must "
            f"be answered 503 by an HTTP API, got {status} after {elapsed:.2f}s with body "
            f"{text[:300]!r} (200 = deadline ignored; 504 = REST API's mapping)"
        )
        assert text == _UNAVAILABLE, (
            f"GET {path}: expected the exact body {_UNAVAILABLE!r}, got {text[:300]!r}"
        )
        assert headers.get("content-type", "").startswith("application/json"), (
            f"GET {path}: expected content-type application/json, got "
            f"{headers.get('content-type')!r}"
        )
        assert elapsed < _SLEEP_S, (
            f"GET {path}: the 503 must arrive before the {_SLEEP_S}s handler could answer, "
            f"proving the configured {_SHORT_MS} ms deadline governed; got {elapsed:.2f}s"
        )
        assert marker not in text, (
            f"GET {path}: effect-absent — the timed-out response must not carry the handler's "
            f"marker {marker!r}, got {text[:300]!r}"
        )

    # --- restore the one broken thing; the IDENTICAL request now waits and serves
    agw.update_integration(
        ApiId=api_id, IntegrationId=integrations["short2"], TimeoutInMillis=_LONG_MS
    )
    status, _, text, elapsed = _poll_http(
        _invoke_url(ctx, api_endpoint, "/short2"),
        accept=lambda s, t: s == 200,
        timeout_s=180.0,
        description=f"GET /short2 once its TimeoutInMillis was raised to {_LONG_MS}",
    )
    assert text == f"{marker}:/short2", (
        f"after the restore /short2 must reach the handler and return {marker + ':/short2'!r}, "
        f"got {status} after {elapsed:.2f}s with body {text[:300]!r}"
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
