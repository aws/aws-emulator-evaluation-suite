"""xsvc-apigatewayv2-3-http-api-malformed-proxy-response-rejected-500-not-502."""

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

CHECK = "xsvc-apigatewayv2-3-http-api-malformed-proxy-response-rejected-500-not-502"

GROUP = "error-propagation"

SERVICES = ["apigatewayv2", "lambda"]

#: The last path segment picks the shape the handler RETURNS (it never raises):
#:   ok        a well-formed {"statusCode", "body": str} envelope
#:   bare      a JSON object with no statusCode
#:   dictbody  statusCode 200 but a non-string body
#:   strstatus a non-integer statusCode
#:   text      a bare string, not an object at all
_HANDLER = """
import os


def handler(event, context):
    marker = os.environ["MARKER"]
    path = event.get("rawPath") or event.get("path") or ""
    leaf = path.rstrip("/").rsplit("/", 1)[-1]
    if leaf == "bare":
        return {"marker": marker, "shape": "bare"}
    if leaf == "dictbody":
        return {"statusCode": 200, "body": {"marker": marker}}
    if leaf == "strstatus":
        return {"statusCode": "abc", "body": marker}
    if leaf == "text":
        return marker + "-text"
    return {"statusCode": 200, "body": marker + ":" + path}
"""

_INTERNAL_ERROR = '{"message":"Internal Server Error"}'

#: (payload format, leaf) pairs that real AWS classifies as a malformed integration response.
_MALFORMED = (
    ("1.0", "bare"),
    ("1.0", "dictbody"),
    ("1.0", "strstatus"),
    ("1.0", "text"),
    ("2.0", "dictbody"),
    ("2.0", "strstatus"),
)


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An HTTP API answers each malformed Lambda proxy response (four at format 1.0, two at 2.0)
    with exactly 500 {"message":"Internal Server Error"}, not 502, while well-formed twins serve
    200 and the bare-string return that 1.0 rejects is inferred into a 200 by 2.0."""
    marker = _name(ctx, "malformed")
    fn = _create_function(ctx, _HANDLER, env={"MARKER": marker})
    account = _account_id(ctx)

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_name(ctx, "httpapi"), ProtocolType="HTTP", Tags={"sim2real": CHECK}
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    prefix = {"1.0": "/v1", "2.0": "/v2"}
    for version in ("1.0", "2.0"):
        integration_id = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=fn["arn"],
            PayloadFormatVersion=version,
        )["IntegrationId"]
        for leaf in ("ok", "bare", "dictbody", "strstatus", "text"):
            agw.create_route(
                ApiId=api_id,
                RouteKey=f"GET {prefix[version]}/{leaf}",
                Target=f"integrations/{integration_id}",
            )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    _allow_invoke(
        ctx, fn["name"], "apigw-all-routes", f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*"
    )

    # --- positive controls: a well-formed envelope serves at both formats
    for version in ("1.0", "2.0"):
        path = f"{prefix[version]}/ok"
        status, _, text, _ = _poll_http(
            _invoke_url(ctx, api_endpoint, path),
            accept=lambda s, t: s == 200,
            description=f"GET {path} (well-formed envelope, format {version})",
        )
        assert text == f"{marker}:{path}", (
            f"format {version}: the well-formed twin must return {marker + ':' + path!r}, got "
            f"{status} {text[:300]!r}"
        )

    # --- every malformed shape: exactly 500, exactly the generic body, nothing leaked
    for version, leaf in _MALFORMED:
        path = f"{prefix[version]}/{leaf}"
        status, headers, text, _ = _http("GET", _invoke_url(ctx, api_endpoint, path))
        assert status == 500, (
            f"format {version} {leaf!r}: a malformed Lambda proxy response must be answered 500 "
            f"(HTTP API, not REST's 502), got {status} with body {text[:300]!r}"
        )
        assert text == _INTERNAL_ERROR, (
            f"format {version} {leaf!r}: expected the exact body {_INTERNAL_ERROR!r}, got "
            f"{text[:300]!r}"
        )
        assert headers.get("content-type", "").startswith("application/json"), (
            f"format {version} {leaf!r}: expected content-type application/json, got "
            f"{headers.get('content-type')!r}"
        )
        assert marker not in text, (
            f"format {version} {leaf!r}: the malformed payload must not be forwarded; marker "
            f"{marker!r} appeared in {text[:300]!r}"
        )

    # --- the format-specific twin: the bare string 1.0 rejected is inferred by 2.0
    status, _, text, _ = _http("GET", _invoke_url(ctx, api_endpoint, "/v2/text"))
    assert (status, text) == (200, f"{marker}-text"), (
        f"format 2.0 must infer a bare-string return into a 200 whose body is the string, "
        f"expected (200, {marker + '-text'!r}), got ({status}, {text[:300]!r})"
    )

    # --- the other side of the boundary: each malformed shape was a SUCCESSFUL invocation
    lam = ctx.client("lambda")
    for leaf in ("bare", "dictbody", "strstatus", "text"):
        event = {"path": f"/v1/{leaf}"}
        resp = lam.invoke(FunctionName=fn["name"], Payload=json.dumps(event).encode())
        payload = json.loads(resp["Payload"].read())
        assert "FunctionError" not in resp, (
            f"direct Invoke of {event!r} must succeed (the 500 is the gateway's verdict on the "
            f"shape, not a function error), got FunctionError {resp.get('FunctionError')!r} "
            f"with payload {payload!r}"
        )
        assert marker in json.dumps(payload), (
            f"direct Invoke of {event!r} must return the {leaf!r} shape carrying the marker, "
            f"got {payload!r}"
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
