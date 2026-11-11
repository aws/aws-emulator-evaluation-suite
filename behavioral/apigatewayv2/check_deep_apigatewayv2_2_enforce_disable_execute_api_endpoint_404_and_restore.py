"""deep-apigatewayv2-2-enforce-disable-execute-api-endpoint-404-and-restore."""

from __future__ import annotations

import json
import textwrap
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigatewayv2-2-enforce-disable-execute-api-endpoint-404-and-restore"

GROUP = "enforcement"

SERVICES = ["apigatewayv2"]

_NONCE_HEADER = "x-sim2real-nonce"

_HANDLER = """
import os


def lambda_handler(event, context):
    nonce = (event.get("headers") or {}).get("x-sim2real-nonce", "none")
    print("NONCE=" + nonce)
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": os.environ["MARKER"],
    }
"""

#: After every positive nonce is visible in the backend's log, how long a refused request's
#: nonce is still watched for (bounds a late log flush; the refused requests were sent first).
_ABSENCE_WINDOW_S = 20.0
_REFUSED_PROBES = 3


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """UpdateApi(DisableExecuteApiEndpoint=True) makes the HTTP API's default execute-api URL
    answer 404 {"message":"Not Found"} without reaching the backend, while an enabled twin API on
    the same backend keeps serving; clearing the flag restores 200 with the backend's marker.
    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-disable-default-endpoint.html
    """
    marker = ctx.unique_name("sim2real-behav-dis-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})
    log_group = f"/aws/lambda/{fn['name']}"
    account = _account_id(ctx)

    agw = ctx.client("apigatewayv2")
    urls = {}
    for role in ("target", "twin"):
        api = agw.create_api(
            Name=_name(ctx, f"httpapi-dis-{role}"), ProtocolType="HTTP", Tags=_resource_tags()
        )
        api_id = api["ApiId"]
        ctx.on_cleanup(lambda a=api_id: ctx.client("apigatewayv2").delete_api(ApiId=a))
        integration_id = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=fn["arn"],
            IntegrationMethod="POST",
            PayloadFormatVersion="2.0",
        )["IntegrationId"]
        agw.create_route(ApiId=api_id, RouteKey="GET /hit", Target=f"integrations/{integration_id}")
        agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
        ctx.on_cleanup(
            lambda a=api_id: ctx.client("apigatewayv2").delete_stage(ApiId=a, StageName="$default")
        )
        _allow_apigw_invoke(
            ctx,
            fn["name"],
            f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
            statement_id=f"apigw-invoke-{role}",
        )
        urls[role] = (api_id, _invoke_url(ctx, api["ApiEndpoint"], "$default", "/hit"))
    target_id, target_url = urls["target"]
    twin_id, twin_url = urls["twin"]

    # Beat 1 - positive control: both APIs route GET /hit to the backend.
    _wait_routes_deployed([target_url, twin_url])
    for label, url in (("target", target_url), ("twin", twin_url)):
        status, _, text = _http("GET", url)
        assert (status, text) == (200, marker), (
            f"precondition: the {label} API must serve GET /hit with marker {marker!r} while its "
            f"execute-api endpoint is enabled; got {status}: {text[:200]!r}"
        )

    # Beat 2 - disable the target's default endpoint only.
    agw.update_api(ApiId=target_id, DisableExecuteApiEndpoint=True)
    flags = {
        a: agw.get_api(ApiId=a).get("DisableExecuteApiEndpoint") for a in (target_id, twin_id)
    }
    assert flags == {target_id: True, twin_id: False}, (
        f"GetApi must report the flag set on the target API ONLY; got {flags!r}"
    )
    _wait_status(target_url, 404, description="the target's execute-api URL refusing once disabled")

    refused_nonces, twin_nonces = [], []
    for _ in range(_REFUSED_PROBES):
        nonce = f"refused-{uuid.uuid4().hex}"
        refused_nonces.append(nonce)
        status, _, text = _http("GET", target_url, headers={_NONCE_HEADER: nonce})
        assert status == 404, (
            f"a request to a DISABLED execute-api endpoint must be refused with 404, got "
            f"{status}: {text[:200]!r}"
        )
        assert _json_or_none(text) == {"message": "Not Found"}, (
            f'the refusal must be the gateway\'s {{"message":"Not Found"}} envelope, got '
            f"{text[:200]!r}"
        )
        assert marker not in text, f"a refused request leaked the backend marker: {text[:200]!r}"
        twin_nonce = f"twin-{uuid.uuid4().hex}"
        twin_nonces.append(twin_nonce)
        status, _, text = _http("GET", twin_url, headers={_NONCE_HEADER: twin_nonce})
        assert (status, text) == (200, marker), (
            f"the twin API (endpoint still enabled, same backend) must keep serving GET /hit in "
            f"the same instant; got {status}: {text[:200]!r}"
        )

    # Beat 3 - the effect is absent at the destination.
    _poll_until(
        lambda: _log_messages(ctx, log_group, "NONCE="),
        lambda msgs: all(any(f"NONCE={n}" in m for m in msgs) for n in twin_nonces),
        timeout_s=120.0,
        interval_s=4.0,
        description="every twin request's nonce in the backend log",
    )
    deadline = time.monotonic() + _ABSENCE_WINDOW_S
    while True:
        msgs = _log_messages(ctx, log_group, "NONCE=")
        leaked = [m.strip() for m in msgs if any(n in m for n in refused_nonces)]
        assert not leaked, (
            f"a request refused by the disabled endpoint still reached the backend: {leaked!r}"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)

    # Beat 4 - restore: flip the flag back and the same URL serves again.
    agw.update_api(ApiId=target_id, DisableExecuteApiEndpoint=False)
    restored_flag = agw.get_api(ApiId=target_id).get("DisableExecuteApiEndpoint")
    assert restored_flag is False, (
        f"GetApi must report DisableExecuteApiEndpoint=False after re-enabling, got "
        f"{restored_flag!r}"
    )
    _wait_status(target_url, 200, description="the target's execute-api URL serving once re-enabled")
    restore_nonce = f"restored-{uuid.uuid4().hex}"
    status, _, text = _http("GET", target_url, headers={_NONCE_HEADER: restore_nonce})
    assert (status, text) == (200, marker), (
        f"after re-enabling, the target API must serve GET /hit with marker {marker!r} again; got "
        f"{status}: {text[:200]!r}"
    )
    _poll_until(
        lambda: _log_messages(ctx, log_group, restore_nonce),
        lambda msgs: any(f"NONCE={restore_nonce}" in m for m in msgs),
        timeout_s=120.0,
        interval_s=4.0,
        description="the restored request's nonce in the backend log",
    )


def _wait_status(url, want, *, stable_s=25.0, timeout_s=180.0, interval_s=1.0, description="status"):
    """Poll url until it has answered `want` on EVERY request for `stable_s` seconds running.

    The flag reaches the edge node by node, so one answer - or three - is not a settled state. On
    AWS, after a disable 200s can keep arriving for ~10 s, and after a re-enable 404s for ~7 s; a
    streak of 3 x 404 can still be followed by a 200. The settle window is a continuous run of the
    wanted status, not a sleep: any other answer restarts it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    streak_start, seen = None, []
    while True:
        try:
            status = _http("GET", url)[0]
        except OSError as exc:
            status = f"connection error: {exc}"
        now = time.monotonic()
        seen.append(status)
        if status == want:
            streak_start = now if streak_start is None else streak_start
            if now - streak_start >= stable_s:
                return
        else:
            streak_start = None
        if now >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description}: {url} never answered {want} continuously for {stable_s}s within "
        f"{timeout_s}s; statuses seen {seen[-20:]!r}"
    )


# ===== helpers (self-contained) =====


_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _json_or_none(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


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


def _http(method, url, body=None, headers=None, timeout_s=40):
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


def _timed_get(url, headers):
    """(status, text, elapsed_s) for one GET, timed around the whole exchange."""
    t0 = time.monotonic()
    status, _, text = _http("GET", url, headers=headers)
    return status, text, time.monotonic() - t0


def _poll_http(
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=150.0,
    interval_s=3.0,
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


def _wait_routes_deployed(urls, *, passes=3, timeout_s=150.0, interval_s=3.0):
    """Poll until EVERY url answers something other than 404 on `passes` consecutive rounds.

    A new HTTP API deployment reaches the edge node by node, so one live route does not prove its
    siblings are: measured, GET /open served 200 while GET /iam on the same deployment still
    answered 404 from a node that had not caught up. This accepts any status except 404, so it
    never pre-accepts the outcome a check asserts next. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    streak, last = 0, {}
    while True:
        ok = True
        for url in urls:
            try:
                status = _http("GET", url)[0]
            except OSError as exc:  # execute-api DNS/TLS still settling
                status = f"connection error: {exc}"
            last[url] = status
            ok = ok and status != 404 and isinstance(status, int)
        streak = streak + 1 if ok else 0
        if streak >= passes:
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(f"routes not all deployed within {timeout_s}s; last statuses {last!r}")


def _invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of an HTTP API stage. Transport only; guards no assertion."""
    p = path.lstrip("/")
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{p}"


def _log_messages(ctx, log_group, needle):
    """Every message in log_group matching the quoted needle, across all pages."""
    logs = ctx.client("logs")
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=log_group, filterPattern=f'"{needle}"'
        )
        return [e["message"] for page in pages for e in page.get("events", [])]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return []  # the group is created on first invocation
        raise


def _reap_log_group(ctx, log_group, *, quiet_s=30.0, timeout_s=90.0, interval_s=5.0):
    """Delete the Lambda log group and keep re-deleting it until it has stayed ABSENT for
    `quiet_s` running: a buffered flush from an invocation that already returned can recreate
    the group after delete_function (measured: one absent read 5 s after the delete was not
    enough - the group reappeared). Bounded; a residue is declared, never hung on."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    quiet_since = None
    while time.monotonic() < deadline:
        groups = logs.describe_log_groups(logGroupNamePrefix=log_group).get("logGroups", [])
        if any(g["logGroupName"] == log_group for g in groups):
            quiet_since = None
            try:
                logs.delete_log_group(logGroupName=log_group)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
        else:
            quiet_since = time.monotonic() if quiet_since is None else quiet_since
            if time.monotonic() - quiet_since >= quiet_s:
                return
        time.sleep(interval_s)


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
    role_name = _name(ctx, f"role-{trust_service.split('.')[0]}")
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
        Tags=_tags_kv(),
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
    auto-created /aws/lambda/<name> log group (registered BEFORE the function so LIFO reaps the
    group after the delete)."""
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
    name = _name(ctx, "fn")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
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
        "Tags": dict(_resource_tags()),
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
