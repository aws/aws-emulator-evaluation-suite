"""deep-apigatewayv2-2-enforce-integration-timeout-503-while-twin-route-serves."""

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

CHECK = "deep-apigatewayv2-2-enforce-integration-timeout-503-while-twin-route-serves"

GROUP = "enforcement"

SERVICES = ["apigatewayv2"]

#: How long the backend sleeps on EVERY invocation. Both routes hit the same function, so the
#: only asymmetry between them is the integration's TimeoutInMillis.
_SLEEP_S = 3.0
_SHORT_TIMEOUT_MS = 1000
_LONG_TIMEOUT_MS = 30000
# The raised timeout is settled once GET /slow answers 200 continuously for this fixed span.
_SETTLE_S = 10.0

_HANDLER = """
import os
import time


def lambda_handler(event, context):
    nonce = (event.get("headers") or {}).get("x-sim2real-nonce", "none")
    print("NONCE=" + nonce)
    time.sleep(float(os.environ["SLEEP_S"]))
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": os.environ["MARKER"],
    }
"""


# timing:real-time — workflow: 1 s https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html
@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An HTTP API route whose integration TimeoutInMillis (1000) is shorter than the backend's 3 s
    sleep gets the gateway's 503 Service Unavailable while a 30000 ms twin route serves the marker;
    raising the timeout makes the same route serve. HTTP APIs answer 503 here, not REST's 504.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html
    Reference: https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-integrations.html
    """
    marker = ctx.unique_name("sim2real-behav-tmo-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker, "SLEEP_S": str(_SLEEP_S)}, timeout=15)

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_name(ctx, "httpapi-timeout"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    short_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
        TimeoutInMillis=_SHORT_TIMEOUT_MS,
    )["IntegrationId"]
    long_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
        TimeoutInMillis=_LONG_TIMEOUT_MS,
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /slow", Target=f"integrations/{short_id}")
    agw.create_route(ApiId=api_id, RouteKey="GET /twin", Target=f"integrations/{long_id}")
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    )

    stored = {
        iid: agw.get_integration(ApiId=api_id, IntegrationId=iid)["TimeoutInMillis"]
        for iid in (short_id, long_id)
    }
    assert stored == {short_id: _SHORT_TIMEOUT_MS, long_id: _LONG_TIMEOUT_MS}, (
        f"precondition: the two integrations must store {_SHORT_TIMEOUT_MS} and "
        f"{_LONG_TIMEOUT_MS} ms so the routes differ ONLY in timeout; GetIntegration says {stored!r}"
    )

    slow_url = _invoke_url(ctx, api["ApiEndpoint"], "$default", "/slow")
    twin_url = _invoke_url(ctx, api["ApiEndpoint"], "$default", "/twin")

    # Beat 1 - positive control: the twin route waits out the 3 s backend and serves its marker.
    _wait_routes_deployed(ctx, [twin_url, slow_url], timeout_s=_budget_s(ctx, 150.0), interval_s=1.0)
    twin_status, twin_text, twin_elapsed = _timed_get(twin_url, {})
    assert twin_status == 200, f"GET /twin should serve 200, got {twin_status}: {twin_text[:200]!r}"
    assert twin_text == marker, (
        f"GET /twin should return this check's backend marker {marker!r}, got {twin_text[:200]!r}"
    )
    assert twin_elapsed >= _SLEEP_S, (
        f"GET /twin returned after {twin_elapsed:.2f}s, faster than the backend's {_SLEEP_S}s "
        f"sleep - the backend under test is not the one answering"
    )

    # Beat 2 - the negative: the identical request on the 1000 ms route is cut off by the gateway.
    nonce = f"slow-{uuid.uuid4().hex}"
    slow_status, slow_text, slow_elapsed = _timed_get(slow_url, {"x-sim2real-nonce": nonce})
    assert slow_status == 503, (
        f"GET /slow (TimeoutInMillis={_SHORT_TIMEOUT_MS}, backend sleeps {_SLEEP_S}s) must be cut "
        f"off by the gateway with 503, got {slow_status} after {slow_elapsed:.2f}s: "
        f"{slow_text[:200]!r}"
    )
    assert _json_or_none(slow_text) == {"message": "Service Unavailable"}, (
        f"the timeout response must be the gateway's own envelope "
        f'{{"message":"Service Unavailable"}}, got {slow_text[:200]!r}'
    )
    assert marker not in slow_text, (
        f"a timed-out request must not deliver the backend's marker {marker!r}; got "
        f"{slow_text[:200]!r}"
    )
    assert slow_elapsed >= _SHORT_TIMEOUT_MS / 1000.0, (
        f"the gateway answered GET /slow after {slow_elapsed:.2f}s, BEFORE its "
        f"{_SHORT_TIMEOUT_MS} ms integration timeout could have elapsed - that is not a timeout"
    )
    assert slow_elapsed < _SLEEP_S, (
        f"the gateway answered GET /slow after {slow_elapsed:.2f}s, i.e. it waited out the "
        f"{_SLEEP_S}s backend instead of enforcing its {_SHORT_TIMEOUT_MS} ms timeout"
    )

    # The backend DID run for that request: the 503 is a timeout, not a failed invocation.
    log_group = f"/aws/lambda/{fn['name']}"
    _poll_until(
        ctx, lambda: _log_messages(ctx, log_group, nonce),
        lambda msgs: any(f"NONCE={nonce}" in m for m in msgs),
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=1.0,
        description=f"the backend's log showing it was invoked for the timed-out request {nonce}",
    )

    # Beat 3 - restore: raise /slow's timeout and demand the identical request succeed.
    agw.update_integration(ApiId=api_id, IntegrationId=short_id, TimeoutInMillis=_LONG_TIMEOUT_MS)
    after = agw.get_integration(ApiId=api_id, IntegrationId=short_id)["TimeoutInMillis"]
    assert after == _LONG_TIMEOUT_MS, (
        f"UpdateIntegration must store TimeoutInMillis={_LONG_TIMEOUT_MS}, GetIntegration says "
        f"{after!r}"
    )
    # UpdateIntegration reaches the edge node by node: a 200 can be followed by a 503 from a node
    # still holding the 1000 ms timeout. Settle on a continuous run of 200s.
    _wait_status(
        ctx, slow_url,
        200,
        stable_s=_SETTLE_S,
        timeout_s=_budget_s(ctx, 180.0),
        description=f"GET /slow serving once its integration timeout is raised to {_LONG_TIMEOUT_MS}",
    )
    restored_status, restored_text, restored_elapsed = _timed_get(slow_url, {})
    assert (restored_status, restored_text) == (200, marker), (
        f"GET /slow must keep serving the marker once restored, got {restored_status}: "
        f"{restored_text[:200]!r}"
    )
    assert restored_elapsed >= _SLEEP_S, (
        f"restored GET /slow answered after {restored_elapsed:.2f}s, faster than the backend's "
        f"{_SLEEP_S}s sleep"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_status(ctx, url, want, *, stable_s=20.0, timeout_s=180.0, interval_s=1.0, description="status"):
    """Poll url until it has answered `want` on EVERY request for `stable_s` seconds running.
    Any other answer restarts the run, so this is a settled state, not a sleep. RAISES on
    timeout."""
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
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description}: {url} never answered {want} continuously for {stable_s}s within "
        f"{timeout_s:.0f}s; statuses seen {seen[-20:]!r}"
    )


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


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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


def _wait_routes_deployed(ctx, urls, *, passes=3, timeout_s=150.0, interval_s=3.0):
    """Poll until EVERY url answers something other than 404 on `passes` consecutive rounds.

    A new deployment reaches the edge node by node, so one live route does not prove its siblings."""
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
    if _budget_spent(ctx):
        raise TimeoutError(f"routes {urls!r} all deployed: the run budget ended first; not graded")
    raise AssertionError(f"routes not all deployed within {timeout_s}s; last statuses {last!r}")


def _invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of an HTTP API stage."""
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
    """Re-delete the Lambda log group until it stays absent for `quiet_s`: a buffered flush from
    an invocation that already returned can recreate it after delete_function."""
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
    """Create a Lambda (role scoped to logs plus `permissions`), retrying through IAM role
    propagation, then wait for Active. The log-group reap is registered first so LIFO runs it last."""
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
        ctx, _try_create,
        lambda r: r is not None,
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=2.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        ctx, lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=1.0,
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
