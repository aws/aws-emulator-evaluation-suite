"""apigw-lambda-authorizer-deny-blocks-backend-invocation."""

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

CHECK = "apigw-lambda-authorizer-deny-blocks-backend-invocation"

GROUP = "overly-permissive"

SERVICES = ["apigateway", "lambda", "logs"]


_AUTHORIZER = """
def lambda_handler(event, context):
    token = event.get("authorizationToken") or ""
    effect = "Allow" if token == "allow-me" else "Deny"
    return {
        "principalId": "sim2real-principal",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": event["methodArn"],
                }
            ],
        },
    }
"""

_BACKEND = """
import json
import os


def lambda_handler(event, context):
    # The one observable that separates 'authorizer denied' from 'authorizer ignored'.
    print("BACKEND-INVOKED " + os.environ["MARKER"])
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": os.environ["MARKER"]}),
    }
"""


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:endpoint",
    "plane:data", "resource:account-singleton:apigateway-account",
)
def run(ctx) -> None:
    """A TOKEN authorizer returning Deny answers 403 and the backend Lambda logs no invocation marker,
    while an allowing token returns 200 and the marker appears."""
    marker = ctx.unique_name("backend-")
    authorizer_fn = _create_lambda(ctx, _AUTHORIZER)
    backend = _create_lambda(ctx, _BACKEND, env={"MARKER": marker})
    backend_log_group = f"/aws/lambda/{backend['name']}"
    access_log = _create_log_group(ctx, kind="apigw-authzlog")
    # Prerequisite: without the account-level cloudwatchRoleArn UpdateStage refuses the
    # accessLogSettings patch; it is set here and restored on cleanup.
    _ensure_account_cloudwatch_role(ctx)

    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, kind="apigw-authz")
    account = _account_id(ctx)
    authorizer_id = ag.create_authorizer(
        restApiId=api_id,
        name=_xname(ctx, "tokenauthz"),
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{authorizer_fn['arn']}/invocations"
        ),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )["id"]
    _allow_apigw_invoke(
        ctx,
        authorizer_fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/authorizers/{authorizer_id}",
        statement_id="apigw-authorizer",
    )

    res_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="secure")[
        "id"
    ]
    ag.put_method(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{backend['arn']}/invocations"
        ),
    )
    _allow_apigw_invoke(
        ctx,
        backend["name"],
        f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
        statement_id="apigw-backend",
    )
    _deploy_stage(
        ctx,
        api_id,
        "test",
        accessLogSettings={
            "destinationArn": access_log["arn"],
            # UpdateStage refuses a format without $context.requestId or
            # $context.extendedRequestId, so requestId is in the format and asserted below.
            "format": json.dumps(
                {
                    "requestId": "$context.requestId",
                    "status": "$context.status",
                    "path": "$context.path",
                }
            ),
        },
    )

    url = _rest_invoke_url(ctx, api_id, "test", "/secure")
    start_ms = int(time.time() * 1000) - 60_000

    # Break exactly one thing: a token the authorizer denies.
    deny_status, _, deny_text = _poll_http(
        url,
        accept=lambda s: s in (200, 401, 403),
        headers={"Authorization": "deny-me"},
        description="denied request to the authorizer-protected route",
    )
    assert deny_status == 403, (
        f"expected 403 for a request the Lambda authorizer explicitly Denied, got "
        f"{deny_status}: {deny_text!r} (200 => the emulator ignored the authorizer's "
        f"policy document)"
    )
    assert "not authorized" in deny_text.lower(), (
        f"expected API Gateway's explicit-deny message, got {deny_text!r}"
    )

    # The effect that must never appear: the backend running for a denied request.
    _stays_absent(
        lambda: _log_events_containing(
            ctx, backend_log_group, f"BACKEND-INVOKED {marker}", start_ms
        ),
        lambda msgs: bool(msgs),
        # At least as long as the control's confirmed-delivery timeout below (120s), never shorter.
        # An absence window narrower than the window in which delivery is known to be observable is
        # unsound: Lambda log delivery routinely exceeds 30s, so a backend that WAS wrongly invoked
        # could emit its line at 40-90s -- after a 30s window closed, but inside the control's 120s
        # -- and both legs would pass. That is a false pass on the exact over-permissiveness this
        # check exists to catch.
        window_s=120.0,
        interval_s=5.0,
        description=(
            f"a BACKEND-INVOKED log line in {backend_log_group} (the backend Lambda "
            f"running despite the authorizer's Deny)"
        ),
    )

    # The gateway itself recorded the 403 — the request was seen and rejected, not dropped.
    # The denied request is re-issued until one is logged, since the first requests after access
    # logging is enabled are not logged; each re-issue must still return 403.
    access_records, _ = _request_until_logged(
        ctx,
        url,
        log_group=access_log["name"],
        needle='"403"',
        start_ms=start_ms,
        expect_status=403,
        headers={"Authorization": "deny-me"},
        description="denied request to the authorizer-protected route",
    )
    assert any("/secure" in msg for msg in access_records), (
        f"the 403 access-log record should name /secure, got {access_records[:3]!r}"
    )
    # Re-assert the absence after the additional denied requests issued above: every one
    # of them was refused at the gateway, so the backend still must never have run.
    still_absent = _log_events_containing(
        ctx, backend_log_group, f"BACKEND-INVOKED {marker}", start_ms
    )
    assert not still_absent, (
        f"the backend Lambda ran for one of the denied requests -- {still_absent[:2]!r}"
    )
    denied_record = None
    for msg in access_records:
        try:
            candidate = json.loads(msg)
        except ValueError:
            continue
        if candidate.get("path", "").endswith("/secure"):
            denied_record = candidate
            break
    assert denied_record is not None, (
        f"the 403 access-log record must parse as the configured JSON format, got "
        f"{access_records[:3]!r}"
    )
    # $context.path is stage-qualified on real AWS: /{stage}/{resource}.
    assert denied_record.get("path") == "/test/secure", (
        f"$context.path should be the stage-qualified '/test/secure', got "
        f"{denied_record.get('path')!r}"
    )
    assert denied_record.get("requestId"), (
        f"$context.requestId must be resolved in the denied request's access-log record "
        f"-- API Gateway requires the format to name it, so an empty value means the "
        f"gateway wrote the line without ever binding a request id: {denied_record!r}"
    )

    # Control: the same route, same authorizer, an allowing token.
    ok_status, _, ok_text = _poll_http(
        url,
        accept=lambda s: s == 200,
        headers={"Authorization": "allow-me"},
        description="allowed request to the authorizer-protected route",
    )
    assert ok_status == 200, (
        f"control: an allowing token should reach the backend, got {ok_status}: {ok_text!r}"
    )
    assert json.loads(ok_text).get("marker") == marker, (
        f"control response should carry the backend marker {marker!r}, got {ok_text!r}"
    )
    _poll_until(
        lambda: _log_events_containing(
            ctx, backend_log_group, f"BACKEND-INVOKED {marker}", start_ms
        ),
        lambda msgs: bool(msgs),
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            "the control invocation's BACKEND-INVOKED log line (proves the absence "
            "asserted above was the authorizer's decision, not a broken observation)"
        ),
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result.

    Raises AssertionError on timeout. Propagation (IAM, stage deploy, log delivery) is
    always waited out this way — never with a bare time.sleep as the assertion.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _stays_absent(
    probe, predicate, *, window_s=25.0, interval_s=2.5, description="effect"
):
    """Assert predicate(probe()) stays FALSY for a whole bounded window.

    The negative-delivery shape: an effect that must NEVER appear is observed over a
    settle window, not with one racy read that could pass simply by being early.
    """
    deadline = time.monotonic() + window_s
    while True:
        last = probe()
        assert not predicate(last), (
            f"{description} appeared but must NOT have (delivery was suppressed "
            f"upstream). Observed: {last!r}"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


def _http(method, url, body=None, headers=None, timeout_s=20):
    """HTTP request via urllib (stdlib only). Returns (status, lower-cased headers, text).

    A 4xx/5xx is a RESULT, not an exception — negative checks assert on the status and
    body of the error response, so HTTPError is unwrapped rather than raised.
    """
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as e:
        return (
            e.code,
            {k.lower(): v for k, v in e.headers.items()},
            e.read().decode("utf-8", "replace"),
        )


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
    """Poll an invoke URL until accept(status) is true; return (status, headers, text).

    Stage/deployment/execute-api-DNS propagation is real and measured in seconds, so the
    first request through a freshly deployed stage is polled to a CONDITION with a bounded
    deadline. Connection-level errors (DNS/TLS still settling) are retried, not raised.
    """
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers)
        except Exception:  # noqa: BLE001 - execute-api DNS/TLS settling
            last = (None, {}, "connection error")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} {url} never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:400]!r}"
    )


def _request_until_logged(
    ctx,
    url,
    *,
    log_group,
    needle,
    start_ms,
    expect_status,
    method="GET",
    headers=None,
    timeout_s=360.0,
    interval_s=10.0,
    description="request",
):
    """Re-issue the same request until one shows up in the access log; return (matching messages,
    the last status). The first requests after access logging is enabled are not logged, and every
    re-issue must return `expect_status`."""
    deadline = time.monotonic() + timeout_s
    attempts = 0
    status = None
    while True:
        status, _, text = _poll_http(
            url,
            accept=lambda s: s == expect_status,
            method=method,
            headers=headers,
            description=description,
        )
        attempts += 1
        assert status == expect_status, (
            f"{description}: expected HTTP {expect_status} on every attempt, attempt "
            f"{attempts} returned {status}: {text!r}"
        )
        msgs = _log_events_containing(ctx, log_group, needle, start_ms)
        if msgs:
            return msgs, status
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no access-log record containing {needle!r} appeared in {log_group} "
                f"after {attempts} identical {description} attempts over {timeout_s}s "
                f"(the stage accepted accessLogSettings but delivered nothing)"
            )
        time.sleep(interval_s)


def _rest_invoke_url(ctx, api_id, stage, path):
    """The invoke URL of a DEPLOYED REST API stage, from ``ctx.rest_api_url``.

    Real AWS: ``https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>``; under an
    emulator, the ``/_aws/execute-api/<id>/<stage>/<path>`` route.
    """
    p = path.lstrip("/")
    return f"{ctx.rest_api_url(api_id, stage)}/{p}"


def _create_rest_api(ctx, kind="api", **extra):
    """Create a REGIONAL REST API (teardown registered) and return (api_id, root_resource_id)."""
    ag = ctx.client("apigateway")
    api_id = ag.create_rest_api(
        name=_xname(ctx, kind),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=_xsvc_resource_tags(),
        **extra,
    )["id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    return api_id, root_id


def _deploy_stage(ctx, api_id, stage, variables=None, **extra):
    """CreateDeployment + CreateStage; return the deployment id. accessLogSettings is not a
    CreateStage input, so it is applied with UpdateStage patchOperations."""
    ag = ctx.client("apigateway")
    access_log_settings = extra.pop("accessLogSettings", None)
    dep_id = ag.create_deployment(restApiId=api_id)["id"]
    kwargs = {"restApiId": api_id, "stageName": stage, "deploymentId": dep_id}
    if variables:
        kwargs["variables"] = variables
    kwargs.update(extra)
    ag.create_stage(**kwargs)
    ctx.on_cleanup(
        lambda: ctx.client("apigateway").delete_stage(restApiId=api_id, stageName=stage)
    )
    if access_log_settings:
        _retry_throttled(
            lambda: ag.update_stage(
                restApiId=api_id,
                stageName=stage,
                patchOperations=[
                    {
                        "op": "replace",
                        "path": "/accessLogSettings/destinationArn",
                        "value": access_log_settings["destinationArn"],
                    },
                    {
                        "op": "replace",
                        "path": "/accessLogSettings/format",
                        "value": access_log_settings["format"],
                    },
                ],
            )
        )
        # Round-trip the setting before relying on delivery: an emulator that accepts the
        # patch and drops it would otherwise fail later with the much vaguer "no access-log
        # record appeared".
        applied = ag.get_stage(restApiId=api_id, stageName=stage).get(
            "accessLogSettings", {}
        )
        assert applied.get("destinationArn") == access_log_settings["destinationArn"], (
            f"UpdateStage must persist the access-log destination; expected "
            f"{access_log_settings['destinationArn']!r}, GetStage returned {applied!r}"
        )
        assert applied.get("format") == access_log_settings["format"], (
            f"UpdateStage must persist the access-log format byte-exact; expected "
            f"{access_log_settings['format']!r}, GetStage returned "
            f"{applied.get('format')!r}"
        )
    return dep_id


def _retry_throttled(fn, attempts=10, base_delay=3.0):
    """Retry TooManyRequestsException only; every other error propagates.

    API Gateway's control plane -- UpdateAccount and UpdateStage especially -- throttles
    aggressively, and a swallowed throttle on the account-level role would silently leave
    this account's global config pointing at a role this check is about to delete.
    """
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 3)))
    raise last


_APIGW_CW_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "apigateway.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_APIGW_CW_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents",
                "logs:GetLogEvents",
                "logs:FilterLogEvents",
            ],
            "Resource": "*",
        }
    ],
}


def _ensure_account_cloudwatch_role(ctx):
    """Set the account-level cloudwatchRoleArn, which UpdateStage requires before it accepts
    accessLogSettings, and restore it on cleanup; return its ARN. An existing value is used as is."""
    ag = ctx.client("apigateway")
    existing = ag.get_account().get("cloudwatchRoleArn")
    if existing:
        return existing

    iam = ctx.client("iam")
    role_name = _xname(ctx, "apigw-cw")
    try:
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(_APIGW_CW_TRUST),
            Tags=_xsvc_tags_kv(),
        )["Role"]["Arn"]
    except ClientError as exc:
        raise AssertionError(
            "the account-level apigateway cloudwatchRoleArn is unset and the caller "
            "cannot create the role it requires, so no stage can enable access "
            f"logging: {exc.response.get('Error', {}).get('Code')}"
        ) from exc
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(_APIGW_CW_POLICY),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
    )
    # IAM propagation: API Gateway validates that it can assume the role. Bounded retry,
    # never a bare sleep -- the deadline below is the only thing that gates correctness.
    _poll_until(
        lambda: _account_role_set(ctx, role_arn),
        lambda ok: ok,
        timeout_s=120.0,
        interval_s=5.0,
        description=f"account cloudwatchRoleArn accepted as {role_arn}",
    )
    # Registered AFTER the set, so LIFO clears the account setting BEFORE the role and
    # its policy are deleted -- the only order that does not leave this account's global
    # config pointing at a deleted role.
    ctx.on_cleanup(lambda: _clear_account_cloudwatch_role(ctx))
    return role_arn


def _account_role_set(ctx, role_arn) -> bool:
    """One attempt at setting the account role; False while API Gateway still refuses it."""
    ag = ctx.client("apigateway")
    try:
        _retry_throttled(
            lambda: ag.update_account(
                patchOperations=[
                    {"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}
                ]
            )
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "BadRequestException":
            raise
        return False
    return ag.get_account().get("cloudwatchRoleArn") == role_arn


def _clear_account_cloudwatch_role(ctx) -> None:
    """Restore the account-global cloudwatchRoleArn to unset (its value before this check)."""
    ag = ctx.client("apigateway")
    _retry_throttled(
        lambda: ag.update_account(
            patchOperations=[
                {"op": "replace", "path": "/cloudwatchRoleArn", "value": ""}
            ]
        )
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust_service, inline_policy=None, managed_policies=None):
    """Create an IAM role and register its (policies-first) teardown. Returns {name,arn}.

    IAM propagation is real: the caller must still tolerate the first use of a brand-new
    role failing (see _create_function_with_retry / the apigateway credentials retries).
    """
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
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    # IAM trust/permission propagation before a service assumes it: no bare sleep here --
    # _create_function_with_retry bounds-and-retries "cannot be assumed" against its own
    # deadline, which is the only thing that needs to tolerate this lag.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
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
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_function_active(ctx, name, timeout_s=90.0):
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} Active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
):
    """Create a Lambda, RETRYING through the IAM role-propagation window, then wait Active.

    Registers the function's teardown plus its auto-created /aws/lambda/<name> log group
    (which survives function deletion and would otherwise leak).
    """
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    last_err = None
    while True:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            ctx.on_cleanup(
                lambda: _delete_log_group_persistently(ctx, f"/aws/lambda/{name}")
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                if time.monotonic() >= deadline:
                    break
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
):
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM
    statement fragments like [{"Action": ["dynamodb:PutItem"], "Resource": arn}]); logs are
    always allowed. Role + function each register their own teardown. Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    """Grant apigateway.amazonaws.com lambda:InvokeFunction, scoped to source_arn."""
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as e:
        if "ResourceConflictException" not in str(e):
            raise


def _create_log_group(ctx, kind="loggroup"):
    """Create a CloudWatch Logs group (teardown registered). Returns {name,arn}."""
    logs = ctx.client("logs")
    name = f"/sim2real/xsvc/{_xname(ctx, kind)}"
    logs.create_log_group(logGroupName=name, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: _delete_log_group_persistently(ctx, name))
    arn = f"arn:aws:logs:{ctx.region}:{_account_id(ctx)}:log-group:{name}"
    return {"name": name, "arn": arn}


def _delete_log_group_persistently(ctx, name, *, attempts=3, delay=20.0):
    """Delete a log group and delete it again if a late log flush recreates it."""
    logs = ctx.client("logs")
    for attempt in range(attempts):
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(delay)
        alive = [
            g["logGroupName"]
            for g in logs.describe_log_groups(logGroupNamePrefix=name).get(
                "logGroups", []
            )
            if g["logGroupName"] == name
        ]
        if not alive:
            return
    raise AssertionError(
        f"LEAK: log group {name} was recreated by an async writer after {attempts} "
        f"deletes spanning {attempts * delay}s"
    )


def _log_events_containing(ctx, log_group, needle, start_ms=None):
    """Every message in log_group containing `needle`. A MISSING log group is 'no events',
    not an error — for a suppressed-delivery check the group legitimately never appears."""
    logs = ctx.client("logs")
    kwargs = {"logGroupName": log_group, "limit": 100}
    if start_ms is not None:
        kwargs["startTime"] = start_ms
    out = []
    try:
        paginator = logs.get_paginator("filter_log_events")
        for page in paginator.paginate(**kwargs):
            for ev in page.get("events", []):
                if needle in ev.get("message", ""):
                    out.append(ev["message"])
            if len(out) >= 20:
                break
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
