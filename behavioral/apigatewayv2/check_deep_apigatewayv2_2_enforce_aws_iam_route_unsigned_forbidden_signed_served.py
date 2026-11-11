"""deep-apigatewayv2-2-enforce-aws-iam-route-unsigned-forbidden-signed-served."""

from __future__ import annotations

import json
import textwrap
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from io import BytesIO

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigatewayv2-2-enforce-aws-iam-route-unsigned-forbidden-signed-served"

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

#: After every positive nonce is visible in the backend's log, how long a forbidden request's
#: nonce is still watched for. A forbidden request that reached the backend would have logged at
#: the same moment as the positives sent after it, so this bounds a late flush, not a guess.
_ABSENCE_WINDOW_S = 20.0


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS_IAM route refuses unsigned and bad-signature requests with 403 and serves SigV4 ones.

    Refused nonces never reach the backend log; a NONE twin route serves unsigned requests. HTTP
    APIs answer {"message":"Forbidden"} without the SigV4 mismatch text REST APIs echo.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control-iam.html
    """
    marker = ctx.unique_name("sim2real-behav-iam-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})
    log_group = f"/aws/lambda/{fn['name']}"

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_name(ctx, "httpapi-iam"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    iam_route = agw.create_route(
        ApiId=api_id,
        RouteKey="GET /iam",
        Target=f"integrations/{integration_id}",
        AuthorizationType="AWS_IAM",
    )["RouteId"]
    open_route = agw.create_route(
        ApiId=api_id,
        RouteKey="GET /open",
        Target=f"integrations/{integration_id}",
        AuthorizationType="NONE",
    )["RouteId"]
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    )

    auth = {
        rid: agw.get_route(ApiId=api_id, RouteId=rid)["AuthorizationType"]
        for rid in (iam_route, open_route)
    }
    assert auth == {iam_route: "AWS_IAM", open_route: "NONE"}, (
        f"precondition: the routes must differ ONLY in AuthorizationType; GetRoute says {auth!r}"
    )

    iam_url = _invoke_url(ctx, api["ApiEndpoint"], "$default", "/iam")
    open_url = _invoke_url(ctx, api["ApiEndpoint"], "$default", "/open")

    # Beat 1 - positive control: the NONE twin serves an unsigned request from the backend.
    _wait_routes_deployed([open_url, iam_url])
    open_nonce = f"open-{uuid.uuid4().hex}"
    status, _, text = _http("GET", open_url, headers={_NONCE_HEADER: open_nonce})
    assert (status, text) == (200, marker), (
        f"GET /open (AuthorizationType=NONE) must serve an unsigned request with marker "
        f"{marker!r}; got {status}: {text[:200]!r}"
    )

    # Beat 2 - the negatives: unsigned, then a signature that does not verify.
    unsigned_nonce = f"unsigned-{uuid.uuid4().hex}"
    status, _, text = _http("GET", iam_url, headers={_NONCE_HEADER: unsigned_nonce})
    assert status == 403, (
        f"an UNSIGNED request to an AWS_IAM route must be refused with 403, got {status}: "
        f"{text[:200]!r}"
    )
    assert _json_or_none(text) == {"message": "Forbidden"}, (
        f'the refusal must be the gateway\'s {{"message":"Forbidden"}} envelope, got {text[:200]!r}'
    )
    assert marker not in text, f"a refused request leaked the backend marker: {text[:200]!r}"

    bad_nonce = f"badsig-{uuid.uuid4().hex}"
    bad_headers = _sigv4_headers(ctx, iam_url, {_NONCE_HEADER: bad_nonce})
    sig_at = bad_headers["Authorization"].rindex("Signature=") + len("Signature=")
    real_sig = bad_headers["Authorization"][sig_at:]
    forged = ("0" if real_sig[0] != "0" else "1") + real_sig[1:]
    bad_headers["Authorization"] = bad_headers["Authorization"][:sig_at] + forged
    status, _, text = _http("GET", iam_url, headers=bad_headers)
    assert status == 403, (
        f"a request whose SigV4 signature does not verify must be refused with 403, got "
        f"{status}: {text[:200]!r}"
    )
    assert _json_or_none(text) == {"message": "Forbidden"}, (
        f'the bad-signature refusal must be {{"message":"Forbidden"}}, got {text[:200]!r}'
    )

    # Beat 3 - the signed request on the SAME route is served. A fresh route's IAM authorization
    # reaches the edge node by node, so a validly signed request can still meet a 403 Forbidden
    # for a short window; only that answer is retried, each try with its own signature and nonce.
    deadline = time.monotonic() + 90.0
    while True:
        signed_nonce = f"signed-{uuid.uuid4().hex}"
        status, _, text = _http(
            "GET", iam_url, headers=_sigv4_headers(ctx, iam_url, {_NONCE_HEADER: signed_nonce})
        )
        if status != 403 or time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    assert (status, text) == (200, marker), (
        f"a request SigV4-signed for execute-api by the API owner must be served by the AWS_IAM "
        f"route with marker {marker!r}; got {status}: {text[:200]!r}"
    )

    # Beat 4 - the effect is absent at the destination: both positives reach the backend's log,
    # neither refused request ever does.
    _poll_until(
        lambda: _log_messages(ctx, log_group, "NONCE="),
        lambda msgs: all(any(f"NONCE={n}" in m for m in msgs) for n in (open_nonce, signed_nonce)),
        timeout_s=120.0,
        interval_s=4.0,
        description="both served requests' nonces in the backend log",
    )
    deadline = time.monotonic() + _ABSENCE_WINDOW_S
    while True:
        msgs = _log_messages(ctx, log_group, "NONCE=")
        leaked = [m.strip() for m in msgs if unsigned_nonce in m or bad_nonce in m]
        assert not leaked, (
            f"a request the gateway refused with 403 still reached the backend: {leaked!r}"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)


def _sigv4_headers(ctx, url, extra):
    """Headers of a GET to url signed for execute-api with the caller's own credentials."""
    creds = ctx.client("apigatewayv2")._request_signer._credentials
    req = AWSRequest(method="GET", url=url, headers=dict(extra))
    SigV4Auth(creds, "execute-api", ctx.region).add_auth(req)
    return dict(req.headers.items())


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

    A deployment reaches the edge node by node, so one live route does not prove its siblings are;
    any non-404 is accepted so the next assertion is not pre-judged. RAISES on timeout."""
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
    """Delete the Lambda log group, re-deleting until it stays absent for `quiet_s`.

    A buffered flush from a finished invocation can recreate the group after delete_function.
    """
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
    """Create a Lambda (role: logs plus `permissions`) through IAM propagation; wait for Active.

    The log-group reap is registered before the function so LIFO reaps it after the delete.
    """
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
