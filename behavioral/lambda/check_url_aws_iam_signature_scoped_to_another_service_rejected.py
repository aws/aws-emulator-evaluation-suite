"""url-aws-iam-signature-scoped-to-another-service-rejected."""

from __future__ import annotations

import base64
import http.client
import io
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "url-aws-iam-signature-scoped-to-another-service-rejected"
GROUP = "function_url"
SERVICES = ["lambda"]

RUNTIME = "python3.12"
FILENAME = "index.py"
TIMEOUT_S = 10

_FORBIDDEN = {
    "Message": "Forbidden. For troubleshooting Function URL authorization issues, see: "
               "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html"
}

HANDLER = """
import json


def handler(event, context):
    return {"statusCode": 200, "headers": {"content-type": "application/json"},
            "body": json.dumps({"marker": "sim2real-url-handler-ran", "event": event})}
"""


_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 4.0,
                    budget_s: float = 40.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; raise if not."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry on an observable condition. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _make_role(ctx, iam) -> str:
    """This check's own execution role (basic logging only), deleted in its teardown."""
    name = ctx.unique_name("sim2real-behav-url-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC), "NoSuchEntity"))
    # IAM propagation exposes no pollable condition: CreateFunction retries the documented
    # role-propagation refusal instead of sleeping here.
    return role["Role"]["Arn"]


def _create_function(ctx, lam, logs, **kwargs) -> str:
    """CreateFunction retrying ONLY the role-propagation refusal; waits for Active."""
    name = kwargs["FunctionName"]
    # Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 90.0
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or (
                _ROLE_PROPAGATION not in msg
            ):
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"CreateFunction kept failing on role propagation: {msg}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))

    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"function failed: {cfg.get('StateReason')} {cfg.get('LastUpdateStatusReason')}"
            )
        return cfg

    _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active"
        and cfg.get("LastUpdateStatus") in (None, "Successful"),
        timeout_s=180.0, interval_s=1.0, description="the function reaching State=Active",
    )
    return name


def _create_url(ctx, lam, fn: str, auth: str = "NONE", **kwargs) -> dict:
    """CreateFunctionUrlConfig, torn down with the function; the URL is graded as published."""
    cfg = lam.create_function_url_config(FunctionName=fn, AuthType=auth, **kwargs)
    qualifier = {"Qualifier": kwargs["Qualifier"]} if "Qualifier" in kwargs else {}
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function_url_config(FunctionName=fn, **qualifier),
        "ResourceNotFoundException"))
    assert not (p := ctx.published_url_mismatch(cfg["FunctionUrl"])), p
    return cfg


def _grant_public(lam, fn: str, *, url_grant: bool = True, invoke_grant: bool = True,
                  **qualifier) -> None:
    """The two resource-policy grants an anonymous caller of an AuthType=NONE URL needs."""
    if url_grant:
        lam.add_permission(
            FunctionName=fn, StatementId="sim2real-url", Action="lambda:InvokeFunctionUrl",
            Principal="*", FunctionUrlAuthType="NONE", **qualifier,
        )
    if invoke_grant:
        lam.add_permission(
            FunctionName=fn, StatementId="sim2real-invoke", Action="lambda:InvokeFunction",
            Principal="*", InvokedViaFunctionUrl=True, **qualifier,
        )


def _ssl_context(ctx) -> ssl.SSLContext:
    verify = ctx.http_verify
    if verify is False:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if isinstance(verify, str) and verify:
        return ssl.create_default_context(cafile=verify)
    return ssl.create_default_context()


def _sign(ctx, method: str, url: str, headers: dict, data, service: str = "lambda") -> dict:
    """SigV4 headers for a request to ``url``, signed with THIS check's credentials."""
    frozen = ctx.client("lambda")._request_signer._credentials.get_frozen_credentials()
    req = AWSRequest(method=method, url=url, data=data, headers=dict(headers))
    SigV4Auth(frozen, service, ctx.region).add_auth(req)
    return dict(req.headers.items())


def _http(ctx, url: str, method: str = "GET", headers: dict | None = None, data=None,
          *, sign: bool = False, timeout_s: float = 40.0) -> dict:
    """One raw HTTPS request to the published URL. Never raises on 4xx/5xx."""
    headers = dict(headers or {})
    if sign:
        headers = _sign(ctx, method, url, headers, data)
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(target, data=data, method=method, headers={**headers, **route})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(ctx))
    except urllib.error.HTTPError as exc:
        resp = exc
    with resp:
        try:
            body = resp.read()
        except http.client.IncompleteRead as exc:  # a stream the server cut short
            body = exc.partial
        return {
            "status": resp.status if hasattr(resp, "status") else resp.code,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "set_cookie": resp.headers.get_all("Set-Cookie") or [],
            "body": body,
        }


def _authorizer_refusal(obs: dict) -> bool:
    return obs["status"] == 403 and obs["headers"].get("x-amzn-errortype") == "AccessDeniedException"


def _until_served(ctx, url: str, **kwargs) -> dict:
    """Request ``url`` until the URL authorizer stops refusing it (resource-policy propagation).

    A 403 from the authorizer never reaches the handler, so a retry cannot add an invocation.
    """
    return _poll_until(
        lambda: _http(ctx, url, **kwargs), lambda obs: not _authorizer_refusal(obs),
        timeout_s=120.0, interval_s=2.0, description="the function URL serving the request",
    )


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An AWS_IAM function URL accepts only SigV4 scoped to service `lambda`: the same GET signed for
    `execute-api` is refused 403 InvalidSignatureException with a message naming the required
    service, while the `lambda`-scoped request runs the handler.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/urls-invocation.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-url-"),
        Runtime=RUNTIME, Role=_make_role(ctx, ctx.client("iam")), Handler="index.handler",
        Code={"ZipFile": _zip(FILENAME, HANDLER)}, MemorySize=256, Timeout=TIMEOUT_S,
        Tags={"sim2real": CHECK},
    )
    url = _create_url(ctx, lam, fn, auth="AWS_IAM")["FunctionUrl"]

    good = _poll_until(
        lambda: _http(ctx, url, sign=True), lambda obs: obs["status"] == 200,
        timeout_s=120.0, interval_s=3.0, description="the lambda-scoped signed GET being served",
    )
    assert json.loads(good["body"])["marker"] == "sim2real-url-handler-ran", good["body"][:300]

    wrong = _http(ctx, url, headers=_sign(ctx, "GET", url, {}, None, service="execute-api"))
    assert wrong["status"] == 403, f"a wrongly scoped signature must be refused, got {wrong!r}"
    assert wrong["headers"].get("x-amzn-errortype") == "InvalidSignatureException", wrong["headers"]
    assert json.loads(wrong["body"]) == {
        "message": "Credential should be scoped to correct service: 'lambda'. "
    }, f"unexpected refusal body {wrong['body']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
