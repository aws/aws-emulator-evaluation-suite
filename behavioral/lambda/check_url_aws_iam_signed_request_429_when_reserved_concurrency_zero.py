"""url-aws-iam-signed-request-429-when-reserved-concurrency-zero."""

from __future__ import annotations

import io
import json
import ssl
import textwrap
import time
import urllib.error
import urllib.request
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "url-aws-iam-signed-request-429-when-reserved-concurrency-zero"
GROUP = "function_url"
SERVICES = ["lambda"]

RUNTIME = "python3.13"
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"

HANDLER = """
def handler(event, context):
    return {"statusCode": 200, "headers": {"content-type": "application/json"},
            "body": "{\\"ran\\": true}"}
"""


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
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


def _zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(source))
    return buf.getvalue()


def _make_role(ctx, iam) -> str:
    """This check's own execution role (basic logging only), deleted in its teardown."""
    name = ctx.unique_name("sim2real-behav-url429-")
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
    return role["Role"]["Arn"]


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _create_function(ctx, lam, logs, **kwargs) -> str:
    """CreateFunction retrying ONLY the role-propagation refusal; waits for Active."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
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
                raise TimeoutError(f"CreateFunction kept failing on role propagation: {msg}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))

    timeout_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"function failed: {cfg.get('StateReason')} {cfg.get('LastUpdateStatusReason')}"
            )
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            break
        if time.monotonic() > deadline:
            raise TimeoutError(f"function {name} did not reach Active within {timeout_s:.0f}s: {cfg!r}")
        time.sleep(1.0)
    return name


def _create_url(ctx, lam, fn: str, auth: str = "AWS_IAM") -> str:
    cfg = lam.create_function_url_config(FunctionName=fn, AuthType=auth)
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function_url_config(FunctionName=fn), "ResourceNotFoundException"))
    assert not (p := ctx.published_url_mismatch(cfg["FunctionUrl"])), p
    return cfg["FunctionUrl"]


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


def _sign(ctx, method: str, url: str, headers: dict, data) -> dict:
    """SigV4 headers for a request to ``url``, signed with THIS check's credentials."""
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    creds = Credentials(akid, secret, env.get("AWS_SESSION_TOKEN"))
    req = AWSRequest(method=method, url=url, data=data, headers=dict(headers))
    SigV4Auth(creds, "lambda", ctx.region).add_auth(req)
    return dict(req.headers.items())


def _http_signed_get(ctx, url: str, *, timeout_s: float = 40.0) -> dict:
    """One raw, SigV4-signed HTTPS GET against the published URL. Never raises on 4xx/5xx."""
    headers = _sign(ctx, "GET", url, {}, None)
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(target, method="GET", headers={**headers, **route})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(ctx))
    except urllib.error.HTTPError as exc:
        resp = exc
    with resp:
        body = resp.read()
        return {
            "status": resp.status if hasattr(resp, "status") else resp.code,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "body": body,
        }


def _poll_until(ctx, probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not observed within {timeout_s:.0f}s; last saw {last!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A SigV4-signed GET against an AWS_IAM function URL succeeds while concurrency is
    unreserved, and is refused with the exact TooManyRequestsException body once the function's
    reserved concurrency is set to 0.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/urls-invocation.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-url429-"),
        Runtime=RUNTIME, Role=_make_role(ctx, ctx.client("iam")), Handler="index.handler",
        Code={"ZipFile": _zip("index.py", HANDLER)}, MemorySize=128, Timeout=10,
        Tags={"sim2real": CHECK},
    )
    url = _create_url(ctx, lam, fn)

    served = _poll_until(
        ctx, lambda: _http_signed_get(ctx, url), lambda obs: obs["status"] == 200,
        timeout_s=120.0, interval_s=3.0, description="the signed GET being served",
    )
    assert json.loads(served["body"]) == {"ran": True}, (
        f"the positive control must reach the handler, got {served!r}"
    )

    lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=0)
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function_concurrency(FunctionName=fn), "ResourceNotFoundException"))

    throttled = _poll_until(
        ctx, lambda: _http_signed_get(ctx, url), lambda obs: obs["status"] == 429,
        timeout_s=60.0, interval_s=2.0,
        description="the signed GET being throttled by ReservedConcurrentExecutions=0",
    )
    assert throttled["headers"].get("x-amzn-errortype") == "TooManyRequestsException", (
        f"expected x-amzn-ErrorType TooManyRequestsException, got {throttled['headers']!r}"
    )
    assert json.loads(throttled["body"]) == {
        "Reason": "ReservedFunctionConcurrentInvocationLimitExceeded",
        "Type": "User",
        "message": "Rate Exceeded.",
    }, f"expected the exact throttle body AWS returns, got {throttled['body']!r}"

    lam.delete_function_concurrency(FunctionName=fn)
    restored = _poll_until(
        ctx, lambda: _http_signed_get(ctx, url), lambda obs: obs["status"] == 200,
        timeout_s=60.0, interval_s=2.0,
        description="the signed GET being served again after the reservation is removed",
    )
    assert json.loads(restored["body"]) == {"ran": True}, (
        f"identical request must succeed again after the reservation is removed, got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
