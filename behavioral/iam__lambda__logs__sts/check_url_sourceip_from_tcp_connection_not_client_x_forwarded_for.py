"""url-sourceip-from-tcp-connection-not-client-x-forwarded-for."""

from __future__ import annotations

import io
import ipaddress
import json
import re
import ssl
import time
import urllib.error
import urllib.request
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "url-sourceip-from-tcp-connection-not-client-x-forwarded-for"
GROUP = "function_url"
SERVICES = ["iam", "lambda", "logs", "sts"]

RUNTIME = "python3.12"
FILENAME = "index.py"
TIMEOUT_S = 10

HANDLER = """
import json


def handler(event, context):
    return {"statusCode": 200, "headers": {"content-type": "application/json"},
            "body": json.dumps(event)}
"""

_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"
_SPOOFED_IP = "203.0.113.9"
_TRACE_ID_RE = re.compile(r"^Root=1-[0-9a-f]{8}-[0-9a-f]{24}(;Parent=[0-9a-f]{16})?(;Sampled=[01])?$")


def _teardown(undo, *not_found: str):
    """Runs ``undo()``; returns on ``not_found`` codes, raises every other failure."""

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


def _create_url(ctx, lam, fn: str) -> str:
    """CreateFunctionUrlConfig (AWS_IAM), torn down with the function; graded as published."""
    cfg = lam.create_function_url_config(FunctionName=fn, AuthType="AWS_IAM")
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function_url_config(FunctionName=fn), "ResourceNotFoundException"))
    assert not (p := ctx.published_url_mismatch(cfg["FunctionUrl"])), p
    return cfg["FunctionUrl"]


def _caller_principal(ctx) -> str:
    """The IAM principal this check runs as: the role behind an assumed-role session, else its ARN."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        role = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        return ctx.client("iam").get_role(RoleName=role)["Role"]["Arn"]
    return arn


def _grant_caller(ctx, lam, fn: str) -> None:
    """The two URL grants, scoped to this check's own principal and never to ``*``."""
    principal = _caller_principal(ctx)
    lam.add_permission(
        FunctionName=fn, StatementId="sim2real-url", Action="lambda:InvokeFunctionUrl",
        Principal=principal, FunctionUrlAuthType="AWS_IAM",
    )
    lam.add_permission(
        FunctionName=fn, StatementId="sim2real-invoke", Action="lambda:InvokeFunction",
        Principal=principal, InvokedViaFunctionUrl=True,
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


def _sign(ctx, method: str, url: str) -> dict:
    """SigV4 headers for a bare request to ``url``, signed with THIS check's credentials."""
    frozen = ctx.client("lambda")._request_signer._credentials.get_frozen_credentials()
    req = AWSRequest(method=method, url=url)
    SigV4Auth(frozen, "lambda", ctx.region).add_auth(req)
    return dict(req.headers.items())


def _http(ctx, url: str, *, extra_headers: dict | None = None, timeout_s: float = 40.0) -> dict:
    """One signed, raw HTTPS GET to the published URL, plus unsigned ``extra_headers`` on top.

    Never raises on 4xx/5xx.
    """
    headers = _sign(ctx, "GET", url)
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(
        target, method="GET", headers={**headers, **route, **(extra_headers or {})}
    )
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


def _authorizer_refusal(obs: dict) -> bool:
    return obs["status"] == 403 and obs["headers"].get("x-amzn-errortype") == "AccessDeniedException"


def _until_served(ctx, url: str, **kwargs) -> dict:
    """Request ``url`` until the URL authorizer stops refusing it (resource-policy propagation)."""
    return _poll_until(
        lambda: _http(ctx, url, **kwargs), lambda obs: not _authorizer_refusal(obs),
        timeout_s=120.0, interval_s=2.0, description="the function URL serving the request",
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A function URL's requestContext.http.sourceIp is always the client's real TCP peer, never
    a client-supplied X-Forwarded-For value, which it passes through verbatim instead (or
    synthesizes from sourceIp when absent), beside x-forwarded-proto/-port and x-amzn-trace-id.

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
    url = _create_url(ctx, lam, fn)
    _grant_caller(ctx, lam, fn)

    plain = _until_served(ctx, url)
    assert plain["status"] == 200, f"the plain GET must be served 200, got {plain!r}"
    ev1 = json.loads(plain["body"])

    spoofed = _http(ctx, url, extra_headers={"X-Forwarded-For": _SPOOFED_IP})
    assert spoofed["status"] == 200, f"the spoofed GET must be served 200, got {spoofed!r}"
    ev2 = json.loads(spoofed["body"])

    ip1 = ev1["requestContext"]["http"]["sourceIp"]
    ip2 = ev2["requestContext"]["http"]["sourceIp"]
    assert ip1 == ip2, f"sourceIp must be stable across calls from one client: {ip1!r} vs {ip2!r}"
    assert ip1 != _SPOOFED_IP, f"sourceIp must not become the client-supplied value, got {ip1!r}"
    ipaddress.ip_address(ip1)  # documented to be an IP address; raises ValueError otherwise

    assert ev1["headers"]["x-forwarded-for"] == ip1, (
        "omitting X-Forwarded-For gets one synthesized as the real sourceIp alone, got "
        f"{ev1['headers'].get('x-forwarded-for')!r} for sourceIp {ip1!r}"
    )
    assert ev2["headers"]["x-forwarded-for"] == _SPOOFED_IP, (
        "a client-supplied X-Forwarded-For is passed through verbatim, never replaced by the "
        f"real sourceIp, got {ev2['headers'].get('x-forwarded-for')!r}"
    )

    for ev, label in ((ev1, "plain"), (ev2, "spoofed")):
        headers = ev["headers"]
        assert headers["x-forwarded-proto"] == "https", (
            f"{label} call: x-forwarded-proto must be 'https', got {headers.get('x-forwarded-proto')!r}"
        )
        assert headers["x-forwarded-port"] == "443", (
            f"{label} call: x-forwarded-port must be '443', got {headers.get('x-forwarded-port')!r}"
        )
        trace = headers.get("x-amzn-trace-id")
        assert trace and _TRACE_ID_RE.match(trace), (
            f"{label} call: x-amzn-trace-id must match the documented Root=1-... form, got {trace!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
