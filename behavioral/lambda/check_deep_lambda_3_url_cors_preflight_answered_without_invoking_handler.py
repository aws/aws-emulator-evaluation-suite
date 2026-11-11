"""deep-lambda-3-url-cors-preflight-answered-without-invoking-handler."""

from __future__ import annotations

import io
import json
import sys
import time
import urllib.error
import urllib.request
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-3-url-cors-preflight-answered-without-invoking-handler"
GROUP = "function_url"
SERVICES = ["lambda"]

ORIGIN = "https://example.test"
CORS = {
    "AllowOrigins": [ORIGIN],
    "AllowMethods": ["GET"],
    "AllowHeaders": ["x-sim-hdr"],
    "MaxAge": 300,
}
MARKER = "sim2real-cors-handler-ran"

# The handler records every invocation on an SQS queue BEFORE it returns, so the queue is an
# invocation counter that is independent of whatever the URL front end puts on the HTTP response.
HANDLER = f"""\
import json
import os
import time

import boto3

SQS = boto3.client("sqs")


def handler(event, context):
    http = event["requestContext"]["http"]
    rec = {{
        "method": http["method"],
        "nonce": (event.get("queryStringParameters") or {{}}).get("n"),
        "origin": (event.get("headers") or {{}}).get("origin"),
    }}
    deadline = time.time() + 20
    while True:
        try:
            SQS.send_message(QueueUrl=os.environ["SIDE_QUEUE"], MessageBody=json.dumps(rec))
            break
        except Exception as exc:  # IAM propagation of the role's inline policy
            if time.time() > deadline:
                return {{"statusCode": 500, "body": json.dumps({{"side_channel_error": str(exc)}})}}
            time.sleep(1)
    return {{
        "statusCode": 200,
        "headers": {{"Content-Type": "application/json"}},
        "body": json.dumps(dict(rec, marker="{MARKER}")),
    }}
"""


@tags("dp:endpoint", "plane:data", "concern:data-plane", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """A function URL answers a CORS preflight with exactly the configured Access-Control-* headers
    without invoking the handler; the following GET reaches the handler once with Allow-Origin.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    queue_url, queue_arn = _make_queue(ctx, sqs)
    role_arn = _make_role(ctx, iam, queue_arn)
    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-cors-"),
        Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip(HANDLER)}, MemorySize=128, Timeout=30,
        Environment={"Variables": {"SIDE_QUEUE": queue_url}},
        Tags={"sim2real": CHECK},
    )
    url = _open_url(ctx, lam, fn, CORS)

    preflight_headers = {
        "Origin": ORIGIN,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "x-sim-hdr",
    }
    expected_preflight = {
        "access-control-allow-origin": ORIGIN,
        "access-control-allow-methods": "GET",
        "access-control-allow-headers": "x-sim-hdr",
        "access-control-max-age": "300",
    }

    # Leg 1: the preflight, before anything else has touched the function. The preflight is
    # answered even before any invoke permission is granted.
    status, hdrs, body = _http(ctx, _with_nonce(url, "preflight-1"), "OPTIONS", preflight_headers)
    assert status == 200, f"preflight must be answered 200, got {status!r} {hdrs!r} {body[:200]!r}"
    assert _cors_headers(hdrs) == expected_preflight, (
        f"preflight must carry EXACTLY the configured CORS headers {expected_preflight!r}, "
        f"got {_cors_headers(hdrs)!r}"
    )
    assert hdrs.get("vary") == "Origin", f"preflight must vary on Origin, got {hdrs.get('vary')!r}"
    assert MARKER not in body, f"preflight body came from the handler: {body!r}"
    seen = _drain(sqs, queue_url, window_s=3)
    assert seen == [], f"the preflight must not invoke the handler; side channel holds {seen!r}"

    # Leg 2: the actual cross-origin GET reaches the handler and carries Allow-Origin.
    status, hdrs, body = _get_until_served(ctx, _with_nonce(url, "get-1"), {"Origin": ORIGIN})
    assert status == 200, f"cross-origin GET must be served 200, got {status!r} {body[:300]!r}"
    served = json.loads(body)
    assert served.get("marker") == MARKER and served.get("nonce") == "get-1", (
        f"the GET response must be the handler's own body for this request, got {served!r}"
    )
    assert hdrs.get("access-control-allow-origin") == ORIGIN, (
        f"the actual response must carry Allow-Origin {ORIGIN!r}, got {_cors_headers(hdrs)!r}"
    )
    for preflight_only in ("access-control-allow-methods", "access-control-max-age"):
        assert preflight_only not in hdrs, (
            f"{preflight_only} belongs to the preflight, not the actual response: {_cors_headers(hdrs)!r}"
        )
    seen = _await_records(sqs, queue_url, lambda recs: any(r.get("nonce") == "get-1" for r in recs))
    assert seen == [{"method": "GET", "nonce": "get-1", "origin": ORIGIN}], (
        f"the GET must invoke the handler exactly once and nothing else may have; side channel "
        f"holds {seen!r}"
    )

    # Leg 3: grants are now proven effective (so a non-invocation is not a 403), and a preflight
    # still does not reach the handler.
    status, hdrs, body = _http(ctx, _with_nonce(url, "preflight-2"), "OPTIONS", preflight_headers)
    assert status == 200 and _cors_headers(hdrs) == expected_preflight, (
        f"second preflight must match the first, got {status!r} {_cors_headers(hdrs)!r}"
    )
    assert MARKER not in body, f"second preflight body came from the handler: {body!r}"
    seen = _drain(sqs, queue_url, window_s=3)
    assert seen == [], (
        f"with invoke grants proven effective, a preflight must still not invoke the handler; "
        f"side channel holds {seen!r}"
    )


_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"


def _zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


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


def _make_queue(ctx, sqs) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-cors-")
    queue_url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    return queue_url, arn["Attributes"]["QueueArn"]


def _make_role(ctx, iam, queue_arn: str) -> str:
    """This check's own execution role: basic logging plus SendMessage on its own queue only."""
    name = ctx.unique_name("sim2real-behav-cors-")
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    iam.put_role_policy(
        RoleName=name, PolicyName="side-channel",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="side-channel"))
    # IAM propagation exposes no pollable condition: CreateFunction retries the role-propagation
    # refusal and the handler retries SendMessage, so no fixed sleep is added here.
    return role["Role"]["Arn"]


def _group_exists(logs, group: str) -> bool:
    page = logs.describe_log_groups(logGroupNamePrefix=group)
    return any(g["logGroupName"] == group for g in page.get("logGroups", []))


def _reap_log_group(logs, group: str) -> None:
    """delete_function does not remove /aws/lambda/<fn>, and a buffered flush can RECREATE it after
    the delete — so reap in a loop until it has stayed absent for three consecutive reads."""
    quiet = 0
    for _ in range(14):
        if _group_exists(logs, group):
            quiet = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            quiet += 1
            if quiet >= 3:
                return
        time.sleep(4)
    if _group_exists(logs, group):
        raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_function(ctx, lam, logs, **kwargs) -> str:
    """CreateFunction retrying ONLY the documented role-propagation refusal; waits for Active."""
    name = kwargs["FunctionName"]
    group = f"/aws/lambda/{name}"
    # Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, group))
    deadline = time.monotonic() + 90.0
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            code = exc.response["Error"]["Code"]
            if code != "InvalidParameterValueException" or _ROLE_PROPAGATION not in msg:
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"CreateFunction({name}) kept failing on role propagation: {msg}")
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_ready(lam, name)
    return name


def _wait_ready(lam, name: str) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} failed: {cfg.get('StateReason')} {cfg.get('LastUpdateStatusReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active"
        and cfg.get("LastUpdateStatus") in (None, "Successful"),
        timeout_s=180.0, interval_s=2.0, description=f"{name} Active + LastUpdateStatus=Successful",
    )


def _open_url(ctx, lam, fn: str, cors: dict) -> str:
    """AuthType=AWS_IAM URL with the given Cors, plus BOTH grants this account's signed caller needs."""
    url = lam.create_function_url_config(FunctionName=fn, AuthType="AWS_IAM", Cors=cors)["FunctionUrl"]
    assert not (p := ctx.published_url_mismatch(url)), p
    lam.add_permission(
        FunctionName=fn, StatementId="sim2real-url", Action="lambda:InvokeFunctionUrl",
        Principal=ctx.account, FunctionUrlAuthType="AWS_IAM",
    )
    lam.add_permission(
        FunctionName=fn, StatementId="sim2real-invoke", Action="lambda:InvokeFunction",
        Principal=ctx.account, InvokedViaFunctionUrl=True,
    )
    return url


def _with_nonce(url: str, nonce: str) -> str:
    return f"{url}?n={nonce}"


def _http(ctx, url: str, method: str, headers: dict, timeout_s: float = 40.0):
    """SigV4-signed with ctx's credentials: (status, {lower-cased header: value}, body text) —
    never raises on 4xx/5xx."""
    signer_creds = ctx.client("lambda")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign the function URL request")
    aws_req = AWSRequest(method=method, url=url, data=None, headers=dict(headers))
    SigV4Auth(signer_creds.get_frozen_credentials(), "lambda", ctx.region).add_auth(aws_req)
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**dict(aws_req.headers), **_route})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in exc.headers.items()},
                exc.read().decode("utf-8", errors="replace"))


def _get_until_served(ctx, url: str, headers: dict, timeout_s: float = 120.0):
    """GET, retrying ONLY the URL authorizer's 403 while the resource-policy grants propagate.
    A 403 from the authorizer never reaches the handler, so retries cannot add invocations."""
    def _probe():
        return _http(ctx, url, "GET", headers)

    def _not_auth_refusal(resp):
        status, hdrs, _ = resp
        return not (status == 403 and hdrs.get("x-amzn-errortype") == "AccessDeniedException")

    return _poll_until(_probe, _not_auth_refusal, timeout_s=timeout_s, interval_s=3.0,
                       description=f"GET {url} past the URL authorizer")


def _cors_headers(hdrs: dict) -> dict:
    return {k: v for k, v in hdrs.items() if k.startswith("access-control-")}


def _receive(sqs, queue_url: str, wait_s: int) -> list[dict]:
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s, VisibilityTimeout=60,
    )
    out = []
    for msg in resp.get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _drain(sqs, queue_url: str, window_s: int) -> list[dict]:
    """Every side-channel record that arrives within a bounded long-poll window (consumed)."""
    out: list[dict] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        out += _receive(sqs, queue_url, wait_s=max(1, min(5, int(deadline - time.monotonic()))))
    return out


def _await_records(sqs, queue_url: str, predicate, timeout_s: float = 60.0) -> list[dict]:
    """Consume records until predicate(all so far) holds, then one quiet pass to catch extras.
    The handler sends before it returns, so its record is already queued when the HTTP call ends."""
    got: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while not predicate(got):
        if time.monotonic() > deadline:
            raise AssertionError(f"side-channel record not observed within {timeout_s}s; saw {got!r}")
        got += _receive(sqs, queue_url, wait_s=5)
    return got + _drain(sqs, queue_url, window_s=3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
