"""function-url-missing-permission-not-invoked."""

from __future__ import annotations

import io
import json
import secrets
import textwrap
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "function-url-missing-permission-not-invoked"
GROUP = 'function_url'
SERVICES = ['lambda']

MARKER = "sim2real-url-marker-7f3a"
STATEMENT_ID = "sim2real-behav-url-public"

# The handler serves only callers presenting the per-run secret header; any other request is 403.
HANDLER = f"""\
import hmac
import json
import os


def handler(event, context):
    sent = (event.get("headers") or {{}}).get("x-sim2real-auth", "")
    if not hmac.compare_digest(sent, os.environ["URL_SECRET"]):
        return {{"statusCode": 403, "body": "forbidden"}}
    return {{
        "statusCode": 200,
        "headers": {{"Content-Type": "application/json"}},
        "body": json.dumps({{
            "marker": "{MARKER}",
            "method": event.get("requestContext", {{}}).get("http", {{}}).get("method"),
        }}),
    }}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _role_arn(ctx):
    """An execution role this check creates once per run and deletes in its teardown."""
    import json as _json

    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_url_config(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll(probe, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=120):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        return cfg if cfg["State"] == "Active" else None

    cfg = _poll(_probe, timeout_s, interval_s=1.0)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _error(call):
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call succeeded; expected a ClientError")


def _http_get(ctx, url, timeout_s=20):
    """Return (status, body_text) for a plain GET, without raising on 4xx/5xx."""
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method="GET", headers=_route)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        return None, f"urlerror:{exc.reason}"


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An AuthType=NONE function URL whose policy grants the anonymous principal only
    lambda:InvokeFunctionUrl refuses unsigned GETs with the authorizer's 403 Forbidden, and removing that
    grant leaves the identical refusal and no policy (GetPolicy ResourceNotFoundException).

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-fn-")
    secret = secrets.token_urlsafe(32)
    _create_function(lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(HANDLER)},
        MemorySize=128, Timeout=30, Environment={"Variables": {"URL_SECRET": secret}},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_active(lam, fn)

    # Positive control: the function and credentials are healthy, independent of the URL surface.
    event = json.dumps({"headers": {"x-sim2real-auth": secret}}).encode()
    invoke_payload = json.loads(lam.invoke(FunctionName=fn, Payload=event)["Payload"].read())
    invoke_body = json.loads(invoke_payload["body"])
    assert invoke_body["marker"] == MARKER, (
        f"the function must be invocable via the Invoke API before the URL negative means "
        f"anything, got {invoke_payload}"
    )

    url = lam.create_function_url_config(FunctionName=fn, AuthType="NONE")["FunctionUrl"]
    assert not (p := ctx.published_url_mismatch(url)), p

    lam.add_permission(
        FunctionName=fn, StatementId=STATEMENT_ID, Action="lambda:InvokeFunctionUrl",
        Principal="*", FunctionUrlAuthType="NONE",
    )

    # The grant is a real resource-policy statement carrying the FunctionUrlAuthType condition —
    # AddPermission recorded correctly even though it will not change what the anonymous GET sees.
    policy = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
    stmt = next((s for s in policy["Statement"] if s.get("Sid") == STATEMENT_ID), None)
    assert stmt is not None, f"AddPermission statement missing from the policy: {policy}"
    assert stmt["Action"] == "lambda:InvokeFunctionUrl", stmt
    assert stmt["Condition"]["StringEquals"]["lambda:FunctionUrlAuthType"] == "NONE", (
        f"the URL grant must record the FunctionUrlAuthType condition, got {stmt}"
    )

    def _forbidden(status, body):
        if status != 403:
            return None
        try:
            msg = json.loads(body).get("Message", "")
        except (json.JSONDecodeError, TypeError):
            return None
        return body if "Forbidden" in msg and "Function URL authorization" in msg else None

    def _reaches_forbidden():
        status, body = _http_get(ctx, url)
        return _forbidden(status, body)

    granted = _poll(_reaches_forbidden, 30, interval_s=3.0)
    assert granted is not None, (
        f"expected 403 Forbidden for an anonymous GET with only lambda:InvokeFunctionUrl granted: "
        f"anonymous access to a function URL also needs lambda:InvokeFunction granted, last "
        f"attempt: {_http_get(ctx, url)}"
    )
    assert MARKER not in granted, (
        f"a denied URL request must not deliver the handler's response, body was {granted!r}"
    )

    # Remove the grant: the refusal persists, byte-identically — proving the grant, not the URL,
    # is what is inert here.
    lam.remove_permission(FunctionName=fn, StatementId=STATEMENT_ID)
    ungranted = _poll(_reaches_forbidden, 30, interval_s=3.0)
    assert ungranted is not None, (
        f"expected the same anonymous-URL refusal once the grant is removed, last attempt: "
        f"{_http_get(ctx, url)}"
    )
    assert ungranted == granted, (
        f"removing the grant must not change the refusal body if the grant was never the reason "
        f"for it, got granted={granted!r} ungranted={ungranted!r}"
    )
    assert MARKER not in ungranted, (
        f"a denied URL request must not deliver the handler's response, body was {ungranted!r}"
    )
    no_policy = _error(lambda: lam.get_policy(FunctionName=fn))
    assert no_policy == ("ResourceNotFoundException", "The resource you requested does not exist."), (
        f"removing the only statement must leave no policy, GetPolicy returned {no_policy}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
