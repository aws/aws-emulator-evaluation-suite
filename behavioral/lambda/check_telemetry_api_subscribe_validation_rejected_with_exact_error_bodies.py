"""telemetry-api-subscribe-validation-rejected-with-exact-error-bodies."""

from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-api-subscribe-validation-rejected-with-exact-error-bodies"
GROUP = "extensions_runtime"
SERVICES = ["lambda"]

RUNTIME = "python3.13"
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"

# Registers an internal extension during the Init phase (subscribe is only accepted then), probes
# the Telemetry API Subscribe endpoint with four invalid bodies plus one valid one, then starts the
# extension's event loop so the runtime's own first invocation can proceed, and reports every
# observed (status, body) pair back through the function's own response.
# side-channel: embeds 'sandbox.localdomain', the only hostname the Telemetry API accepts as a
# Subscribe destination (an AWS-mandated sentinel resolved inside the execution environment, not a
# stranger's host); no event ever flows there within this check's short invocation.
HANDLER = """
import json
import os
import threading
import urllib.error
import urllib.request

RUNTIME_API = os.environ["AWS_LAMBDA_RUNTIME_API"]


def _req(method, path, body=None, headers=None, timeout=5):
    url = "http://" + RUNTIME_API + path
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return {"status": resp.status, "body": resp.read().decode(),
                "headers": dict(resp.headers.items())}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": exc.read().decode(),
                "headers": dict(exc.headers.items())}


_REG = _req("POST", "/2020-01-01/extension/register", body={"events": ["INVOKE"]},
            headers={"Lambda-Extension-Name": "sim2real-telemetry-probe"})
_EXT_ID = _REG["headers"].get("Lambda-Extension-Identifier")


def _subscribe(body):
    return _req("PUT", "/2022-07-01/telemetry", body=body,
                headers={"Lambda-Extension-Identifier": _EXT_ID} if _EXT_ID else {})


# side-channel: the Telemetry API accepts only this literal hostname as a Subscribe destination
# (an AWS-mandated sentinel resolved inside the execution environment, never a stranger's host),
# and this check never lets an event actually flow there within its short invocation.
_DEST = {"protocol": "HTTP", "URI": "http://sandbox.localdomain:8080"}
_RESULTS = {
    "invalid_schema_version": _subscribe(
        {"schemaVersion": "9999-99-99", "types": ["platform"], "destination": _DEST}),
    "destination_uri_without_port": _subscribe(
        {"schemaVersion": "2022-07-01", "types": ["platform"],
         "destination": {"protocol": "HTTP", "URI": "http://sandbox.localdomain"}}),
    "empty_types": _subscribe(
        {"schemaVersion": "2022-07-01", "types": [], "destination": _DEST}),
    "maxitems_out_of_range": _subscribe(
        {"schemaVersion": "2022-07-01", "types": ["platform"], "destination": _DEST,
         "buffering": {"maxItems": 999999}}),
    "valid": _subscribe(
        {"schemaVersion": "2022-07-01", "types": ["platform"], "destination": _DEST}),
}


def _drain_events():
    while True:
        _req("GET", "/2020-01-01/extension/event/next",
             headers={"Lambda-Extension-Identifier": _EXT_ID} if _EXT_ID else {}, timeout=70)


if _EXT_ID:
    threading.Thread(target=_drain_events, daemon=True).start()


def handler(event, context):
    return _RESULTS
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
        zf.writestr(filename, source)
    return buf.getvalue()


def _make_role(ctx, iam) -> str:
    """This check's own execution role (basic logging only), deleted in its teardown."""
    name = ctx.unique_name("sim2real-behav-tel-")
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

    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"function failed: {cfg.get('StateReason')} {cfg.get('LastUpdateStatusReason')}"
            )
        return cfg

    timeout_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = _probe()
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            break
        if time.monotonic() > deadline:
            raise TimeoutError(f"function {name} did not reach Active within {timeout_s:.0f}s: {cfg!r}")
        time.sleep(1.0)
    return name


def _invoke_with_role_retry(ctx, lam, fn: str, payload: bytes, *, timeout_s: float = 90.0) -> dict:
    """Invoke, retrying only the IAM role-propagation refusal Active can still race."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            return lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                               LogType="Tail", Payload=payload)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "AccessDeniedException" or _ROLE_PROPAGATION not in err.get(
                "Message", ""
            ):
                raise
            if time.monotonic() > deadline:
                raise TimeoutError(f"Invoke kept failing on role propagation: {err!r}") from exc
            time.sleep(3)


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Telemetry API Subscribe call is refused with an exact validation error for an unknown
    schemaVersion, a destination URI without a port, an empty types array and an out-of-range
    buffering.maxItems, and an otherwise-identical request succeeds.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/telemetry-api-reference.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/telemetry-api.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-tel-"),
        Runtime=RUNTIME, Role=_make_role(ctx, ctx.client("iam")), Handler="index.handler",
        Code={"ZipFile": _zip("index.py", HANDLER)}, MemorySize=256, Timeout=25,
        Tags={"sim2real": CHECK},
    )

    resp = _invoke_with_role_retry(ctx, lam, fn, b"{}")
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"the probing invoke must itself succeed: StatusCode={resp.get('StatusCode')!r}, "
        f"FunctionError={resp.get('FunctionError')!r}, "
        f"log={base64.b64decode(resp.get('LogResult', '')).decode('utf-8', 'replace')!r}"
    )
    results = json.loads(resp["Payload"].read())

    cases = {
        "invalid_schema_version": (
            400,
            "Telemetry.DeserializationError",
            "unknown variant `9999-99-99`, expected one of `2020-08-15`, `2021-03-18`, "
            "`2022-07-01`, `2022-12-13`, `2025-01-29` at line 1 column 30",
        ),
        "destination_uri_without_port": (
            400, "Telemetry.ValidationError", "URI port is not provided",
        ),
        "empty_types": (
            400, "Telemetry.ValidationError", "types should not be empty",
        ),
        "maxitems_out_of_range": (
            400, "Telemetry.ValidationError", "maxItems should be between 1000 and 10000",
        ),
    }
    for key, (status, error_type, error_message) in cases.items():
        obs = results[key]
        assert obs["status"] == status, f"{key}: expected HTTP {status}, got {obs!r}"
        body = json.loads(obs["body"])
        assert body == {"errorType": error_type, "errorMessage": error_message}, (
            f"{key}: expected errorType={error_type!r} errorMessage={error_message!r}, got {body!r}"
        )

    valid = results["valid"]
    assert valid["status"] == 200, f"a schema-valid subscribe must succeed, got {valid!r}"
    assert json.loads(valid["body"]) == "OK", f"a successful Subscribe body is \"OK\", got {valid!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
