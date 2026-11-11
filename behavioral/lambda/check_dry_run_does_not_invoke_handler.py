"""dry-run-does-not-invoke-handler."""

from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "dry-run-does-not-invoke-handler"
GROUP = 'invoke_sync'
SERVICES = ['lambda']

RAISES = """\
def handler(event, context):
    print("__MARKER__")
    raise RuntimeError("sim2real-dryrun-canary")
"""

RETURNS = """\
def handler(event, context):
    print("__MARKER__")
    return {"marker": "sim2real-dryrun-control"}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}


def _role_arn(ctx) -> str:
    """An execution role this check creates (once per run) and deletes in cleanup."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    _ROLES[id(ctx)] = arn
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
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll(probe, timeout_s, interval_s=1.0):
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

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _deploy(ctx, lam, code):
    name = ctx.unique_name("sim2real-behav-fn-")
    _create_function(
        lam,
        FunctionName=name, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(code)},
        MemorySize=128, Timeout=30,
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(call):
    """(code, message) of the ClientError call raises; a success raises AssertionError."""
    try:
        result = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DryRun of a handler that can only fail returns 204, no FunctionError, an empty body and no
    log marker, so it never dispatched; DryRun still refuses an unknown function and a bad body.
    """
    lam = ctx.client("lambda")
    canary_marker = ctx.unique_name("SIM2REAL-DRYRUN-CANARY-")
    control_marker = ctx.unique_name("SIM2REAL-DRYRUN-CONTROL-")
    canary = _deploy(ctx, lam, RAISES.replace("__MARKER__", canary_marker))
    control = _deploy(ctx, lam, RETURNS.replace("__MARKER__", control_marker))

    dry = lam.invoke(
        FunctionName=canary, InvocationType="DryRun", Payload=b"{}", LogType="Tail",
    )
    assert dry["StatusCode"] == 204, f"DryRun must return 204, got {dry['StatusCode']}"
    assert "FunctionError" not in dry, (
        f"DryRun reported FunctionError={dry.get('FunctionError')!r} — the handler was dispatched, "
        f"which DryRun must never do"
    )
    assert dry["Payload"].read() == b"", "DryRun must return an empty response body"
    dry_log = base64.b64decode(dry.get("LogResult") or "").decode("utf-8", errors="replace")
    assert canary_marker not in dry_log, (
        f"DryRun must not dispatch the handler, but {canary_marker!r} was captured in its "
        f"LogResult: {dry_log[:300]!r}"
    )

    # The same function on the real path does fail — so the 204 above was not a broken handler.
    live = lam.invoke(
        FunctionName=canary, InvocationType="RequestResponse", Payload=b"{}", LogType="Tail",
    )
    assert live["StatusCode"] == 200, live["StatusCode"]
    assert live.get("FunctionError") == "Unhandled", (
        f"the canary must fail when actually invoked, got FunctionError="
        f"{live.get('FunctionError')!r}"
    )
    body = json.loads(live["Payload"].read())
    assert "sim2real-dryrun-canary" in body.get("errorMessage", ""), body
    live_log = base64.b64decode(live.get("LogResult") or "").decode("utf-8", errors="replace")
    assert canary_marker in live_log, (
        f"the live RequestResponse invoke must dispatch the handler and capture {canary_marker!r} "
        f"in LogResult, got {live_log[:300]!r}"
    )

    # DryRun on a healthy function likewise delivers nothing back to the caller.
    dry_ok = lam.invoke(
        FunctionName=control, InvocationType="DryRun", Payload=b"{}", LogType="Tail",
    )
    assert dry_ok["StatusCode"] == 204, dry_ok["StatusCode"]
    assert dry_ok["Payload"].read() == b"", (
        "DryRun must not return the handler's return value"
    )
    dry_ok_log = base64.b64decode(dry_ok.get("LogResult") or "").decode("utf-8", errors="replace")
    assert control_marker not in dry_ok_log, (
        f"DryRun of a healthy function must not dispatch it either, but {control_marker!r} was "
        f"captured in its LogResult: {dry_ok_log[:300]!r}"
    )

    # DryRun still validates the request itself.
    absent = ctx.unique_name("sim2real-behav-absent-")
    nf_code, nf_msg = _error(
        lambda: lam.invoke(FunctionName=absent, InvocationType="DryRun", Payload=b"{}")
    )
    assert nf_code == "ResourceNotFoundException", (
        f"DryRun of an unknown function must be refused with ResourceNotFoundException, got "
        f"{nf_code}"
    )
    absent_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{absent}"
    assert nf_msg == f"Function not found: {absent_arn}:$LATEST", f"not-found message: {nf_msg!r}"
    bad_code, bad_msg = _error(
        lambda: lam.invoke(FunctionName=control, InvocationType="DryRun", Payload=b"not-json")
    )
    assert bad_code == "InvalidRequestContentException", (
        f"DryRun must still parse the request body, expected InvalidRequestContentException, got "
        f"{bad_code}: {bad_msg}"
    )
    assert bad_msg == (
        "Could not parse request body into json: Could not parse payload into json: "
        "Unrecognized token 'not': was expecting (JSON String, Number, Array, Object or token "
        "'null', 'true' or 'false')\n at [Source: REDACTED "
        "(`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: 1]"
    ), f"unparseable-body message: {bad_msg!r}"

    # Control still works.
    final = lam.invoke(FunctionName=control, Payload=b"{}", LogType="Tail")
    assert final["StatusCode"] == 200 and "FunctionError" not in final, final.get("FunctionError")
    final_body = json.loads(final["Payload"].read())
    assert final_body == {"marker": "sim2real-dryrun-control"}, final_body
    final_log = base64.b64decode(final.get("LogResult") or "").decode("utf-8", errors="replace")
    assert control_marker in final_log, (
        f"the final control invoke must dispatch the handler and capture {control_marker!r} in "
        f"LogResult, got {final_log[:300]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
