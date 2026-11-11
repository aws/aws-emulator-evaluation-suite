"""env-var-size-and-reserved-key-rejected."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "env-var-size-and-reserved-key-rejected"
GROUP = 'function_config'
SERVICES = ['lambda']

# Lambda caps the environment-variable set (keys + values) at 4 KB.
CONTROL_BLOB = 3000
OVER_BLOB = 5000

HANDLER = """\
import os


def handler(event, context):
    return {
        "blob_len": len(os.environ.get("SIM2REAL_BLOB", "")),
        "mark": os.environ.get("SIM2REAL_MARK"),
        "region_present": bool(os.environ.get("AWS_REGION")),
    }
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


def _wait_updated(lam, fn, timeout_s=120):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(f"{fn} update failed: {cfg.get('LastUpdateStatusReason')}")
        return cfg if cfg.get("LastUpdateStatus") in (None, "Successful") else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} LastUpdateStatus=Successful not reached within {timeout_s}s"
    return cfg


def _error(call):
    """(code, message) of the ClientError call raises; a success raises AssertionError."""
    try:
        result = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _invoke_env(lam, fn):
    resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    assert resp["StatusCode"] == 200, resp["StatusCode"]
    assert "FunctionError" not in resp, resp.get("FunctionError")
    return json.loads(resp["Payload"].read())


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Env vars over the 4 KB budget and reserved keys (AWS_REGION, _HANDLER, ...) are rejected,
    leaving the configured variables and the values the running function observes unchanged.
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function(
        lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(HANDLER)},
        MemorySize=128, Timeout=30,
        Environment={"Variables": {"SIM2REAL_BLOB": "x" * CONTROL_BLOB, "SIM2REAL_MARK": "ok"}},
        Tags={"sim2real": "env-var-size-and-reserved-key-rejected"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_active(lam, fn)

    # Control: a set comfortably under 4 KB is accepted and delivered to the runtime.
    seen = _invoke_env(lam, fn)
    assert seen["blob_len"] == CONTROL_BLOB, seen
    assert seen["mark"] == "ok", seen
    assert seen["region_present"] is True, (
        f"AWS_REGION must be injected by the runtime, got {seen}"
    )

    # Rejection 1: the total env-var payload exceeds the 4 KB budget.
    over_vars = {"SIM2REAL_BLOB": "x" * OVER_BLOB, "SIM2REAL_MARK": "ok"}
    big_code, big_msg = _error(
        lambda: lam.update_function_configuration(
            FunctionName=fn, Environment={"Variables": over_vars},
        )
    )
    assert big_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a {OVER_BLOB}-byte env value (4 KB budget), "
        f"got {big_code}: {big_msg}"
    )
    assert big_msg == (
        "Lambda was unable to configure your environment variables because the environment "
        "variables you have provided exceeded the 4KB limit. Measured size: "
        f"{len(json.dumps(over_vars, separators=(',', ':')))} bytes"
    ), f"the 4 KB budget rejection message: {big_msg!r}"
    after = lam.get_function_configuration(FunctionName=fn)["Environment"]["Variables"]
    assert len(after["SIM2REAL_BLOB"]) == CONTROL_BLOB, (
        f"the rejected update must not be partially applied, stored value is "
        f"{len(after['SIM2REAL_BLOB'])} bytes"
    )

    # Rejection 2: a runtime-reserved key may not be set by the customer.
    res_code, res_msg = _error(
        lambda: lam.update_function_configuration(
            FunctionName=fn,
            Environment={
                "Variables": {
                    "SIM2REAL_BLOB": "x" * CONTROL_BLOB,
                    "SIM2REAL_MARK": "ok",
                    "AWS_REGION": "us-east-1",
                }
            },
        )
    )
    assert res_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for the reserved key AWS_REGION, got "
        f"{res_code}: {res_msg}"
    )
    assert res_msg == (
        "Lambda was unable to configure your environment variables because the environment "
        "variables you have provided contains reserved keys that are currently not supported "
        "for modification. Reserved keys used in this request: AWS_REGION"
    ), f"the reserved-key rejection message: {res_msg!r}"
    after2 = lam.get_function_configuration(FunctionName=fn)["Environment"]["Variables"]
    assert "AWS_REGION" not in after2, (
        f"the reserved key must not be stored on the function, got keys {sorted(after2)}"
    )

    # The control case still works after both refusals, and a legal update still applies.
    seen2 = _invoke_env(lam, fn)
    assert seen2["blob_len"] == CONTROL_BLOB and seen2["mark"] == "ok", seen2
    lam.update_function_configuration(
        FunctionName=fn,
        Environment={"Variables": {"SIM2REAL_BLOB": "y" * 10, "SIM2REAL_MARK": "updated"}},
    )
    _wait_updated(lam, fn)
    seen3 = _invoke_env(lam, fn)
    assert seen3 == {"blob_len": 10, "mark": "updated", "region_present": True}, seen3


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
