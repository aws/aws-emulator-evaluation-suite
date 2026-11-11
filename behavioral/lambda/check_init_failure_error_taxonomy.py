"""init-failure-error-taxonomy."""

from __future__ import annotations

import json as _json

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "init-failure-error-taxonomy"
GROUP = 'errors'
SERVICES = ['lambda']

IMPORT_FAILS = """\
import sim2real_definitely_not_a_module


def handler(event, context):
    return {"ok": True}
"""

VALID = """\
def handler(event, context):
    return {"ok": True}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLES: dict = {}


def _role_arn(ctx):
    """Create this check's own Lambda execution role once per run and register its cleanup."""
    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = err.get("Code") == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", "")
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


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


def _deploy(ctx, lam, code, handler="index.handler"):
    name = ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam,
        FunctionName=name, Runtime="python3.12", Handler=handler,
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(code)},
        MemorySize=128, Timeout=30,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _invoke_failure(lam, fn):
    resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    assert resp["StatusCode"] == 200, (
        f"an init failure is still HTTP 200 with an error payload, got {resp['StatusCode']}"
    )
    assert resp.get("FunctionError") == "Unhandled", (
        f"expected X-Amz-Function-Error: Unhandled for an init failure, got "
        f"{resp.get('FunctionError')!r}"
    )
    return json.loads(resp["Payload"].read())


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Init failures surface at invoke as Runtime.ImportModuleError and Runtime.HandlerNotFound on
    every invoke while the functions stay State Active, and a correct function on the same runtime
    returns its payload without FunctionError."""
    lam = ctx.client("lambda")

    # --- Class 1: the handler module fails to import.
    broken = _deploy(ctx, lam, IMPORT_FAILS)
    cfg = lam.get_function_configuration(FunctionName=broken)
    assert cfg["State"] == "Active", (
        f"an unimportable package must still create to State=Active (init runs at invoke time), "
        f"got {cfg['State']}/{cfg.get('StateReason')}"
    )
    body = _invoke_failure(lam, broken)
    assert body.get("errorType") == "Runtime.ImportModuleError", (
        f"expected errorType Runtime.ImportModuleError, got {body!r}"
    )
    assert "Unable to import module 'index'" in body.get("errorMessage", ""), (
        f"the errorMessage must name the module that failed to import, got {body!r}"
    )
    assert "stackTrace" in body, f"the error payload must carry stackTrace, got {sorted(body)}"

    # Deterministic: a second invoke fails identically rather than succeeding from a cache.
    again = _invoke_failure(lam, broken)
    assert again.get("errorType") == "Runtime.ImportModuleError", (
        f"the init failure must reproduce on every invoke, second invoke gave {again!r}"
    )
    assert lam.get_function_configuration(FunctionName=broken)["State"] == "Active", (
        "a failing init must not transition the function out of Active"
    )

    # --- Class 2: the module imports but the named handler symbol is absent.
    missing = _deploy(ctx, lam, VALID, handler="index.no_such_handler")
    assert lam.get_function_configuration(FunctionName=missing)["State"] == "Active", (
        "a bad Handler string must not be rejected at create time"
    )
    body2 = _invoke_failure(lam, missing)
    assert body2.get("errorType") == "Runtime.HandlerNotFound", (
        f"expected errorType Runtime.HandlerNotFound, got {body2!r}"
    )
    assert "no_such_handler" in body2.get("errorMessage", ""), (
        f"the errorMessage must name the missing handler symbol, got {body2!r}"
    )

    # --- Control: the same runtime and package shape with a working handler.
    good = _deploy(ctx, lam, VALID)
    ok = lam.invoke(FunctionName=good, Payload=b"{}")
    assert ok["StatusCode"] == 200, ok["StatusCode"]
    assert "FunctionError" not in ok, (
        f"the control function must not report a FunctionError, got {ok.get('FunctionError')!r}"
    )
    payload = json.loads(ok["Payload"].read())
    assert payload == {"ok": True}, f"expected the control handler's own return value, got {payload!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
