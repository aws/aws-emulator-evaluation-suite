"""handler-import-failure-raises-rather-than-echoing."""

from __future__ import annotations

import json as _json

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "handler-import-failure-raises-rather-than-echoing"
GROUP = "compute"
SERVICES = ["lambda"]

MISSING_MODULE = "sim2real_module_that_does_not_exist"
CONTROL_INPUT = 21


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A handler whose import cannot be resolved fails the invocation with a FunctionError naming
    the import; a handler that imports boto3 really gets it and returns this account's id.
    """
    lam = ctx.client("lambda")

    # --- Beat 1: positive control -- the runtime executes customer code at all --------------------
    control_fn = _deploy(ctx, lam, """\
        def handler(event, context):
            return {"doubled": event["n"] * 2, "ran": True}
        """)
    error, payload = _invoke(lam, control_fn, {"n": CONTROL_INPUT})
    assert error is None, (
        f"the control handler must run cleanly; got FunctionError={error!r} payload={payload!r}"
    )
    assert payload == {"doubled": CONTROL_INPUT * 2, "ran": True}, (
        f"the control handler must return its own computed output, got {payload!r}. A runtime that "
        f"echoes the invocation event instead of running the handler fails here"
    )

    # --- Beat 2: an unresolvable import must FAIL the invocation, not degrade quietly -------------
    # This is the beat that isolates the cause. The failure mode it exists for is a 200 carrying
    # function metadata and the event, with no FunctionError at all.
    broken_fn = _deploy(ctx, lam, f"""\
        import {MISSING_MODULE}

        def handler(event, context):
            return {{"unreachable": True}}
        """)
    broken_error, broken_payload = _invoke(lam, broken_fn, {"n": CONTROL_INPUT})
    assert broken_error is not None, (
        f"importing {MISSING_MODULE!r} cannot succeed, so the invocation must report a FunctionError; "
        f"got none, payload={broken_payload!r}. A runtime where every import succeeds -- or which "
        f"silently returns an event echo -- passes Beat 1 and fails here"
    )
    rendered = json.dumps(broken_payload)
    assert MISSING_MODULE in rendered, (
        f"the failure must NAME the module it could not import; got {rendered[:400]!r}. Any other "
        f"cause -- a timeout, a permission, an out-of-memory -- also produces a FunctionError"
    )
    assert "unreachable" not in rendered, (
        f"the handler body must never have run, so its return value must not appear: {rendered[:400]!r}"
    )

    # --- Beat 3: a RESOLVABLE import must really resolve, and the SDK must really work ------------
    # boto3 ships in the managed python runtimes. The handler calls a second service and returns the
    # account id, which is cross-checked against the caller's own view -- so a boto3 that evaluates to
    # None, a client that is a sentinel, or a call that returns None all fail.
    expected_account = ctx.client("sts").get_caller_identity()["Account"]
    sdk_fn = _deploy(ctx, lam, """\
        import boto3

        def handler(event, context):
            ident = boto3.client("sts").get_caller_identity()
            return {"account": ident["Account"], "boto3_is_none": boto3 is None}
        """)
    sdk_error, sdk_payload = _invoke(lam, sdk_fn, {})
    assert sdk_error is None, (
        f"importing boto3 must succeed in a managed python runtime; got FunctionError={sdk_error!r} "
        f"payload={sdk_payload!r}"
    )
    assert sdk_payload.get("boto3_is_none") is False, (
        f"boto3 must be a real module inside the handler, not None: {sdk_payload!r}"
    )
    assert sdk_payload.get("account") == expected_account, (
        f"the handler's own sts call must report this account {expected_account!r}, got "
        f"{sdk_payload.get('account')!r}. A stubbed client returning a sentinel, or a call returning "
        f"None, fails here -- and so does a runtime that echoes the event instead of invoking boto3"
    )


def _make_zip(code: str, filename: str = "index.py") -> bytes:
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


def _cleanup_fn(ctx, lam, name: str) -> None:
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


def _wait_active(lam, fn: str, timeout_s: float = 120.0) -> None:
    """A function whose CODE cannot import is still Active -- the import runs at invoke time, not at
    create time -- so this must not treat Beat 2's function as a create failure."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"function {fn} entered Failed: {last.get('StateReason')!r}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(
        f"function {fn} did not reach Active within {timeout_s}s (last={last!r})"
    )


def _deploy(ctx, lam, code: str) -> str:
    name = ctx.unique_name("sim2real-behav-import-")
    _create_function(lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _invoke(lam, fn: str, payload: dict) -> tuple[str | None, object]:
    """(FunctionError or None, decoded payload); never raises on FunctionError, Beat 2 asserts one.

    A cold first invoke can take 10-30s; the client read timeout, not a retry, absorbs it.
    """
    resp = lam.invoke(
        FunctionName=fn,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = resp["Payload"].read()
    decoded: object
    try:
        decoded = json.loads(body) if body else None
    except json.JSONDecodeError:
        decoded = body.decode(errors="replace")
    return resp.get("FunctionError"), decoded


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
