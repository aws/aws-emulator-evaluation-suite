"""cold-start-after-timeout."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "cold-start-after-timeout"
GROUP = 'cold_start'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLES: dict = {}


def _role_arn(ctx):
    """Create this check's own Lambda execution role once per run and register its cleanup."""
    import json as _json

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
    from botocore.exceptions import ClientError as _ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except _ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = err.get("Code") == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", "")
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


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


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _deploy_function(ctx, lam, code, *, name=None, handler="index.handler",
                     runtime="python3.12", memory=128, timeout=30, environment=None,
                     layers=None, ephemeral_storage=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or _role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_function(lam, Tags={"sim2real:managed": "true", "sim2real:check": CHECK}, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _invoke_sync(lam, fn, payload):
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(
            f"Function {fn} returned FunctionError={resp['FunctionError']}: {body.decode()[:500]}"
        )
    return json.loads(body) if body else None


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a timeout, the environment is reset — next invoke gets fresh INIT."""
    lam = ctx.client("lambda")
    code = """\
import time
CALL_COUNT = 0
def handler(event, context):
    global CALL_COUNT
    CALL_COUNT += 1
    if event.get("timeout"):
        time.sleep(60)
    return {"call_count": CALL_COUNT}
"""
    fn = _deploy_function(ctx, lam, code, timeout=3)
    conc = lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=1)
    assert conc["ReservedConcurrentExecutions"] == 1, (
        f"expected the single-slot concurrency lock to hold, got {conc!r}"
    )
    r1 = _invoke_sync(lam, fn, {})
    assert r1["call_count"] == 1, (
        f"first invocation of a fresh function must run a fresh init, got call_count={r1['call_count']!r}"
    )

    resp = lam.invoke(FunctionName=fn, Payload=json.dumps({"timeout": True}).encode())
    body = resp["Payload"].read()
    assert resp.get("FunctionError"), (
        f"a call that sleeps past the function's 3s Timeout must report a FunctionError, got {resp!r}"
    )
    assert b"task timed out" in body.lower(), (
        f"expected the failure to be reported as a task timeout, got body={body!r}"
    )

    r2 = _invoke_sync(lam, fn, {})
    assert r2["call_count"] == 1, (
        f"the very next invocation after a timeout must land on a fresh execution environment "
        f"(call_count reset to 1), got call_count={r2['call_count']!r} — the timed-out environment "
        f"was reused instead of discarded"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
