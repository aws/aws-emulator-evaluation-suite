"""invoke-code-artifact-state-errors."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "invoke-code-artifact-state-errors"
GROUP = 'invoke_sync'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_EXEC_ROLES = {}


def _exec_role_arn(ctx):
    """An execution role this check creates, shared by every function it deploys."""
    cached = _EXEC_ROLES.get(id(ctx))
    if cached is not None and cached[0] is ctx:
        return cached[1]
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
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _EXEC_ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, kwargs, timeout_s=90):
    """CreateFunction, retried while a freshly created role is not yet assumable by Lambda."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed by Lambda" in err.get("Message", "")
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


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
        "Role": role or _exec_role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
        "Tags": {"sim2real": CHECK},
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_function(lam, kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _invoke_refusal(lam, fn, timeout_s=30.0):
    """Poll Invoke until it is refused; raise if it still succeeds at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = lam.invoke(FunctionName=fn, Payload=b"{}")
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"Invoke on deleted {fn} still succeeded after {timeout_s}s: {resp!r}")
        time.sleep(2.0)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeleteFunction removes a function and its code artifact, GetFunctionConfiguration and
    Invoke are ResourceNotFoundException with exact messages instead of a stale success."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, HANDLER_V1)

    resp = lam.invoke(FunctionName=fn, Payload=json.dumps({"mode": "echo"}).encode("utf-8"))
    decoded = json.loads(resp["Payload"].read())
    assert decoded["marker"] == "v1", decoded

    lam.delete_function(FunctionName=fn)

    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    expected_message = f"Function not found: {fn_arn}"
    config_code, config_msg = _error(lambda: lam.get_function_configuration(FunctionName=fn))
    assert config_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from an independent control-plane read "
        f"(GetFunctionConfiguration) right after delete, got {config_code}"
    )
    assert config_msg == expected_message, (
        f"GetFunctionConfiguration on a deleted function: expected message {expected_message!r}, "
        f"got {config_msg!r}"
    )

    # Deletion can take a brief moment to reach the invoke path's own routing layer, so Invoke is
    # polled until it is refused, within a bounded window, on every target.
    code, message = _invoke_refusal(lam, fn)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for Invoke on a deleted function's code artifact, got {code}"
    )
    expected_invoke_message = f"Function not found: {fn_arn}:$LATEST"
    assert message == expected_invoke_message, (
        f"Invoke on a deleted function: expected message {expected_invoke_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
