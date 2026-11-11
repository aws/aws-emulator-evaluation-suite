"""delete-function-url."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-function-url"
GROUP = 'function_url'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLE_ARNS: dict = {}


def _role_arn(ctx):
    key = id(ctx)
    if key not in _ROLE_ARNS:
        iam = ctx.client("iam")
        role_name = ctx.unique_name("sim2real-behav-role-")
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        _ROLE_ARNS[key] = role["Role"]["Arn"]
    return _ROLE_ARNS[key]


def _create_function(lam, kwargs, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed" in err.get("Message", "")
                and time.monotonic() < deadline
            ):
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
    _create_function(lam, kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _client_error(fn):
    """(code, message) of a call that must be refused; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After deleting URL config, GetFunctionUrlConfig returns 404, a mutation on the
    dead config also fails, and the identifier is reusable."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return e")
    lam.create_function_url_config(FunctionName=fn, AuthType="NONE")

    before = lam.get_function_url_config(FunctionName=fn)
    assert before["AuthType"] == "NONE", (
        f"expected AuthType NONE before delete, got {before.get('AuthType')!r}"
    )

    lam.delete_function_url_config(FunctionName=fn)

    read_code, read_code_msg = _client_error(lambda: lam.get_function_url_config(FunctionName=fn))
    assert read_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted config, got {read_code!r}"
    )
    expected_read_code_msg = "The resource you requested does not exist."
    assert read_code_msg == expected_read_code_msg, (
        f"expected message {expected_read_code_msg!r}, got {read_code_msg!r}"
    )

    mutate_code, mutate_code_msg = _client_error(
        lambda: lam.update_function_url_config(FunctionName=fn, AuthType="AWS_IAM")
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating deleted config, got {mutate_code!r}"
    )
    expected_mutate_code_msg = "The resource you requested does not exist."
    assert mutate_code_msg == expected_mutate_code_msg, (
        f"expected message {expected_mutate_code_msg!r}, got {mutate_code_msg!r}"
    )

    lam.create_function_url_config(FunctionName=fn, AuthType="NONE")
    after = lam.get_function_url_config(FunctionName=fn)
    assert after["AuthType"] == "NONE", (
        f"expected the identifier to be reusable after delete, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
