"""create-get-roundtrip."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-get-roundtrip"
GROUP = 'lifecycle'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_ASSUMABLE = "The role defined for the function cannot be assumed by Lambda."
_ROLES = []


def _delete_role(iam, name):
    for call in (
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY),
        lambda: iam.delete_role(RoleName=name),
    ):
        try:
            call()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise


def _execution_role(ctx):
    """The execution role this check creates for its functions, one per run."""
    for owner, arn in _ROLES:
        if owner is ctx:
            return arn
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lam-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY)
    _ROLES.append((ctx, arn))
    return arn


def _call_create_function(lam, **kwargs):
    """CreateFunction, retried while IAM propagates the execution role this check created."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") != "InvalidParameterValueException"
                or err.get("Message") != _ROLE_NOT_ASSUMABLE
                or time.monotonic() > deadline
            ):
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
        "Role": role or _execution_role(ctx),
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
    _call_create_function(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFunction → GetFunction returns consistent configuration."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return e", memory=256, timeout=30)
    config = lam.get_function(FunctionName=fn)["Configuration"]
    assert config["FunctionName"] == fn, (
        f"GetFunction returned FunctionName {config['FunctionName']!r}, expected {fn!r}"
    )
    assert config["MemorySize"] == 256, (
        f"GetFunction returned MemorySize {config['MemorySize']!r}, expected 256 "
        "(the value CreateFunction was called with, not the API default of 128)"
    )
    assert config["Timeout"] == 30, (
        f"GetFunction returned Timeout {config['Timeout']!r}, expected 30 "
        "(the value CreateFunction was called with, not the API default of 3)"
    )
    assert config["State"] == "Active", (
        f"GetFunction returned State {config['State']!r}, expected Active after the "
        "function was already observed Active via GetFunctionConfiguration"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
