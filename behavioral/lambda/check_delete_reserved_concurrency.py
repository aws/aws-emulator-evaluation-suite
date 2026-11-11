"""delete-reserved-concurrency."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-reserved-concurrency"
GROUP = 'concurrency'
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After deleting reserved concurrency, the field is absent from Get.

    The positive control (Get reflects the Put) comes first: without it, a target that never
    implements reserved concurrency at all would pass this check merely by never having the field.
    """
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return e")
    lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=5)
    before = lam.get_function_concurrency(FunctionName=fn)
    assert before.get("ReservedConcurrentExecutions") == 5, (
        f"expected ReservedConcurrentExecutions=5 after Put, got {before!r}"
    )
    lam.delete_function_concurrency(FunctionName=fn)
    after = lam.get_function_concurrency(FunctionName=fn)
    assert "ReservedConcurrentExecutions" not in after, (
        f"expected ReservedConcurrentExecutions absent after Delete, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
