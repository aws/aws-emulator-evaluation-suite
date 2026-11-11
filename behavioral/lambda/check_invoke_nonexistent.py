"""invoke-nonexistent."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "invoke-nonexistent"
GROUP = 'invoke_sync'
SERVICES = ['lambda']

_HANDLER = "def handler(event, context): return {'ok': True}"


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
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, name, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Failed":
            raise AssertionError(f"function {name} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{name} did not reach Active within {timeout_s}s; last saw {last!r}")


def _deploy_function(ctx, lam):
    name = ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam, dict(
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_exec_role_arn(ctx),
        Code={"ZipFile": _make_zip(_HANDLER)},
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _invoke_ok(fn):
    try:
        return fn()
    except ClientError as exc:
        raise AssertionError(
            f"positive control: expected a clean invoke, got {exc.response.get('Error', {})}"
        ) from exc


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Invoke on a function the check created returns 200 without FunctionError, and on a name never
    created it is ResourceNotFoundException with the exact message."""
    lam = ctx.client("lambda")
    name = _deploy_function(ctx, lam)

    ok = _invoke_ok(lambda: lam.invoke(FunctionName=name, Payload=b"{}"))
    assert ok["StatusCode"] == 200 and "FunctionError" not in ok, (
        f"positive control: expected a clean 200 invoke of {name!r}, got {ok!r}"
    )

    missing_name = ctx.unique_name("sim2real-behav-fn-missing-")
    code, message = _error(lambda: lam.invoke(FunctionName=missing_name, Payload=b"{}"))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException invoking {missing_name!r}, got {code}"
    )
    expected = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{missing_name}:$LATEST"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
