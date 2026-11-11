"""event-invoke-config-crud."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "event-invoke-config-crud"
GROUP = 'invoke_async'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_EXEC_ROLES: dict = {}


def _exec_role_arn(ctx):
    """Execution role this check creates for its functions, once per run."""
    cached = _EXEC_ROLES.get(id(ctx))
    if cached and cached[0] is ctx:
        return cached[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _EXEC_ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function_retrying(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role propagates to Lambda."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            err = e.response.get("Error", {})
            if (err.get("Code") == "InvalidParameterValueException"
                    and "cannot be assumed by Lambda" in err.get("Message", "")
                    and time.monotonic() < deadline):
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
        "Role": role or _exec_role_arn(ctx),
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
    _create_function_retrying(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Put/Get/Delete EventInvokeConfig round-trips, and the deleted config is
    both unreadable and unmodifiable until it is put again."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return e")
    lam.put_function_event_invoke_config(
        FunctionName=fn, MaximumRetryAttempts=1, MaximumEventAgeInSeconds=120
    )
    config = lam.get_function_event_invoke_config(FunctionName=fn)
    assert config["MaximumRetryAttempts"] == 1, (
        f"expected MaximumRetryAttempts=1 after put, got {config['MaximumRetryAttempts']!r}"
    )
    assert config["MaximumEventAgeInSeconds"] == 120, (
        f"expected MaximumEventAgeInSeconds=120 after put, got {config['MaximumEventAgeInSeconds']!r}"
    )

    lam.delete_function_event_invoke_config(FunctionName=fn)
    code, message = _error(lambda: lam.get_function_event_invoke_config(FunctionName=fn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on get after delete, got {code!r}"
    )
    expected_message = (
        f"The function arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}:$LATEST "
        "doesn't have an EventInvokeConfig"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r} on get after delete, got {message!r}"
    )

    # A deleted config is not just unreadable -- it is also unmodifiable: Update
    # has nothing to update until Put recreates it.
    update_code, update_message = _error(
        lambda: lam.update_function_event_invoke_config(FunctionName=fn, MaximumRetryAttempts=2)
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted event-invoke-config, got {update_code!r}"
    )
    expected_update_message = (
        f"The function arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}:$LATEST "
        "doesn't have an EventInvokeConfig"
    )
    assert update_message == expected_update_message, (
        f"expected message {expected_update_message!r} updating a deleted event-invoke-config, "
        f"got {update_message!r}"
    )

    # The identifier (the function name) is reusable: Put after Delete recreates
    # the config rather than being permanently blocked by the prior delete.
    lam.put_function_event_invoke_config(
        FunctionName=fn, MaximumRetryAttempts=0, MaximumEventAgeInSeconds=60
    )
    recreated = lam.get_function_event_invoke_config(FunctionName=fn)
    assert recreated["MaximumRetryAttempts"] == 0, (
        f"expected MaximumRetryAttempts=0 after recreate, got {recreated['MaximumRetryAttempts']!r}"
    )
    assert recreated["MaximumEventAgeInSeconds"] == 60, (
        f"expected MaximumEventAgeInSeconds=60 after recreate, got {recreated['MaximumEventAgeInSeconds']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
