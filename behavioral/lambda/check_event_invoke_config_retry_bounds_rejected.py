"""event-invoke-config-retry-bounds-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-invoke-config-retry-bounds-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MaximumRetryAttempts above the documented cap of 2 is rejected with ValidationException,
    and the existing valid config is not overwritten. The MaximumEventAgeInSeconds floor is not
    tested because botocore enforces it client-side.
    """
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-lambda-einv-bad-")
    _create_function(ctx, lam, name=name)
    _wait_active(lam, name)

    # Positive control: an in-bounds value (the documented cap itself) must be
    # accepted. Without this, a target that rejects EVERY put_function_event_invoke_config
    # call would pass the negative below for the wrong reason.
    lam.put_function_event_invoke_config(FunctionName=name, MaximumRetryAttempts=2)
    baseline = lam.get_function_event_invoke_config(FunctionName=name)
    assert baseline["MaximumRetryAttempts"] == 2, (
        f"positive control: expected MaximumRetryAttempts=2 to be accepted and reflected, "
        f"got {baseline.get('MaximumRetryAttempts')!r}"
    )

    code, message = _error(
        lambda: lam.put_function_event_invoke_config(FunctionName=name, MaximumRetryAttempts=5)
    )
    assert code == "ValidationException", (
        f"expected ValidationException for MaximumRetryAttempts=5, got {code}"
    )
    expected_message = (
        "1 validation error detected: Value '5' at 'maximumRetryAttempts' failed to satisfy "
        "constraint: Member must have value less than or equal to 2"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r} for MaximumRetryAttempts=5, got {message!r}"
    )

    # The rejected put must not overwrite the existing (valid) config as a side effect.
    after = lam.get_function_event_invoke_config(FunctionName=name)
    assert after["MaximumRetryAttempts"] == 2, (
        f"rejected put must not mutate the existing config, expected MaximumRetryAttempts=2, "
        f"got {after.get('MaximumRetryAttempts')!r}"
    )


_DEFAULT_HANDLER_SRC = """
import json

def handler(event, context):
    if isinstance(event, dict) and event.get("fail"):
        raise Exception("intentional-failure: " + str(event.get("fail")))
    return {"echo": event}
"""


def _make_zip(src: str = _DEFAULT_HANDLER_SRC, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
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


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=1.5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _cleanup_fn(ctx, lam, name: str) -> None:
    """Delete the function and the log group Lambda implicitly creates for it."""
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


def _wait_active(lam, name: str, timeout_s: float = 90, interval_s: float = 1.5):
    """Poll until State settles at Active or Failed; Failed does not raise here because it
    surfaces as a service error on the next call."""
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"function {name} to leave Pending",
    )


def _create_function(
    ctx,
    lam,
    name=None,
    src: str = _DEFAULT_HANDLER_SRC,
    handler: str = "index.handler",
    runtime: str = "python3.12",
    timeout: int = 15,
    memory: int = 128,
    role_arn: str | None = None,
    env: dict | None = None,
    **kwargs,
):
    """CreateFunction with teardown registered up front and bounded retry on IAM
    role propagation (the classic "cannot be assumed by Lambda" race)."""
    name = name or ctx.unique_name("sim2real-behav-lambda-fn-")
    params = dict(
        FunctionName=name,
        Runtime=runtime,
        Role=role_arn or _exec_role_arn(ctx),
        Handler=handler,
        Code={"ZipFile": _make_zip(src)},
        Timeout=timeout,
        MemorySize=memory,
        Publish=False,
        Tags={"sim2real:managed": "true"},
    )
    if env is not None:
        params["Environment"] = {"Variables": env}
    params.update(kwargs)

    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    last_exc = None
    for _ in range(8):
        try:
            return lam.create_function(**params)
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or (
                "InvalidParameterValueException" in msg and "role" in msg.lower()
            ):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
