"""put-concurrency-refused-on-unknown-function-preserves-real-reservation."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-concurrency-refused-on-unknown-function-preserves-real-reservation"
GROUP = "concurrency"
SERVICES = ["iam", "lambda", "logs"]

_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXECUTION_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION_MESSAGE = "The role defined for the function cannot be assumed by Lambda."


def _package(handler_body: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("entry.py", handler_body)
    return buf.getvalue()


def _teardown(undo, *not_found_codes: str):
    """``undo`` as a cleanup: tolerates the resource's own not-found codes, raises everything else."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found_codes:
                return
            raise

    return run_undo


def _create_execution_role(ctx):
    """A Lambda execution role this check creates and tears down."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXECUTION_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXECUTION_POLICY_ARN))
    return role_arn


def _create_function_once_role_is_assumable(lam, *, deadline_s: float = 90.0, **kwargs):
    """CreateFunction, retried only while Lambda still cannot assume a just-created role."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            still_propagating = (
                error.get("Code") == "InvalidParameterValueException"
                and error.get("Message") == _ROLE_PROPAGATION_MESSAGE
            )
            if not still_propagating or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


def _wait_until_active(lam, function_name: str, *, deadline_s: float = 60.0) -> None:
    deadline = time.monotonic() + deadline_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=function_name)["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"{function_name} reached State=Failed while waiting for Active")
        time.sleep(1.0)
    raise AssertionError(f"{function_name} did not reach State=Active within {deadline_s}s, last State={state!r}")


def _expect_error(fn, code: str, message: str) -> None:
    """Run ``fn``, which AWS must refuse with exactly ``(code, message)``; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        assert error.get("Code") == code, f"expected error code {code!r}, got {error.get('Code')!r}"
        assert error.get("Message") == message, (
            f"expected error message {message!r}, got {error.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused with {code!r}, but it returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutFunctionConcurrency(5) on a real function is read back by GetFunctionConcurrency; the
    same call against a function name this run never created is refused with the exact
    ResourceNotFoundException message, and the real function's reservation is still 5 afterward.
    """
    lam = ctx.client("lambda")
    role_arn = _create_execution_role(ctx)

    function_name = ctx.unique_name("sim2real-behav-fn-")
    _create_function_once_role_is_assumable(
        lam,
        FunctionName=function_name,
        Runtime="python3.12",
        Handler="entry.handler",
        Role=role_arn,
        Code={"ZipFile": _package("def handler(event, context):\n    return event\n")},
        MemorySize=128,
        Timeout=10,
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=function_name),
                             "ResourceNotFoundException"))
    ctx.on_cleanup(_teardown(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}"),
        "ResourceNotFoundException",
    ))
    _wait_until_active(lam, function_name)

    put_response = lam.put_function_concurrency(FunctionName=function_name, ReservedConcurrentExecutions=5)
    assert put_response["ReservedConcurrentExecutions"] == 5, (
        f"PutFunctionConcurrency(5) on {function_name} returned "
        f"{put_response.get('ReservedConcurrentExecutions')!r}, expected 5"
    )

    read_after_put = lam.get_function_concurrency(FunctionName=function_name)
    assert read_after_put["ReservedConcurrentExecutions"] == 5, (
        f"GetFunctionConcurrency on {function_name} returned "
        f"{read_after_put.get('ReservedConcurrentExecutions')!r} right after Put(5), expected 5"
    )

    ghost_name = ctx.unique_name("sim2real-behav-ghost-")
    ghost_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{ghost_name}:$LATEST"
    _NOT_FOUND = ("ResourceNotFoundException", f"Function not found: {ghost_arn}")
    _expect_error(
        lambda: lam.put_function_concurrency(FunctionName=ghost_name, ReservedConcurrentExecutions=5),
        *_NOT_FOUND,
    )

    read_after_refusal = lam.get_function_concurrency(FunctionName=function_name)
    assert read_after_refusal["ReservedConcurrentExecutions"] == 5, (
        f"GetFunctionConcurrency on {function_name} returned "
        f"{read_after_refusal.get('ReservedConcurrentExecutions')!r} after the refused call "
        f"against {ghost_name}, expected the reservation to remain 5"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
