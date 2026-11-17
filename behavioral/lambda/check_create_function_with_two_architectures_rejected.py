"""create-function-with-two-architectures-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-function-with-two-architectures-rejected"
GROUP = "validation"
SERVICES = ["lambda"]

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_ROLE_PENDING = "The role defined for the function cannot be assumed by Lambda."


def _wait_cap(ctx, cap_s: float) -> float:
    """cap_s, shortened when the runner stops the check sooner, keeping 5 s for the failure."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _undo(delete, *gone_codes):
    """A cleanup calling delete(); it returns on the resource's own not-found codes, else raises."""

    def run_undo() -> None:
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in gone_codes:
                raise

    return run_undo


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", "def handler(event, context):\n    return event\n")
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role for a function that is never invoked; returns its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lfta-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Role"]["Arn"]
    ctx.on_cleanup(_undo(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create(ctx, lam, **params) -> None:
    """CreateFunction, repeated only while IAM has not yet made the new role assumable."""
    deadline = time.monotonic() + _wait_cap(ctx, 120.0)
    for attempt in range(10):
        try:
            lam.create_function(**params)
            break
        except ClientError as exc:
            last = attempt == 9 or time.monotonic() >= deadline
            if exc.response["Error"]["Message"] != _ROLE_PENDING or last:
                raise
        time.sleep(min(2 ** attempt, 20))
    name = params["FunctionName"]
    ctx.on_cleanup(_undo(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))


def _refusal(fn, code: str):
    """Call fn, which AWS must refuse with code; return the ClientError.

    A success fails the check, and a different code fails it raised from AWS's own error.
    """
    try:
        result = fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == code:
            return exc
        raise AssertionError(f"expected {code}, got {exc.response['Error']['Code']}") from exc
    raise AssertionError(f"expected {code}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction naming two architectures, where a function has exactly one, is refused and
    leaves no function; the same create naming arm64 alone succeeds and reads it back.
    """
    lam = ctx.client("lambda")
    role = _role(ctx)
    # A first function proves the role is assumable, so the refusal below is about the list.
    ready = ctx.unique_name("sim2real-lfta-ok-")
    _create(ctx, lam, FunctionName=ready, Runtime="python3.13", Role=role, Handler="app.handler",
            Code={"ZipFile": _zip()}, Tags={"sim2real": CHECK})

    name = ctx.unique_name("sim2real-lfta-")
    ctx.on_cleanup(_undo(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    err = _refusal(
        lambda: lam.create_function(FunctionName=name, Runtime="python3.13", Role=role, Handler="app.handler",
                                    Code={"ZipFile": _zip()}, Architectures=["x86_64", "arm64"],
                                    Tags={"sim2real": CHECK}),
        "ValidationException",
    )
    too_many = (
        "1 validation error detected: Value '[x86_64, arm64]' at 'architectures' failed to satisfy "
        "constraint: Member must have length less than or equal to 1"
    )
    message = err.response["Error"]["Message"]
    assert message == too_many, f"the refusal carried the message {message!r}"

    err = _refusal(lambda: lam.get_function(FunctionName=name), "ResourceNotFoundException")
    missing = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{name}"
    message = err.response["Error"]["Message"]
    assert message == missing, f"the refused name reads {message!r}, expected {missing!r}"

    _create(ctx, lam, FunctionName=name, Runtime="python3.13", Role=role, Handler="app.handler",
            Code={"ZipFile": _zip()}, Architectures=["arm64"], Tags={"sim2real": CHECK})
    arch = lam.get_function(FunctionName=name)["Configuration"]["Architectures"]
    assert arch == ["arm64"], f"the accepted create reads Architectures={arch!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
