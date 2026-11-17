"""create-function-name-over-64-characters-rejected."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-function-name-over-64-characters-rejected"
GROUP = "configuration_bounds"
SERVICES = ["iam", "lambda"]

_MAX_FUNCTION_NAME_LENGTH = 64

_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_ROLE_NOT_YET_ASSUMABLE = (
    "InvalidParameterValueException",
    "The role defined for the function cannot be assumed by Lambda.",
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _zip_of(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _name_of_length(ctx, prefix: str, length: int) -> str:
    base = ctx.unique_name(prefix)
    pad = "a" * (length - len(base))
    assert pad, f"{base!r} is already {len(base)} characters, at or past {length}"
    return base + pad


def _create_function_once_role_propagates(lam, deadline, **kwargs):
    """CreateFunction, retried only while the just-created role is not yet assumable by Lambda."""
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _ROLE_NOT_YET_ASSUMABLE or (
                time.monotonic() > deadline
            ):
                raise
            time.sleep(3)


def _refused(fn):
    """The (code, message) a call is refused with; raises if the call instead succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction refuses a FunctionName one character past the documented 64-character
    maximum with its exact validation message, and a 64-character name is created successfully.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-lam-namelen-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    zip_bytes = _zip_of("def handler(event, context):\n    return event\n")

    over_name = _name_of_length(ctx, "sim2real-lam-namelen-over-", _MAX_FUNCTION_NAME_LENGTH + 1)
    code, message = _refused(lambda: lam.create_function(
        FunctionName=over_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
    ))
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a {len(over_name)}-character "
        f"FunctionName, got {code!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{over_name}' at 'functionName' failed to "
        f"satisfy constraint: Member must have length less than or equal to "
        f"{_MAX_FUNCTION_NAME_LENGTH}"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    get_code, _get_message = _refused(lambda: lam.get_function(FunctionName=over_name))
    assert get_code == "ResourceNotFoundException", (
        f"expected no function to exist for the refused name, got {get_code!r}"
    )

    ok_name = _name_of_length(ctx, "sim2real-lam-namelen-ok-", _MAX_FUNCTION_NAME_LENGTH)
    assert len(ok_name) == _MAX_FUNCTION_NAME_LENGTH, (
        f"expected a {_MAX_FUNCTION_NAME_LENGTH}-character control name, got {len(ok_name)}"
    )
    deadline = time.monotonic() + 90
    _create_function_once_role_propagates(
        lam,
        deadline,
        FunctionName=ok_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=ok_name), "ResourceNotFoundException"))

    created = lam.get_function_configuration(FunctionName=ok_name)
    assert created["FunctionName"] == ok_name, (
        f"expected the {_MAX_FUNCTION_NAME_LENGTH}-character name to be created verbatim, "
        f"got {created['FunctionName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
