"""delete-nonexistent."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-nonexistent"
GROUP = 'errors'
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


def _create_function_retrying(lam, kwargs, timeout_s=60):
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


def _create_function(lam, name, role_arn):
    created = _create_function_retrying(lam, dict(
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _make_zip("def handler(event, context): return event")},
        MemorySize=128,
        Timeout=30,
    ))
    _wait_active(lam, name)
    return created["FunctionArn"]


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    """DeleteFunction on a nonexistent name raises ResourceNotFoundException, while deleting an
    existing function and re-deleting a recreated one with the same name both succeed.
    """
    lam = ctx.client("lambda")
    role_arn = _role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-delnx-")

    fn_arn = _create_function(lam, name, role_arn)
    ctx.on_cleanup(lambda: _swallow(lambda: lam.delete_function(FunctionName=name)))

    # Positive control: DeleteFunction succeeds against the function it just created, so a
    # later ResourceNotFoundException cannot be "every DeleteFunction call fails".
    lam.delete_function(FunctionName=name)

    # Independent read: the function is really gone, not just that delete didn't raise.
    gone_code, gone_code_msg = _client_error(lambda: lam.get_function(FunctionName=name))
    assert gone_code == "ResourceNotFoundException", (
        f"GetFunction right after delete: expected ResourceNotFoundException, got {gone_code}"
    )
    expected_gone_code_msg = f"Function not found: {fn_arn}"
    assert gone_code_msg == expected_gone_code_msg, (
        f"expected message {expected_gone_code_msg!r}, got {gone_code_msg!r}"
    )

    # The subject under test: deleting the now-nonexistent name is rejected with the specific
    # not-found code, not a generic error and not a silent success.
    code, code_msg = _client_error(lambda: lam.delete_function(FunctionName=name))
    assert code == "ResourceNotFoundException", (
        f"DeleteFunction on nonexistent function: expected ResourceNotFoundException, got {code}"
    )
    expected_code_msg = f"Function not found: {fn_arn}"
    assert code_msg == expected_code_msg, (
        f"expected message {expected_code_msg!r}, got {code_msg!r}"
    )

    # Restore: the name is reusable. Recreating it and deleting it again succeeds identically,
    # and an independent terminal read confirms it is gone once more.
    _create_function(lam, name, role_arn)
    lam.delete_function(FunctionName=name)
    final_code, final_code_msg = _client_error(lambda: lam.get_function(FunctionName=name))
    assert final_code == "ResourceNotFoundException", (
        f"GetFunction after restore-delete: expected ResourceNotFoundException, got {final_code}"
    )
    expected_final_code_msg = f"Function not found: {fn_arn}"
    assert final_code_msg == expected_final_code_msg, (
        f"expected message {expected_final_code_msg!r}, got {final_code_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
