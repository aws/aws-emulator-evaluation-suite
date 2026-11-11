"""lambda-rejects-role-without-lambda-trust."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-rejects-role-without-lambda-trust"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction rejects a role that does not trust lambda.amazonaws.com with
    InvalidParameterValueException and its exact message, leaves no function behind, and
    succeeds once the role trusts Lambda."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    zip_bytes = _zip_bytes("def handler(event, context):\n    return {'ok': True}\n")

    bad_role_name = ctx.unique_name("role-no-lambda-trust-")
    # Trust policy only allows s3.amazonaws.com -- NOT lambda.amazonaws.com.
    bad_role = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("s3.amazonaws.com")),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    bad_role_arn = bad_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))

    # Make sure the role itself is visible before attempting, so the rejection we observe
    # is attributable to the trust mismatch and not to role-creation propagation delay.
    _poll_until(
        lambda: _role_exists(iam, bad_role_name),
        lambda ok: ok,
        timeout_s=30,
        interval_s=1,
        description=f"role {bad_role_name!r} becoming visible",
    )

    bad_fn_name = ctx.unique_name("fn-bad-trust-")
    ctx.on_cleanup(lambda: _delete_function_if_exists(lam, bad_fn_name))
    code, message = _error(
        lambda: lam.create_function(
            FunctionName=bad_fn_name,
            Runtime="python3.12",
            Role=bad_role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected Lambda to reject a role that does not trust lambda.amazonaws.com, got {code!r}"
    )
    assert message == "The role defined for the function cannot be assumed by Lambda.", (
        f"expected Lambda's trust-rejection message, got {message!r}"
    )

    # Effect absent: the rejected call must not have left a function behind.
    absent_code, absent_message = _error(lambda: lam.get_function(FunctionName=bad_fn_name))
    assert absent_code == "ResourceNotFoundException", (
        f"a rejected CreateFunction still left a function behind, GetFunction returned {absent_code!r}"
    )
    expected_not_found = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn_name}"
    )
    assert absent_message == expected_not_found, (
        f"expected GetFunction's not-found message {expected_not_found!r}, got {absent_message!r}"
    )

    # Positive control: the identical call shape succeeds once the role trusts
    # lambda.amazonaws.com, so the rejection above is attributable to the trust
    # mismatch and not to anything else about the request.
    good_role_name = ctx.unique_name("role-lambda-trust-")
    good_role = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("lambda.amazonaws.com")),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    good_role_arn = good_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))

    good_fn_name = ctx.unique_name("fn-good-trust-")
    _create_function_with_retry(
        lam,
        FunctionName=good_fn_name,
        Runtime="python3.12",
        Role=good_role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_fn_name))

    got = lam.get_function(FunctionName=good_fn_name)
    assert got["Configuration"]["FunctionName"] == good_fn_name, (
        f"the correctly-trusted role's function is not visible via GetFunction: {got!r}"
    )


def _zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _trust_policy(principal_service: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": principal_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _role_exists(iam, role_name: str) -> bool:
    try:
        iam.get_role(RoleName=role_name)
        return True
    except ClientError:
        return False


def _delete_function_if_exists(lam, function_name: str) -> None:
    try:
        lam.delete_function(FunctionName=function_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _create_function_with_retry(lam, *, timeout_s: float = 90.0, interval_s: float = 3.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None, "loop exited without ever calling create_function"
    raise last_exc


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
