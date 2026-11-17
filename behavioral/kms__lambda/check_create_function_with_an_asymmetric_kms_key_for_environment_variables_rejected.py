"""create-function-with-an-asymmetric-kms-key-for-environment-variables-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-function-with-an-asymmetric-kms-key-for-environment-variables-rejected"
GROUP = "encryption"
SERVICES = ["kms", "lambda"]

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

_HANDLER_PY = "def handler(event, context):\n    return {\"ok\": True}\n"


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _HANDLER_PY)
    return buf.getvalue()


def _make_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-kmsasym-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_POLICY))
    return arn


def _create_function_with_retry(lam, **params):
    """A just-created role is not immediately assumable; retry CreateFunction, its first use."""
    deadline = time.monotonic() + 60
    while True:
        try:
            return lam.create_function(**params)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _delete_function(lam, name: str, timeout_s: float = 60.0) -> None:
    lam.delete_function(FunctionName=name)
    # The function's environment key stays in use until Lambda finishes the delete.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lam.get_function(FunctionName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{name} still exists {timeout_s:g} s after DeleteFunction")
        time.sleep(2.0)


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Active":
            return last
        if last["State"] == "Failed":
            raise AssertionError(f"{name} failed to activate: {last.get('StateReason')!r}")
        time.sleep(2.0)
    raise AssertionError(
        f"{name} did not reach Active within {timeout_s}s "
        f"(last state {last['State'] if last else None!r})"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction accepts a symmetric customer managed key for encrypting environment
    variables, but refuses an asymmetric KMS key, creating nothing.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html
    """
    lam = ctx.client("lambda")
    kms = ctx.client("kms")
    role_arn = _make_role(ctx)
    code = {"ZipFile": _zip_bytes()}

    # Positive control: a symmetric customer managed key works for environment-variable encryption.
    symmetric_key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsasym-symkey-"),
        KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    symmetric_id, symmetric_arn = symmetric_key["KeyId"], symmetric_key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=symmetric_id, PendingWindowInDays=7))

    good_name = ctx.unique_name("sim2real-behav-kmsasym-good-fn-")
    _create_function_with_retry(
        lam, FunctionName=good_name, Runtime="python3.13", Role=role_arn,
        Handler="index.handler", Code=code,
        Environment={"Variables": {"PROBE": "1"}}, KMSKeyArn=symmetric_arn,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_function(lam, good_name))
    good_config = _wait_active(lam, good_name)
    assert good_config.get("KMSKeyArn") == symmetric_arn, (
        f"expected the symmetric key to be accepted, got KMSKeyArn {good_config.get('KMSKeyArn')!r}"
    )

    # Break exactly one thing: an asymmetric key cannot encrypt environment variables.
    asymmetric_key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsasym-asymkey-"),
        KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    asymmetric_id, asymmetric_arn = asymmetric_key["KeyId"], asymmetric_key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=asymmetric_id, PendingWindowInDays=7))

    bad_name = ctx.unique_name("sim2real-behav-kmsasym-bad-fn-")
    code_, message = _error(lambda: _create_function_with_retry(
        lam, FunctionName=bad_name, Runtime="python3.13", Role=role_arn,
        Handler="index.handler", Code=code,
        Environment={"Variables": {"PROBE": "1"}}, KMSKeyArn=asymmetric_arn,
        Tags={"sim2real": CHECK},
    ))
    assert code_ == "ServiceException", (
        f"expected ServiceException for an asymmetric KMS key, got {code_}: {message!r}"
    )
    assert message == (
        "Lambda was unable to encrypt your environment variables. Please try again."
    ), f"unexpected message {message!r}"

    # Effect absent: the rejected create made nothing.
    code_, message = _error(lambda: lam.get_function(FunctionName=bad_name))
    assert code_ == "ResourceNotFoundException", (
        f"expected the rejected function to not exist, got {code_}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
