"""create-function-without-a-kms-key-uses-the-account-managed-key."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-function-without-a-kms-key-uses-the-account-managed-key"
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
    name = ctx.unique_name("sim2real-behav-kmsdefault-role-")
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A function created with environment variables but no KMSKeyArn reports no customer key,
    and the account's AWS managed key alias/aws/lambda -- which the check never creates -- is
    the key AWS used in its place.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html
    """
    lam = ctx.client("lambda")
    kms = ctx.client("kms")
    role_arn = _make_role(ctx)
    code = {"ZipFile": _zip_bytes()}

    default_name = ctx.unique_name("sim2real-behav-kmsdefault-fn-")
    _create_function_with_retry(
        lam, FunctionName=default_name, Runtime="python3.13", Role=role_arn,
        Handler="index.handler", Code=code,
        Environment={"Variables": {"PROBE": "1"}},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=default_name))
    default_config = _wait_active(lam, default_name)
    assert "KMSKeyArn" not in default_config, (
        "expected no customer KMSKeyArn on a function created without one, got "
        f"{default_config.get('KMSKeyArn')!r}"
    )

    # Independent read, a different service entirely: the account's AWS managed key for Lambda
    # already exists -- the check never calls kms:CreateKey or kms:CreateAlias for it.
    managed_key = kms.describe_key(KeyId="alias/aws/lambda")["KeyMetadata"]
    assert managed_key["KeyManager"] == "AWS", (
        f"expected alias/aws/lambda to be an AWS managed key, got {managed_key['KeyManager']!r}"
    )
    assert managed_key["Enabled"] is True, (
        f"expected alias/aws/lambda to be enabled, got {managed_key['Enabled']!r}"
    )

    # Positive control: a function that DOES specify a customer managed key reports that exact
    # key, so the absence above is a real representation difference, not a field that is never set.
    cmk = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsdefault-cmk-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    cmk_id, cmk_arn = cmk["KeyId"], cmk["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=cmk_id, PendingWindowInDays=7))

    cmk_name = ctx.unique_name("sim2real-behav-kmscustom-fn-")
    _create_function_with_retry(
        lam, FunctionName=cmk_name, Runtime="python3.13", Role=role_arn,
        Handler="index.handler", Code=code,
        Environment={"Variables": {"PROBE": "1"}}, KMSKeyArn=cmk_arn,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_function(lam, cmk_name))
    cmk_config = _wait_active(lam, cmk_name)
    assert cmk_config.get("KMSKeyArn") == cmk_arn, (
        f"expected KMSKeyArn {cmk_arn!r} on the function that specified it, got "
        f"{cmk_config.get('KMSKeyArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
