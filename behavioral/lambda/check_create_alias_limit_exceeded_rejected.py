"""create-alias-limit-exceeded-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-alias-limit-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After several distinct aliases succeed, CreateAlias with a taken Name is ResourceConflictException
    with the exact message and leaves the original alias unchanged; after DeleteAlias the same
    CreateAlias succeeds and reads back."""
    lam = ctx.client("lambda")
    fn = _create_function(ctx)
    version = lam.publish_version(FunctionName=fn["name"])["Version"]

    dup_name = "sim2real-dup-alias"
    created = 0
    throttle_retries = 0

    def _create_with_retry(name, function_version):
        nonlocal throttle_retries
        while True:
            try:
                resp = lam.create_alias(
                    FunctionName=fn["name"], Name=name, FunctionVersion=function_version
                )
                throttle_retries = 0
                return resp
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("TooManyRequestsException", "ServiceException") and throttle_retries < 8:
                    throttle_retries += 1
                    time.sleep(min(2 ** throttle_retries, 20))
                    continue
                raise

    # a handful of distinct aliases pointing at the same version all succeed
    for i in range(5):
        _create_with_retry(f"sim2real-alias-{i}", version)
        created += 1
    original = _create_with_retry(dup_name, version)

    # a second publish so the duplicate-create attempt targets a *different* version,
    # proving the rejection is keyed on the Name colliding, not on the version matching
    second_version = lam.publish_version(FunctionName=fn["name"])["Version"]
    error_code, error_message = _client_error(
        lambda: lam.create_alias(FunctionName=fn["name"], Name=dup_name, FunctionVersion=second_version)
    )

    assert error_code == "ResourceConflictException", (
        f"expected ResourceConflictException for a duplicate alias name, got {error_code!r}"
    )
    expected_message = f"Alias already exists: {fn['arn']}:{dup_name}"
    assert error_message == expected_message, (
        f"expected message {expected_message!r} for a duplicate alias name, got {error_message!r}"
    )
    assert created >= 5, f"expected the distinct aliases to succeed first, got {created}"

    # the original alias must be untouched by the rejected duplicate attempt
    still_there = lam.get_alias(FunctionName=fn["name"], Name=dup_name)
    assert still_there["FunctionVersion"] == version, (
        f"the pre-existing alias's target version changed after a rejected duplicate create: "
        f"expected {version!r}, got {still_there['FunctionVersion']!r}"
    )
    assert still_there["AliasArn"] == original["AliasArn"], (
        f"the pre-existing alias's ARN changed after a rejected duplicate create: "
        f"expected {original['AliasArn']!r}, got {still_there['AliasArn']!r}"
    )

    # restore: remove the alias that caused the collision, then the identical Name/version
    # combination that was just rejected must now succeed -- proving the rejection was keyed
    # on the live collision, not a permanent inability to create this alias
    lam.delete_alias(FunctionName=fn["name"], Name=dup_name)
    restored = lam.create_alias(FunctionName=fn["name"], Name=dup_name, FunctionVersion=second_version)
    assert restored["FunctionVersion"] == second_version, (
        f"expected the restored alias to target {second_version!r}, got {restored['FunctionVersion']!r}"
    )

    reread = lam.get_alias(FunctionName=fn["name"], Name=dup_name)
    assert reread["FunctionVersion"] == second_version, (
        f"expected the restored alias to read back as {second_version!r}, got {reread['FunctionVersion']!r}"
    )
    assert reread["AliasArn"] == restored["AliasArn"], (
        f"expected the restored alias's ARN to match its own create response: "
        f"expected {restored['AliasArn']!r}, got {reread['AliasArn']!r}"
    )


def _client_error(call):
    """Run a call that MUST be refused and return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = call()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _minimal_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_lambda_role(ctx):
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
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_active(lam, name):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError("function did not become Active in time")


def _create_function(ctx, **overrides):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    role_arn = _create_lambda_role(ctx)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _minimal_zip_bytes()},
        Timeout=10,
        Tags={"sim2real:managed": "true"},
    )
    kwargs.update(overrides)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            resp = lam.create_function(**kwargs)
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and "cannot be assumed" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(lam, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
