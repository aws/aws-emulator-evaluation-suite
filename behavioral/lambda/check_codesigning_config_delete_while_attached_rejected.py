"""codesigning-config-delete-while-attached-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "codesigning-config-delete-while-attached-rejected"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a code signing config still attached to a function is rejected with ResourceConflictException."""
    lam = ctx.client("lambda")
    fn = _create_basic_function(ctx)
    profile_arn = _signing_profile_version_arn(ctx)

    csc = lam.create_code_signing_config(
        AllowedPublishers={"SigningProfileVersionArns": [profile_arn]},
    )["CodeSigningConfig"]
    csc_arn = csc["CodeSigningConfigArn"]
    ctx.on_cleanup(lambda: _delete_csc_ignore(lam, csc_arn))

    lam.put_function_code_signing_config(CodeSigningConfigArn=csc_arn, FunctionName=fn["name"])
    ctx.on_cleanup(lambda: _detach_csc_ignore(lam, fn["name"]))

    code, message = _client_error(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn))
    assert code == "ResourceConflictException", f"expected ResourceConflictException, got {code}"
    expected = (
        "Lambda cannot delete the code signing configuration at this time — another operation is "
        "in progress. Try again later."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # independent reads: the rejected delete left the config intact and still attached
    still_there = lam.get_code_signing_config(CodeSigningConfigArn=csc_arn)["CodeSigningConfig"]
    assert still_there["CodeSigningConfigArn"] == csc_arn, (
        f"expected code signing config to still exist after rejected delete, got {still_there!r}"
    )
    still_attached = lam.get_function_code_signing_config(FunctionName=fn["name"])
    assert still_attached["CodeSigningConfigArn"] == csc_arn, (
        f"expected function to still report the CSC as attached after rejected delete, got {still_attached!r}"
    )

    # detach, then confirm delete now succeeds (proves the rejection was state-specific)
    lam.delete_function_code_signing_config(FunctionName=fn["name"])
    lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn)

    # the now-successful delete must also prove gone, via an independent read
    gone_code, gone_message = _client_error(lambda: lam.get_code_signing_config(CodeSigningConfigArn=csc_arn))
    assert gone_code == "ResourceNotFoundException", f"expected CSC gone, got {gone_code}"
    assert gone_message == _csc_not_found_message(csc_arn), (
        f"expected message {_csc_not_found_message(csc_arn)!r}, got {gone_message!r}"
    )


def _client_error(call):
    """Run a call that MUST be refused and return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = call()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _csc_not_found_message(csc_arn: str) -> str:
    return f"The Lambda code signing configuration {csc_arn} can not be found."


def _signing_profile_version_arn(ctx) -> str:
    """Create this check's own Signer profile (cancelled at cleanup) and return its version ARN."""
    import uuid

    signer = ctx.client("signer")
    name = "sim2realbehav" + uuid.uuid4().hex[:16]
    prof = signer.put_signing_profile(
        profileName=name,
        platformId="AWSLambda-SHA384-ECDSA",
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=name))
    return prof["profileVersionArn"]


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_basic_function(ctx) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                Timeout=10,
                MemorySize=128,
                Publish=False,
            )
            break
        except Exception as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValueException" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError("create_function never succeeded (role propagation timeout)")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _wait_function_active(ctx, name: str) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return cfg
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function did not become Active in time (last={cfg!r})")


def _delete_csc_ignore(lam, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_code_signing_config(CodeSigningConfigArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "CodeSigningConfigNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _detach_csc_ignore(lam, function_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_function_code_signing_config(FunctionName=function_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "CodeSigningConfigNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
