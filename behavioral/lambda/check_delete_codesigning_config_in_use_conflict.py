"""delete-codesigning-config-in-use-conflict."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-codesigning-config-in-use-conflict"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a code signing config still attached to a function is rejected with
    ResourceConflictException; the same delete succeeds on an unattached config and on this
    config once it is detached."""
    signer = ctx.client("signer")
    lam = ctx.client("lambda")

    profile = _put_signing_profile(ctx, signer)

    # ---- positive control: DeleteCodeSigningConfig succeeds when nothing is attached ----
    control_arn = _create_csc(lam, profile["profileVersionArn"])
    lam.delete_code_signing_config(CodeSigningConfigArn=control_arn)
    control_gone = _client_error(lambda: lam.get_code_signing_config(CodeSigningConfigArn=control_arn))
    assert control_gone.get("Code") == "ResourceNotFoundException", (
        f"control config did not actually delete: get_code_signing_config returned {control_gone!r}"
    )
    control_msg = f"The Lambda code signing configuration {control_arn} can not be found."
    assert control_gone.get("Message") == control_msg, (
        f"expected the not-found message {control_msg!r}, got {control_gone.get('Message')!r}"
    )

    fn = _create_function(ctx)
    csc_arn = _create_csc(lam, profile["profileVersionArn"])
    lam.put_function_code_signing_config(CodeSigningConfigArn=csc_arn, FunctionName=fn["name"])
    attached = lam.get_function_code_signing_config(FunctionName=fn["name"])
    assert attached["CodeSigningConfigArn"] == csc_arn, (
        f"config did not attach to the function: {attached!r}"
    )

    def _detach_and_delete():
        try:
            lam.delete_function_code_signing_config(FunctionName=fn["name"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "CodeSigningConfigNotFoundException",
                "ResourceNotFoundException",
            ):
                raise
        try:
            lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "CodeSigningConfigNotFoundException",
                "ResourceNotFoundException",
            ):
                raise

    ctx.on_cleanup(_detach_and_delete)

    # ---- break: the config is still attached, so delete is rejected ----
    rejected = _client_error(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn))
    assert rejected.get("Code") == "ResourceConflictException", (
        f"expected ResourceConflictException, got {rejected!r}"
    )
    conflict_msg = (
        "Lambda cannot delete the code signing configuration at this time \u2014 "
        "another operation is in progress. Try again later."
    )
    assert rejected.get("Message") == conflict_msg, (
        f"expected the in-use message {conflict_msg!r}, got {rejected.get('Message')!r}"
    )

    # ---- the effect is absent: the config still exists and is still attached ----
    still_attached = lam.get_function_code_signing_config(FunctionName=fn["name"])
    assert still_attached["CodeSigningConfigArn"] == csc_arn, (
        f"function no longer reports the config despite the delete having been rejected: {still_attached!r}"
    )

    # ---- restore: detach, then the IDENTICAL delete call now succeeds ----
    lam.delete_function_code_signing_config(FunctionName=fn["name"])
    lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn)

    # ---- gone: an independent read confirms it ----
    gone = _client_error(lambda: lam.get_code_signing_config(CodeSigningConfigArn=csc_arn))
    assert gone.get("Code") == "ResourceNotFoundException", (
        f"expected the deleted config to read back ResourceNotFoundException, got {gone!r}"
    )
    gone_msg = f"The Lambda code signing configuration {csc_arn} can not be found."
    assert gone.get("Message") == gone_msg, (
        f"expected the not-found message {gone_msg!r}, got {gone.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_csc(lam, profile_version_arn: str) -> str:
    resp = lam.create_code_signing_config(
        AllowedPublishers={"SigningProfileVersionArns": [profile_version_arn]},
        Tags={"sim2real:managed": "true"},
    )
    return resp["CodeSigningConfig"]["CodeSigningConfigArn"]


def _minimal_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _put_signing_profile(ctx, signer):
    name = ctx.unique_name("sim2realbehavsp").replace("-", "")[:64]
    resp = signer.put_signing_profile(
        profileName=name,
        platformId="AWSLambda-SHA384-ECDSA",
        tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=name))
    return {"profileName": name, "profileVersionArn": resp["profileVersionArn"]}


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
