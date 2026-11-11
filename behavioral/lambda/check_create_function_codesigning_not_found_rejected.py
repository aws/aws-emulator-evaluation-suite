"""create-function-codesigning-not-found-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-function-codesigning-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction with a real CodeSigningConfigArn succeeds and reports it, while a well-formed
    nonexistent one is CodeSigningConfigNotFoundException with the exact message and creates no
    function."""
    lam = ctx.client("lambda")
    account_id = ctx.account

    role_arn = _create_lambda_role(ctx)

    # ---- positive control: a REAL CodeSigningConfigArn is accepted ----
    real_csc_arn = _create_code_signing_config(ctx)
    good_name = ctx.unique_name("sim2real-behav-fn-")
    resp, error_code, _ = _create_function(ctx, lam, good_name, role_arn, real_csc_arn)
    assert error_code is None, (
        f"expected CreateFunction with a real CodeSigningConfigArn to succeed, got {error_code!r}"
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_name))
    fetched = lam.get_function_code_signing_config(FunctionName=good_name)
    assert fetched["CodeSigningConfigArn"] == real_csc_arn, (
        f"expected {real_csc_arn!r} attached, got {fetched.get('CodeSigningConfigArn')!r}"
    )

    # ---- break exactly one thing: the identical call, a bogus (nonexistent) csc arn ----
    bogus_csc_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:code-signing-config:csc-{'0' * 17}"
    bad_name = ctx.unique_name("sim2real-behav-fn-")
    resp, error_code, error_message = _create_function(ctx, lam, bad_name, role_arn, bogus_csc_arn)
    if resp is not None:
        # Should not happen -- but clean up if it somehow succeeded.
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=bad_name))
    assert error_code == "CodeSigningConfigNotFoundException", (
        f"expected CodeSigningConfigNotFoundException, got {error_code!r}"
    )
    expected = (
        "The code signing configuration cannot be found. Check that the provided configuration "
        f"is not deleted: {bogus_csc_arn}."
    )
    assert error_message == expected, (
        f"a nonexistent CodeSigningConfigArn returned message {error_message!r}, expected {expected!r}"
    )

    # nothing should have been created under this name
    try:
        lam.get_function(FunctionName=bad_name)
        raise AssertionError("function was unexpectedly created despite the rejected create call")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException, got {e.response['Error']['Code']!r}"
        )
        not_found = f"Function not found: arn:aws:lambda:{ctx.region}:{account_id}:function:{bad_name}"
        assert e.response["Error"]["Message"] == not_found, (
            f"GetFunction after the rejected create returned message "
            f"{e.response['Error']['Message']!r}, expected {not_found!r}"
        )


def _minimal_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_function(ctx, lam, name, role_arn, csc_arn):
    """CreateFunction, retrying only while the role has not finished propagating.

    Returns (response, error_code, error_message): on success both error fields are None; on a
    genuine rejection ``response`` is None and the error fields carry AWS's code and message.
    """
    for _ in range(10):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _minimal_zip_bytes()},
                Timeout=10,
                CodeSigningConfigArn=csc_arn,
            )
            return resp, None, None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and "cannot be assumed" in str(e):
                time.sleep(3)
                continue
            return None, code, e.response["Error"].get("Message")
    raise AssertionError(f"create_function for {name!r} never resolved (role propagation timeout)")


def _create_code_signing_config(ctx) -> str:
    """A real CodeSigningConfig, backed by a real Signer profile, for the positive control."""
    lam = ctx.client("lambda")
    signer = ctx.client("signer")
    profile_name = ctx.unique_name("sim2real_behav_csp_")
    profile = signer.put_signing_profile(profileName=profile_name, platformId="AWSLambda-SHA384-ECDSA")
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=profile_name))
    profile_version_arn = profile["profileVersionArn"]

    csc = lam.create_code_signing_config(
        Description="sim2real-behav positive control",
        AllowedPublishers={"SigningProfileVersionArns": [profile_version_arn]},
    )["CodeSigningConfig"]
    csc_arn = csc["CodeSigningConfigArn"]
    ctx.on_cleanup(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn))
    return csc_arn


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
