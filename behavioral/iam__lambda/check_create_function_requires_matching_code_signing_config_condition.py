"""create-function-requires-matching-code-signing-config-condition."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-function-requires-matching-code-signing-config-condition"
GROUP = "condition-keys"
SERVICES = ["iam", "lambda"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(ctx, probe, done, *, timeout_s, interval_s=2.0, what):
    """``probe()`` until ``done(result)``; raises TimeoutError at the capped deadline."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s:.0f}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role whose policy allows lambda:CreateFunction only when lambda:CodeSigningConfigArn
    equals a specific config is allowed when the request names that exact config, and, once that
    allow is in effect, denied CreateFunction naming no config.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/config-codesigning-policies.html
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    signer = ctx.client("signer")

    exec_role_name = ctx.unique_name("sim2real-condkey-exec-")
    exec_role_arn = iam.create_role(
        RoleName=exec_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=exec_role_name), "NoSuchEntity"))
    basic_exec_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=exec_role_name, PolicyArn=basic_exec_policy)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=exec_role_name, PolicyArn=basic_exec_policy),
        "NoSuchEntity"))

    profile_name = ctx.unique_name("sim2real_condkey_sp_").replace("-", "_")
    profile = signer.put_signing_profile(profileName=profile_name, platformId="AWSLambda-SHA384-ECDSA",
                                          tags={"sim2real": CHECK})
    ctx.on_cleanup(_teardown(lambda: signer.cancel_signing_profile(profileName=profile_name),
                             "ResourceNotFoundException"))
    csc_arn = lam.create_code_signing_config(
        AllowedPublishers={"SigningProfileVersionArns": [profile["profileVersionArn"]]},
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        Tags={"sim2real": CHECK},
    )["CodeSigningConfig"]["CodeSigningConfigArn"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn),
                             "ResourceNotFoundException", "CodeSigningConfigNotFoundException"))

    whoami = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" in whoami:
        trust_principal = f"arn:aws:iam::{ctx.account}:role/{whoami.split(':assumed-role/')[1].split('/')[0]}"
    else:
        trust_principal = whoami

    caller_role_name = ctx.unique_name("sim2real-condkey-caller-")
    caller_role_arn = iam.create_role(
        RoleName=caller_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": trust_principal},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=caller_role_name), "NoSuchEntity"))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": exec_role_arn},
            {"Effect": "Allow", "Action": "lambda:GetCodeSigningConfig", "Resource": csc_arn},
            {"Effect": "Allow", "Action": "lambda:TagResource", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": "lambda:CreateFunction",
                "Resource": "*",
                "Condition": {"StringEquals": {"lambda:CodeSigningConfigArn": csc_arn}},
            },
        ],
    }
    iam.put_role_policy(RoleName=caller_role_name, PolicyName="sim2real-condition",
                        PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=caller_role_name, PolicyName="sim2real-condition"),
        "NoSuchEntity"))

    def assumed_lambda_client():
        creds = sts.assume_role(RoleArn=caller_role_arn, RoleSessionName="probe")["Credentials"]
        return ctx.client("lambda", creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        })

    zip_code = {"ZipFile": _zip("def handler(e,c): return 1")}

    # The allowed create runs first and is polled through the caller role's propagation, so the
    # denial below is asserted only once the inline allow is known to be in effect.
    allowed_name = ctx.unique_name("sim2real-condkey-fn-allowed-")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=allowed_name),
                             "ResourceNotFoundException"))
    ctx.on_cleanup(lambda: _delete_log_group(ctx, allowed_name))

    session: dict = {}

    def _try_allowed():
        try:
            session["lambda"] = assumed_lambda_client()
            return session["lambda"].create_function(
                FunctionName=allowed_name, Runtime="python3.12", Handler="index.handler",
                Role=exec_role_arn, Code=zip_code, CodeSigningConfigArn=csc_arn,
                Tags={"sim2real": CHECK})
        except ClientError as exc:
            if exc.response["Error"]["Code"] in (
                "AccessDenied", "AccessDeniedException", "InvalidParameterValueException",
                "UnrecognizedClientException",
            ):
                return None
            raise

    created = _poll(ctx, _try_allowed, lambda r: r is not None, timeout_s=90,
                    what="CreateFunction with the matching CodeSigningConfigArn is allowed")
    assert created["FunctionName"] == allowed_name, (
        f"CreateFunction with the matching condition value returned {created!r}")

    denied_name = ctx.unique_name("sim2real-condkey-fn-denied-")
    expected_denied_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{denied_name}"
    expected_caller_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{caller_role_name}/probe"
    # Registered before the call, so a target that wrongly accepts it still tears it down.
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=denied_name),
                             "ResourceNotFoundException"))
    ctx.on_cleanup(lambda: _delete_log_group(ctx, denied_name))
    # The same session the allowed create succeeded with, so only the condition differs.
    try:
        session["lambda"].create_function(
            FunctionName=denied_name, Runtime="python3.12", Handler="index.handler",
            Role=exec_role_arn, Code=zip_code, Tags={"sim2real": CHECK})
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    else:
        raise AssertionError(
            "CreateFunction with no CodeSigningConfigArn was expected to be refused but it "
            "SUCCEEDED")
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message}"
    assert message == (
        f"User: {expected_caller_arn} is not authorized to perform: lambda:CreateFunction on "
        f"resource: {expected_denied_arn} because no identity-based policy allows the "
        "lambda:CreateFunction action"
    ), f"unexpected AccessDenied message: {message!r}"


def _delete_log_group(ctx, function_name):
    """The log group a successful CreateFunction may not have created yet; absence is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
