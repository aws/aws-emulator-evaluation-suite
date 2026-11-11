"""rotate-secret-lambda-without-invoke-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rotate-secret-lambda-without-invoke-permission-denied"
GROUP = "error-semantics"
SERVICES = ["secretsmanager"]

_CANNOT_INVOKE_MESSAGE = (
    "Secrets Manager cannot invoke the specified Lambda function. Ensure that the function policy "
    "grants access to the principal secretsmanager.amazonaws.com."
)

_ROTATION_HANDLER_SRC = """import boto3


def handler(event, context):
    client = boto3.client("secretsmanager")
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            new_password = client.get_random_password(PasswordLength=32)["RandomPassword"]
            client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=new_password,
                VersionStages=["AWSPENDING"],
            )
    elif step in ("setSecret", "testSecret"):
        pass
    elif step == "finishSecret":
        metadata = client.describe_secret(SecretId=arn)
        current_version = None
        for version, stages in metadata["VersionIdsToStages"].items():
            if "AWSCURRENT" in stages:
                if version == token:
                    return
                current_version = version
                break
        client.update_secret_version_stage(
            SecretId=arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=current_version,
        )
"""


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RotateSecret with a real Lambda lacking an invoke grant for secretsmanager.amazonaws.com is
    AccessDeniedException (distinct from a malformed ARN's InvalidRequestException) and creates no
    version; after granting the permission the identical call starts a rotation."""
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    secret_name = ctx.unique_name("sim2real-behav-rotdenied-")
    secret = sm.create_secret(
        Name=secret_name,
        SecretString="initial-value",
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    func_name, func_arn = _create_rotation_lambda(ctx, iam, lam, secret_arn)

    malformed_arn = "not-a-lambda-arn-at-all"
    code_malformed, message_malformed = _error_code(
        lambda: sm.rotate_secret(SecretId=secret_arn, RotationLambdaARN=malformed_arn)
    )
    assert code_malformed == "InvalidRequestException", (
        f"malformed RotationLambdaARN must be rejected with InvalidRequestException, got {code_malformed!r}"
    )
    expected_malformed = (
        "Invalid rotation Lambda ARN. Ensure the ARN matches format "
        f"arn:aws:lambda:{ctx.region}:<account>:function:<functionName>."
    )
    assert message_malformed == expected_malformed, f"unexpected malformed-ARN message: {message_malformed!r}"

    before_versions = sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]
    code_denied, message_denied = _error_code(
        lambda: sm.rotate_secret(SecretId=secret_arn, RotationLambdaARN=func_arn)
    )
    assert code_denied == "AccessDeniedException", f"expected AccessDeniedException, got {code_denied}"
    assert message_denied == _CANNOT_INVOKE_MESSAGE, f"unexpected missing-permission message: {message_denied!r}"
    assert code_denied != code_malformed, (
        f"missing-permission ({code_denied}) and malformed-ARN ({code_malformed}) "
        "rejections must be distinct error codes"
    )

    after_versions = sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]
    assert len(after_versions) == len(before_versions), "denied RotateSecret must not create a new version"

    # Only the start of rotation is asserted; it is cancelled afterwards rather than awaited.
    lam.add_permission(
        FunctionName=func_name,
        StatementId="AllowSecretsManagerInvoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceAccount=account_id,
    )
    _wait_for_lambda_permission(lam, func_name)

    # GetPolicy visibility can precede enforcement; the retry absorbs that lag.
    _rotate_with_retry(sm, secret_arn, func_arn, timeout_s=90.0)

    # The new pending version can appear a couple of seconds after RotateSecret returns.
    deadline = time.monotonic() + 30.0
    versions_after_grant = after_versions
    while True:
        if len(versions_after_grant) > len(after_versions) or time.monotonic() > deadline:
            break
        time.sleep(2)
        versions_after_grant = sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]
    assert len(versions_after_grant) > len(after_versions), (
        "accepted RotateSecret must create a new pending version; "
        f"before={len(after_versions)} after={len(versions_after_grant)}"
    )

    try:
        sm.cancel_rotate_secret(SecretId=secret_arn)
    except ClientError:
        pass  # best-effort: rotation may already have progressed past a cancellable point


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _make_zip_bytes(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_rotation_lambda(ctx, iam, lam, secret_arn: str):
    role_name = ctx.unique_name("sim2real-behav-rotrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_policy_name = "sim2real-behav-rotpolicy"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:UpdateSecretVersionStage",
                ],
                "Resource": secret_arn,
            },
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetRandomPassword"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))

    func_name = ctx.unique_name("sim2real-behav-rotfn-")
    code_zip = _make_zip_bytes(_ROTATION_HANDLER_SRC)
    deadline = time.monotonic() + 60
    func_arn = None
    while True:
        try:
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code_zip},
                Timeout=30,
                Tags={"sim2real": "behavioral-check"},
            )
            func_arn = resp["FunctionArn"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    return func_name, func_arn


def _wait_for_lambda_permission(lam, func_name: str, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            lam.get_policy(FunctionName=func_name)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(2)
    raise AssertionError("lambda resource policy never became visible")


def _rotate_with_retry(sm, secret_arn: str, func_arn: str, rotation_rules=None, timeout_s: float = 60.0):
    """RotateSecret test-invokes the Lambda; while a fresh role or invoke grant propagates that
    surfaces as a transient ValidationException, which is retried until the deadline."""
    kwargs = {"SecretId": secret_arn, "RotationLambdaARN": func_arn}
    if rotation_rules is not None:
        kwargs["RotationRules"] = rotation_rules
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.rotate_secret(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "Lambda validation failed" in message and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
