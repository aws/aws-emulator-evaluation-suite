"""rotate-secret-lambda-invoke-permission-missing-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rotate-secret-lambda-invoke-permission-missing-denied"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]

_CANNOT_INVOKE_MESSAGE = (
    "Secrets Manager cannot invoke the specified Lambda function. Ensure that the function policy "
    "grants access to the principal secretsmanager.amazonaws.com."
)

# Minimal AWS-style single-value rotation function implementing the four standard steps.
_ROTATION_LAMBDA_SOURCE = """
import boto3


def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    client = boto3.client("secretsmanager")

    if step == "createSecret":
        current = client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=current["SecretString"] + "-rotated",
                VersionStages=["AWSPENDING"],
            )
    elif step == "setSecret":
        pass
    elif step == "testSecret":
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """RotateSecret fails up front with AccessDeniedException when the Lambda's resource policy does
    not let secretsmanager.amazonaws.com invoke it, leaving the secret unchanged; after granting
    the permission, rotation of an equivalent secret completes end to end."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-rotrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_exec_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_policy_arn))

    inline_policy_name = "secrets-rotation-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "secretsmanager:GetSecretValue",
                            "secretsmanager:PutSecretValue",
                            "secretsmanager:UpdateSecretVersionStage",
                            "secretsmanager:DescribeSecret",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _ROTATION_LAMBDA_SOURCE)
    zip_bytes = zip_buf.getvalue()

    function_name = ctx.unique_name("sim2real-behav-rotfn-")
    ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
    function_arn = _create_function_with_retry(lam, function_name, role_arn, zip_bytes, tag_value=CHECK)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _wait_for_function_active(lam, function_name)

    name_a = ctx.unique_name("sim2real-behav-rotsecretA-")
    secret_a = sm.create_secret(
        Name=name_a,
        SecretString="original-value-a",
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    arn_a = secret_a["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn_a, ForceDeleteWithoutRecovery=True))
    original_version_a = secret_a["VersionId"]

    code, message = _error_code_or_raise(
        lambda: sm.rotate_secret(SecretId=arn_a, RotationLambdaARN=function_arn)
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == _CANNOT_INVOKE_MESSAGE, f"unexpected refusal message: {message!r}"

    described_a = sm.describe_secret(SecretId=arn_a)
    current_version_a = next(
        version for version, stages in described_a["VersionIdsToStages"].items() if "AWSCURRENT" in stages
    )
    assert current_version_a == original_version_a, (
        f"AWSCURRENT moved to {current_version_a} despite the denied rotation; expected it to "
        f"stay {original_version_a}"
    )
    value_a = sm.get_secret_value(SecretId=arn_a)["SecretString"]
    assert value_a == "original-value-a", f"expected untouched original-value-a, got {value_a!r}"
    assert not described_a.get(
        "RotationEnabled"
    ), f"expected no rotation schedule after a denied RotateSecret, got RotationEnabled={described_a.get('RotationEnabled')!r}"

    lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowSecretsManagerInvoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceAccount=account_id,
    )

    name_b = ctx.unique_name("sim2real-behav-rotsecretB-")
    secret_b = sm.create_secret(
        Name=name_b,
        SecretString="original-value-b",
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    arn_b = secret_b["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn_b, ForceDeleteWithoutRecovery=True))
    original_version_b = secret_b["VersionId"]

    _rotate_with_retry_on_access_denied(sm, arn_b, function_arn)

    def _current_version_b() -> str:
        described_b = sm.describe_secret(SecretId=arn_b)
        return next(
            version for version, stages in described_b["VersionIdsToStages"].items() if "AWSCURRENT" in stages
        )

    deadline = time.monotonic() + 90.0
    rotated = False
    while time.monotonic() < deadline:
        if _current_version_b() != original_version_b:
            rotated = True
            break
        time.sleep(3.0)
    assert rotated, "rotation never completed on secret B even after granting Lambda invoke permission"
    value_b = sm.get_secret_value(SecretId=arn_b)["SecretString"]
    assert value_b == "original-value-b-rotated", f"expected rotated value, got {value_b!r}"


def _error_code_or_raise(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be denied, but it SUCCEEDED and returned {result!r}")


def _create_function_with_retry(lam, function_name, role_arn, zip_bytes, timeout_s=60.0, tag_value=None):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Publish=False,
                Tags={"sim2real-behav-check": tag_value} if tag_value else {},
            )
            return resp["FunctionArn"]
        except ClientError as err:
            last_err = err
            # IAM role propagation lag: Lambda can't yet assume the freshly created role.
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"could not create rotation lambda in time: {last_err}")


def _wait_for_function_active(lam, function_name, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        last_state = cfg.get("State")
        if last_state == "Active":
            return
        time.sleep(2.0)
    raise AssertionError(f"lambda function never became Active in time (last state={last_state})")


def _rotate_with_retry_on_access_denied(sm, secret_arn, function_arn, timeout_s=60.0):
    """IAM/Lambda resource-policy grants can take a few seconds to propagate; retry the
    RotateSecret call on AccessDeniedException until it either succeeds or times out."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sm.rotate_secret(
                SecretId=secret_arn, RotationLambdaARN=function_arn, RotateImmediately=True
            )
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "AccessDeniedException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"RotateSecret kept failing with AccessDeniedException after granting invoke permission: {last_err}")


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
