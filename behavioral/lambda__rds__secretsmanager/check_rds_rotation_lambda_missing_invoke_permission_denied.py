"""rds-rotation-lambda-missing-invoke-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rds-rotation-lambda-missing-invoke-permission-denied"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]

_ROTATION_LAMBDA_SRC = r'''
import json
import boto3

def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    client = boto3.client("secretsmanager")

    metadata = client.describe_secret(SecretId=arn)
    if not metadata.get("RotationEnabled", False):
        raise ValueError("secret %s is not enabled for rotation" % arn)

    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            current = client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
            current_dict = json.loads(current["SecretString"])
            new_password = client.get_random_password()["RandomPassword"]
            current_dict["password"] = new_password
            client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=json.dumps(current_dict),
                VersionStages=["AWSPENDING"],
            )
    elif step == "setSecret":
        pass
    elif step == "testSecret":
        client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
    elif step == "finishSecret":
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
    else:
        raise ValueError("invalid step %s" % step)
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """RotateSecret is refused with AccessDeniedException (exact message) and the secret keeps its single
    AWSCURRENT version and password when the rotation Lambda lacks the secretsmanager.amazonaws.com
    invoke grant; once granted, rotation yields a new version and password."""
    sm = ctx.client("secretsmanager")

    payload = {
        "engine": "mysql",
        "host": ctx.unique_name("sim2real-behav-rds-") + ".rds.amazonaws.com",
        "username": "admin",
        "password": "InitialPassw0rd!23",
        "dbname": "mydb",
        "port": 3306,
    }
    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-rds-secret-"),
        SecretString=json.dumps(payload),
        Tags=[{"Key": "sim2real:linked-service", "Value": "rds"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    original_version_id = _current_version_id(ctx, secret_arn)

    role_arn = _create_lambda_role(ctx, [secret_arn])
    fn_name = ctx.unique_name("sim2real-behav-rotate-")
    fn_arn = _create_rotation_function(ctx, role_arn, fn_name)
    # Deliberately NOT calling add_permission here: the function's resource policy grants
    # no principal invoke rights at all.

    code, message = _expect_denied(
        lambda: sm.rotate_secret(
            SecretId=secret_arn,
            RotationLambdaARN=fn_arn,
            RotationRules={"AutomaticallyAfterDays": 30},
            RotateImmediately=True,
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}: {message!r}"
    assert message == _CANNOT_INVOKE, f"unexpected RotateSecret refusal message: {message!r}"

    # Effect absent: no new version was created/promoted, secret is unchanged.
    meta = sm.describe_secret(SecretId=secret_arn)
    stages = meta["VersionIdsToStages"]
    assert stages.get(original_version_id) == ["AWSCURRENT"], (
        f"expected {original_version_id} to remain the sole AWSCURRENT version, got {stages!r}"
    )
    assert len(stages) == 1, f"expected no pending rotation version, got {stages!r}"
    unchanged = json.loads(sm.get_secret_value(SecretId=secret_arn)["SecretString"])
    assert unchanged["password"] == payload["password"], (
        "secret password changed despite the denied rotation"
    )

    # Positive control: grant the missing permission and confirm rotation now succeeds.
    # Resource-policy grants on the Lambda side are not immediately consistent, so retry the
    # first call that actually exercises the new permission rather than the add_permission call.
    _grant_invoke(ctx, fn_name, source_arn=secret_arn)
    deadline = time.monotonic() + 60.0
    accepted = False
    while time.monotonic() < deadline:
        accepted = _accepted(
            lambda: sm.rotate_secret(
                SecretId=secret_arn,
                RotationLambdaARN=fn_arn,
                RotationRules={"AutomaticallyAfterDays": 30},
                RotateImmediately=True,
            )
        )
        if accepted:
            break
        time.sleep(3)
    assert accepted, "rotate_secret still denied 60s after the permission grant"
    new_version_id = _poll_for_new_current_version(ctx, secret_arn, original_version_id)
    assert new_version_id != original_version_id, "positive control did not promote a new AWSCURRENT version"
    rotated = json.loads(sm.get_secret_value(SecretId=secret_arn)["SecretString"])
    assert rotated["password"] != payload["password"], (
        "positive control rotation did not change the password"
    )


_CANNOT_INVOKE = (
    "Secrets Manager cannot invoke the specified Lambda function. Ensure that the function "
    "policy grants access to the principal secretsmanager.amazonaws.com."
)


def _accepted(fn) -> bool:
    """True when fn() succeeds, False while it is still refused with AccessDeniedException
    (grant propagation); any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AccessDeniedException":
            return False
        raise
    return True


def _expect_denied(fn):
    """The (code, message) of a call this check asserts MUST be denied."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected rotate_secret to be denied for the missing Lambda invoke permission, "
        f"but it succeeded and returned {result!r}"
    )


def _current_version_id(ctx: Any, secret_arn: str) -> str:
    sm = ctx.client("secretsmanager")
    meta = sm.describe_secret(SecretId=secret_arn)
    for version, stages in meta["VersionIdsToStages"].items():
        if "AWSCURRENT" in stages:
            return version
    raise AssertionError("secret has no AWSCURRENT version")


def _build_lambda_zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _create_lambda_role(ctx: Any, secret_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-rot-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
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
                "Resource": secret_arns,
            },
            {"Effect": "Allow", "Action": "secretsmanager:GetRandomPassword", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="rotation-policy", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="rotation-policy"))
    return role_arn


def _create_rotation_function(ctx: Any, role_arn: str, fn_name: str) -> str:
    lam = ctx.client("lambda")
    zip_bytes = _build_lambda_zip(_ROTATION_LAMBDA_SRC)

    deadline = time.monotonic() + 60.0
    last_err: Exception | None = None
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Publish=True,
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=fn_name)["Configuration"]["State"]
        if state == "Active":
            break
        time.sleep(2)
    else:
        raise AssertionError("lambda function never became Active")
    return resp["FunctionArn"]


def _grant_invoke(ctx: Any, fn_name: str, source_arn: str | None = None) -> None:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = {
        "FunctionName": fn_name,
        "StatementId": "AllowSecretsManagerInvoke",
        "Action": "lambda:InvokeFunction",
        "Principal": "secretsmanager.amazonaws.com",
    }
    if source_arn:
        kwargs["SourceArn"] = source_arn
    lam.add_permission(**kwargs)


def _poll_for_new_current_version(
    ctx: Any, secret_arn: str, original_version_id: str, timeout_s: float = 120.0, interval_s: float = 3.0
) -> str:
    sm = ctx.client("secretsmanager")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        meta = sm.describe_secret(SecretId=secret_arn)
        for version, stages in meta.get("VersionIdsToStages", {}).items():
            if "AWSCURRENT" in stages and version != original_version_id:
                return version
        time.sleep(interval_s)
    raise AssertionError("rotation never promoted a new AWSCURRENT version within timeout")


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
