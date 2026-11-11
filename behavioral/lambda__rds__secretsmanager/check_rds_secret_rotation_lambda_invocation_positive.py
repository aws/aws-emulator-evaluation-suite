"""rds-secret-rotation-lambda-invocation-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rds-secret-rotation-lambda-invocation-positive"
GROUP = "event-propagation"
SERVICES = ["lambda", "rds", "secretsmanager"]

# Standard single-user rotation Lambda contract (createSecret/setSecret/testSecret/
# finishSecret) as documented at
# https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda.html
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """rotate_secret on an RDS-shaped secret invokes the configured Lambda through the full
    createSecret/setSecret/testSecret/finishSecret protocol and promotes a new AWSCURRENT
    version with a changed password."""
    sm = ctx.client("secretsmanager")

    initial_payload = {
        "engine": "mysql",
        "host": ctx.unique_name("sim2real-behav-rds-") + ".rds.amazonaws.com",
        "username": "admin",
        "password": "InitialPassw0rd!23",
        "dbname": "mydb",
        "port": 3306,
        "dbInstanceIdentifier": ctx.unique_name("sim2real-behav-dbi-"),
    }
    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-rds-secret-"),
        SecretString=json.dumps(initial_payload),
        Tags=[{"Key": "sim2real:linked-service", "Value": "rds"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    original_version_id = _current_version_id(ctx, secret_arn)

    role_arn = _create_lambda_role(ctx, [secret_arn])
    fn_name = ctx.unique_name("sim2real-behav-rotate-")
    fn_arn = _create_rotation_function(ctx, role_arn, fn_name)
    _grant_invoke(ctx, fn_name, source_arn=secret_arn)

    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )

    new_version_id = _poll_for_new_current_version(ctx, secret_arn, original_version_id)
    assert new_version_id != original_version_id, (
        f"AWSCURRENT version did not change: still {original_version_id!r} after rotation"
    )

    meta = sm.describe_secret(SecretId=secret_arn)
    stages = meta["VersionIdsToStages"]
    assert "AWSPREVIOUS" in stages.get(original_version_id, []), (
        f"expected AWSPREVIOUS on old version {original_version_id!r}, "
        f"got stages={stages.get(original_version_id, [])!r}"
    )

    new_value = json.loads(sm.get_secret_value(SecretId=secret_arn)["SecretString"])
    assert new_value["password"] != initial_payload["password"], (
        f"password unchanged after rotation: still {initial_payload['password']!r}"
    )
    assert new_value["username"] == initial_payload["username"], (
        f"expected username {initial_payload['username']!r} unchanged, got {new_value['username']!r}"
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
    iam.put_role_policy(
        RoleName=role_name, PolicyName="rotation-policy", PolicyDocument=json.dumps(policy_doc)
    )
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
