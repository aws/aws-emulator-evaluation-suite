"""secretsmanager-rotation-lambda-invocation-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "secretsmanager-rotation-lambda-invocation-positive"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """RotateSecret invokes the configured rotation Lambda through all four rotation
    steps and produces a new AWSCURRENT secret version distinct from the original."""
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")

    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:UpdateSecretVersionStage",
                    "secretsmanager:GetRandomPassword",
                ],
                "Resource": "*",
            }
        ],
    )
    fn_name, fn_arn = _create_rotation_function(ctx, role_arn, _ROTATION_LAMBDA_SRC)
    account_id = sts.get_caller_identity()["Account"]
    _add_invoke_permission(ctx, fn_name, account_id)

    secret_arn = _create_secret(ctx, "initial-secret-value-0")
    initial_version = _current_version_id(sm, secret_arn)

    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )

    stages = _poll_until(
        lambda: sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"],
        lambda stages: any(
            vid != initial_version and "AWSCURRENT" in st for vid, st in stages.items()
        ),
        timeout_s=150.0,
        interval_s=5.0,
        description="secret rotation producing a new AWSCURRENT version",
    )
    new_version = next(
        vid for vid, st in stages.items() if vid != initial_version and "AWSCURRENT" in st
    )
    assert "AWSCURRENT" not in stages.get(initial_version, []), (
        f"prior version {initial_version} still carries AWSCURRENT after rotation "
        f"promoted {new_version}; expected exactly one AWSCURRENT version, got stages={stages!r}"
    )

    new_value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert new_value != "initial-secret-value-0", (
        f"expected the rotation Lambda to replace the secret value, got the original "
        f"'initial-secret-value-0' back after rotating to version {new_version}"
    )
    assert new_value, f"expected a non-empty rotated secret value, got {new_value!r}"

    assert "AWSPREVIOUS" in stages.get(initial_version, []), (
        f"prior AWSCURRENT version {initial_version} was not demoted to AWSPREVIOUS after "
        f"rotation, got stages={stages.get(initial_version, [])!r}"
    )


_ROTATION_LAMBDA_SRC = '''
import boto3
import json
import os
import time


def handler(event, context):
    sm = boto3.client("secretsmanager")
    step = event["Step"]
    secret_arn = event["SecretId"]
    token = event["ClientRequestToken"]

    if step == "createSecret":
        bucket = os.environ.get("BACKUP_BUCKET")
        if bucket:
            s3 = boto3.client("s3")
            desc = sm.describe_secret(SecretId=secret_arn)
            desc.pop("ResponseMetadata", None)
            key = "backups/" + secret_arn.split(":")[-1] + "/" + token + ".json"
            s3.put_object(
                Bucket=bucket,
                Key=key,
                Body=json.dumps(desc, default=str).encode("utf-8"),
            )
        try:
            sm.get_secret_value(
                SecretId=secret_arn, VersionId=token, VersionStage="AWSPENDING"
            )
        except sm.exceptions.ResourceNotFoundException:
            new_value = sm.get_random_password(ExcludePunctuation=True)["RandomPassword"]
            sm.put_secret_value(
                SecretId=secret_arn,
                ClientRequestToken=token,
                SecretString=new_value,
                VersionStages=["AWSPENDING"],
            )
    elif step == "setSecret":
        pass
    elif step == "testSecret":
        sm.get_secret_value(
            SecretId=secret_arn, VersionId=token, VersionStage="AWSPENDING"
        )
    elif step == "finishSecret":
        metadata = sm.describe_secret(SecretId=secret_arn)
        current_version = None
        for version_id, stages in metadata["VersionIdsToStages"].items():
            if "AWSCURRENT" in stages:
                if version_id == token:
                    return
                current_version = version_id
                break
        sm.update_secret_version_stage(
            SecretId=secret_arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=current_version,
        )
        table = os.environ.get("AUDIT_TABLE")
        if table:
            ddb = boto3.client("dynamodb")
            ddb.put_item(
                TableName=table,
                Item={
                    "secret_id": {"S": secret_arn},
                    "client_request_token": {"S": token},
                    "event_time": {"S": str(time.time())},
                    "step": {"S": step},
                },
            )
    else:
        raise ValueError("unknown step: " + step)
'''


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _zip_bytes(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _create_lambda_role(ctx, extra_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-rot-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "*",
        }
    ] + extra_statements
    policy_name = "inline-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_rotation_function(
    ctx, role_arn: str, source: str, env: dict[str, str] | None = None
) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-sm-rotator-")
    kwargs: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_bytes(source)},
        Timeout=30,
        MemorySize=128,
        Tags={"sim2real": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    deadline = time.monotonic() + 90.0
    resp = None
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"could not create rotation function: {last_exc}")
    fn_arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"lambda function {fn_name} Active",
    )
    return fn_name, fn_arn


def _add_invoke_permission(ctx, function_name: str, account_id: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowSecretsManagerInvoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceAccount=account_id,
    )


def _create_secret(ctx, initial_value: str) -> str:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-sm-rot-secret-")
    arn = sm.create_secret(
        Name=name,
        SecretString=initial_value,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ARN"]
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
    )
    return arn


def _current_version_id(sm, secret_arn: str) -> str:
    meta = sm.describe_secret(SecretId=secret_arn)
    for vid, stages in meta.get("VersionIdsToStages", {}).items():
        if "AWSCURRENT" in stages:
            return vid
    raise AssertionError(f"secret {secret_arn} has no AWSCURRENT version")


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
