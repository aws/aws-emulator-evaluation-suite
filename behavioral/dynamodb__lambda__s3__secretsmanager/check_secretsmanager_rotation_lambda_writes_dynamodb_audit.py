"""secretsmanager-rotation-lambda-writes-dynamodb-audit."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "secretsmanager-rotation-lambda-writes-dynamodb-audit"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """The rotation Lambda's finishSecret step writes an audit record of the
    rotation event into a DynamoDB table, keyed on the secret ARN and the
    rotation's ClientRequestToken."""
    sm = ctx.client("secretsmanager")
    ddb = ctx.client("dynamodb")
    sts = ctx.client("sts")

    table_name = _create_audit_table(ctx)

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
            },
            {
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem"],
                "Resource": ddb.describe_table(TableName=table_name)["Table"]["TableArn"],
            },
        ],
    )
    fn_name, fn_arn = _create_rotation_function(
        ctx, role_arn, _ROTATION_LAMBDA_SRC, env={"AUDIT_TABLE": table_name}
    )
    account_id = sts.get_caller_identity()["Account"]
    _add_invoke_permission(ctx, fn_name, account_id)

    secret_arn = _create_secret(ctx, "audited-secret-value")
    initial_version = _current_version_id(sm, secret_arn)

    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )

    # Wait for the audit record itself rather than the secret's version stages:
    # the record is the observable proof the finishSecret step actually ran.
    items = _poll_until(
        lambda: ddb.query(
            TableName=table_name,
            KeyConditionExpression="secret_id = :sid",
            ExpressionAttributeValues={":sid": {"S": secret_arn}},
        )["Items"],
        lambda items: len(items) >= 1,
        timeout_s=150.0,
        interval_s=5.0,
        description="audit record written to DynamoDB after rotation",
    )
    assert len(items) == 1, f"expected exactly one audit record for {secret_arn}, got {len(items)}: {items!r}"
    item = items[0]
    assert item["secret_id"]["S"] == secret_arn, (
        f"audit record secret_id {item['secret_id']['S']!r} != rotated secret {secret_arn!r}"
    )
    assert item["step"]["S"] == "finishSecret", (
        f"audit record step {item['step']['S']!r} != expected 'finishSecret'"
    )
    assert item["client_request_token"]["S"], "audit record client_request_token is empty"

    # And the rotation genuinely completed end to end.
    final_version = _current_version_id(sm, secret_arn)
    assert final_version != initial_version, (
        f"AWSCURRENT version {final_version!r} did not change from initial {initial_version!r}"
    )
    assert item["client_request_token"]["S"] == final_version, (
        f"audit record token {item['client_request_token']['S']!r} != final AWSCURRENT version {final_version!r}"
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


def _create_audit_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-sm-rot-audit-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "secret_id", "AttributeType": "S"},
            {"AttributeName": "client_request_token", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "secret_id", "KeyType": "HASH"},
            {"AttributeName": "client_request_token", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"table {table_name} ACTIVE",
    )
    return table_name


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        Tags={"sim2real:managed": "true"},
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
