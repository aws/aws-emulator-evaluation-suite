"""secretsmanager-rotation-lambda-s3-backup-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "secretsmanager-rotation-lambda-s3-backup-positive"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """The rotation Lambda's createSecret step backs up the secret's prior
    metadata (describe_secret snapshot) to an S3 object as part of the rotation
    workflow, and the rotation itself completes end to end."""
    sm = ctx.client("secretsmanager")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    bucket = _create_backup_bucket(ctx)

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
                "Action": ["s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            },
        ],
    )
    fn_name, fn_arn = _create_rotation_function(
        ctx, role_arn, _ROTATION_LAMBDA_SRC, env={"BACKUP_BUCKET": bucket}
    )
    account_id = sts.get_caller_identity()["Account"]
    _add_invoke_permission(ctx, fn_name, account_id)

    secret_arn, secret_name = _create_secret(ctx, "backed-up-secret-value")
    initial_version = _current_version_id(sm, secret_arn)
    secret_suffix = secret_arn.split(":")[-1]

    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )

    listing = _poll_until(
        lambda: s3.list_objects_v2(Bucket=bucket, Prefix=f"backups/{secret_suffix}/"),
        lambda resp: resp.get("KeyCount", 0) >= 1,
        timeout_s=150.0,
        interval_s=5.0,
        description="rotation backup object written to S3",
    )
    keys = [obj["Key"] for obj in listing["Contents"]]
    assert len(keys) == 1, (
        f"expected exactly one backup object under backups/{secret_suffix}/, found {keys!r}"
    )

    body = json.loads(s3.get_object(Bucket=bucket, Key=keys[0])["Body"].read())
    assert body["ARN"] == secret_arn, (
        f"backup object ARN mismatch: expected {secret_arn!r}, got {body.get('ARN')!r}"
    )
    assert body["Name"] == secret_name, (
        f"backup object Name mismatch: expected {secret_name!r}, got {body.get('Name')!r}"
    )

    # The rotation itself must also have completed end to end.
    final_version = _current_version_id(sm, secret_arn)
    assert final_version != initial_version, (
        f"rotation did not advance AWSCURRENT: still {final_version!r} after RotateSecret"
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


def _create_backup_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-rot-backup-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    # us-east-1 is CreateBucket's implicit default region; passing a LocationConstraint
    # for it is itself rejected, so the constraint is only supplied for every other region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


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


def _create_secret(ctx, initial_value: str) -> tuple[str, str]:
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
    return arn, name


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
