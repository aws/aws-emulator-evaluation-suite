"""secretsmanager-rotation-missing-invoke-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "secretsmanager-rotation-missing-invoke-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]
_SECRETSMANAGER_PRINCIPAL = "secretsmanager.amazonaws.com"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """RotateSecret with a function that grants secretsmanager.amazonaws.com no invoke permission is refused with
    AccessDeniedException and its exact message and the secret's version and value stay; after the grant,
    rotating a second secret moves AWSCURRENT and replaces the value.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

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
    # Deliberately NOT calling _add_invoke_permission here: this is the one broken
    # condition under test.

    secret_a = _create_secret(ctx, "unpermissioned-secret-value")
    initial_version_a = _current_version_id(sm, secret_a)

    # RotateSecret checks that it can invoke the function within the call: without a policy statement
    # letting secretsmanager.amazonaws.com invoke it, the call fails AccessDeniedException at once.
    try:
        sm.rotate_secret(
            SecretId=secret_a,
            RotationLambdaARN=fn_arn,
            RotationRules={"AutomaticallyAfterDays": 30},
            RotateImmediately=True,
        )
        rejected = False
    except sm.exceptions.ClientError as exc:
        rejected = True
        code = exc.response.get("Error", {}).get("Code")
        assert code == "AccessDeniedException", (
            f"expected AccessDeniedException, got {code}: {exc}"
        )
        message = exc.response.get("Error", {}).get("Message")
        assert message == (
            "Secrets Manager cannot invoke the specified Lambda function. Ensure that the "
            f"function policy grants access to the principal {_SECRETSMANAGER_PRINCIPAL}."
        ), message
    assert rejected, "RotateSecret succeeded despite the Lambda lacking invoke permission"

    # Bounded poll (belt-and-suspenders): watch for the version changing. It
    # must not, as the call above was rejected before any invocation.
    changed = False
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        stages = sm.describe_secret(SecretId=secret_a)["VersionIdsToStages"]
        if any(
            vid != initial_version_a and "AWSCURRENT" in st
            for vid, st in stages.items()
        ):
            changed = True
            break
        time.sleep(3.0)
    assert not changed, "rotation completed despite the Lambda lacking invoke permission"

    final_version_a = _current_version_id(sm, secret_a)
    assert final_version_a == initial_version_a, (
        f"AWSCURRENT moved from {initial_version_a} to {final_version_a} despite "
        "the rejected RotateSecret call"
    )
    value_a = sm.get_secret_value(SecretId=secret_a)["SecretString"]
    assert value_a == "unpermissioned-secret-value", (
        f"expected secret value unchanged at 'unpermissioned-secret-value', got {value_a!r}"
    )

    # Positive control: grant the invoke permission on the SAME function, then
    # rotate a FRESH secret and confirm rotation completes.
    _add_invoke_permission(ctx, fn_name, account_id)
    secret_b = _create_secret(ctx, "permissioned-secret-value")
    initial_version_b = _current_version_id(sm, secret_b)

    # The just-granted resource policy can lag a few seconds before RotateSecret's
    # own invocability check honors it, surfacing as a transient AccessDeniedException
    # indistinguishable from the negative case above; retry through that window only.
    _rotate_with_retry_on_access_denied(
        sm,
        secret_b,
        fn_arn,
        {"AutomaticallyAfterDays": 30},
    )
    stages_b = _poll_until(
        lambda: sm.describe_secret(SecretId=secret_b)["VersionIdsToStages"],
        lambda st: any(
            vid != initial_version_b and "AWSCURRENT" in s for vid, s in st.items()
        ),
        timeout_s=150.0,
        interval_s=5.0,
        description="control secret rotation after granting invoke permission",
    )
    new_version_b = next(
        vid
        for vid, st in stages_b.items()
        if vid != initial_version_b and "AWSCURRENT" in st
    )
    assert new_version_b != initial_version_b, (
        f"expected AWSCURRENT to move off {initial_version_b}, but it did not"
    )
    value_b = sm.get_secret_value(SecretId=secret_b)["SecretString"]
    assert value_b != "permissioned-secret-value", (
        f"expected rotation to replace the secret value, but it is still {value_b!r}"
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
        Tags={"sim2real": "true"},
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
        Principal=_SECRETSMANAGER_PRINCIPAL,
        SourceAccount=account_id,
    )


def _rotate_with_retry_on_access_denied(
    sm, secret_arn: str, function_arn: str, rotation_rules: dict, *, timeout_s: float = 60.0
) -> None:
    """A resource policy granted moments ago can still lag RotateSecret's own
    invocability check by a few seconds; retry through that specific transient
    AccessDeniedException rather than any other failure."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sm.rotate_secret(
                SecretId=secret_arn,
                RotationLambdaARN=function_arn,
                RotationRules=rotation_rules,
                RotateImmediately=True,
            )
            return
        except sm.exceptions.ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(
        f"RotateSecret kept failing with AccessDeniedException after granting invoke "
        f"permission: {last_exc}"
    )


def _create_secret(ctx, initial_value: str) -> str:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-sm-rot-secret-")
    arn = sm.create_secret(
        Name=name,
        SecretString=initial_value,
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
