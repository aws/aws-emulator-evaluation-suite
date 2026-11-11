"""rotation-rules-sets-next-rotation-date-window."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import timedelta

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rotation-rules-sets-next-rotation-date-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["secretsmanager"]

_ROTATION_LAMBDA_SOURCE = """
import boto3


def handler(event, context):
    client = boto3.client("secretsmanager")
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            current = client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
            client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=current["SecretString"],
                VersionStages=["AWSPENDING"],
            )
    elif step == "setSecret":
        pass
    elif step == "testSecret":
        pass
    elif step == "finishSecret":
        metadata = client.describe_secret(SecretId=arn)
        current_version = None
        for version_id, stages in metadata["VersionIdsToStages"].items():
            if "AWSCURRENT" in stages:
                if version_id == token:
                    return
                current_version = version_id
                break
        client.update_secret_version_stage(
            SecretId=arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=current_version,
        )
"""


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Enabling rotation with AutomaticallyAfterDays sets NextRotationDate on DescribeSecret
    consistent with the configured window from the last rotation."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sm = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-behav-rotwindow-")
    secret_arn = sm.create_secret(
        Name=name, SecretString="rotation-seed", Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    role_name = ctx.unique_name("sim2real-behav-rotwindow-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    policy_name = "rotation-window-inline-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:UpdateSecretVersionStage",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    func_name = ctx.unique_name("sim2real-behav-rotwindow-fn-")
    # Lambda creates the function's log group on first invocation; registered before the
    # function's own teardown, so LIFO cleanup removes the group after the function is gone.
    ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{func_name}"))
    func_arn = _create_function_with_retry(
        lam, func_name, role_arn, _zip_bytes(_ROTATION_LAMBDA_SOURCE), timeout_s=_budget_s(ctx, 90.0), ctx=ctx
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))

    lam.add_permission(
        FunctionName=func_name,
        StatementId="allow-secretsmanager-invoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceArn=secret_arn,
    )

    before = sm.describe_secret(SecretId=secret_arn)
    original_version = next(v for v, st in before["VersionIdsToStages"].items() if "AWSCURRENT" in st)

    _rotate_with_retry(sm, secret_arn, func_arn, days=30, timeout_s=_budget_s(ctx, 90.0), ctx=ctx)

    desc = _poll_until_rotated(sm, secret_arn, original_version, timeout_s=_budget_s(ctx, 120.0), ctx=ctx)

    assert desc["RotationEnabled"] is True, f"expected RotationEnabled=True, got {desc.get('RotationEnabled')!r}"
    assert desc["RotationLambdaARN"] == func_arn, (
        f"expected RotationLambdaARN {func_arn!r}, got {desc.get('RotationLambdaARN')!r}"
    )
    assert "LastRotatedDate" in desc, "rotation completed but LastRotatedDate was never set"
    last_rotated = desc["LastRotatedDate"]

    assert "NextRotationDate" in desc, "NextRotationDate missing after a successful rotation"
    next_rotation = desc["NextRotationDate"]
    expected_next = last_rotated + timedelta(days=30)
    delta_seconds = abs((next_rotation - expected_next).total_seconds())
    assert delta_seconds < 86400, (
        f"NextRotationDate {next_rotation} is not within a day of LastRotatedDate+30d "
        f"{expected_next} (delta={delta_seconds}s)"
    )


def _delete_log_group(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
def _zip_bytes(code: str, filename: str = "lambda_function.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_function_with_retry(lam, func_name: str, role_arn: str, code_bytes: bytes, timeout_s: float = 90.0, ctx=None) -> str:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code_bytes},
                Timeout=30,
                Tags={"sim2real": "true"},
            )
            return resp["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(1)
                continue
            raise
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("lambda create_function succeeding: the run budget ended first; not graded")
    raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_exc}")


def _rotate_with_retry(sm, secret_arn: str, func_arn: str, days: int, timeout_s: float = 90.0, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            sm.rotate_secret(
                SecretId=secret_arn,
                RotationLambdaARN=func_arn,
                RotationRules={"AutomaticallyAfterDays": days},
                RotateImmediately=True,
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "InvalidRequestException", "ResourceNotFoundException"):
                last_exc = exc
                time.sleep(1)
                continue
            raise
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("rotate_secret succeeding: the run budget ended first; not graded")
    raise AssertionError(f"rotate_secret never succeeded (lambda permission propagation?): {last_exc}")


def _poll_until_rotated(sm, secret_arn: str, original_version: str, timeout_s: float, ctx=None):
    deadline = time.monotonic() + timeout_s
    last_desc = None
    while time.monotonic() < deadline:
        last_desc = sm.describe_secret(SecretId=secret_arn)
        current = next((v for v, st in last_desc["VersionIdsToStages"].items() if "AWSCURRENT" in st), None)
        if current is not None and current != original_version and "LastRotatedDate" in last_desc:
            return last_desc
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("rotation completing: the run budget ended first; not graded")
    raise AssertionError(f"rotation never completed within {timeout_s}s; last DescribeSecret={last_desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
