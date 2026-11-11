"""rotation-rules-automatically-after-days-sets-next-rotation-date."""
from __future__ import annotations

import datetime as dt
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rotation-rules-automatically-after-days-sets-next-rotation-date"
GROUP = "visibility-timeout-ttl"
SERVICES = ["secretsmanager"]

_SCENARIO = "secretsmanager-rotation-next-rotation-date"

_AUTOMATICALLY_AFTER_DAYS = 10
# NextRotationDate may be snapped to a rotation-window day boundary rather than the
# exact second, so allow generous slack while still catching a wrong/absent value.
_TOLERANCE_SECONDS = 129600  # 36 hours

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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RotateSecret with RotationRules.AutomaticallyAfterDays enables rotation and sets
    NextRotationDate to about now + AutomaticallyAfterDays on DescribeSecret, without waiting
    for the Lambda rotation itself to finish."""
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    secret_name = ctx.unique_name("sim2real-behav-nextrot-")
    secret = sm.create_secret(Name=secret_name, SecretString="rotatable-value", Tags=_sim2real_tags(_SCENARIO))
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    func_name, func_arn = _create_rotation_lambda(ctx, iam, lam, secret_arn)
    lam.add_permission(
        FunctionName=func_name,
        StatementId="AllowSecretsManagerInvoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceAccount=account_id,
    )
    _wait_for_lambda_permission(lam, func_name)

    before = dt.datetime.now(dt.timezone.utc)
    _rotate_with_retry(
        sm, secret_arn, func_arn, rotation_rules={"AutomaticallyAfterDays": _AUTOMATICALLY_AFTER_DAYS}, timeout_s=90.0
    )
    described = _wait_for_rotation_scheduled(sm, secret_arn, timeout_s=90.0)

    assert described["RotationRules"]["AutomaticallyAfterDays"] == _AUTOMATICALLY_AFTER_DAYS, (
        f"expected AutomaticallyAfterDays={_AUTOMATICALLY_AFTER_DAYS}, "
        f"got {described['RotationRules'].get('AutomaticallyAfterDays')!r}"
    )
    assert described["RotationEnabled"] is True, f"expected RotationEnabled=True, got {described.get('RotationEnabled')!r}"
    next_rotation = described["NextRotationDate"]
    expected = before + dt.timedelta(days=_AUTOMATICALLY_AFTER_DAYS)
    delta = abs((next_rotation - expected).total_seconds())
    assert delta < _TOLERANCE_SECONDS, f"NextRotationDate off by {delta}s from now+{_AUTOMATICALLY_AFTER_DAYS}d"


def _sim2real_tags(scenario: str) -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": scenario},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_sim2real_tags(_SCENARIO)
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
                Tags={t["Key"]: t["Value"] for t in _sim2real_tags(_SCENARIO)},
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


def _wait_for_rotation_scheduled(sm, secret_arn: str, timeout_s: float = 90.0):
    """Poll DescribeSecret until RotationEnabled and NextRotationDate appear; both are set when
    the rotation is scheduled, before the Lambda rotation completes."""
    deadline = time.monotonic() + timeout_s
    last_described = None
    while time.monotonic() < deadline:
        described = sm.describe_secret(SecretId=secret_arn)
        last_described = described
        if described.get("RotationEnabled") and described.get("NextRotationDate") is not None:
            return described
        time.sleep(3)
    raise AssertionError(
        f"RotationEnabled/NextRotationDate never appeared in time; last observed {last_described}"
    )


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
