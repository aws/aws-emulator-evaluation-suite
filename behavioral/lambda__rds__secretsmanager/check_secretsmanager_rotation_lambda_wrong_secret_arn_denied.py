"""secretsmanager-rotation-lambda-wrong-secret-arn-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "secretsmanager-rotation-lambda-wrong-secret-arn-denied"
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


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A rotation Lambda whose invoke grant is scoped by SourceArn to one secret rotates that secret, but
    RotateSecret on a second secret is refused with AccessDeniedException (exact message) and leaves it
    unchanged; granting the second secret the same scoped permission lets its rotation succeed."""
    sm = ctx.client("secretsmanager")

    def make_secret(tag: str) -> tuple[str, dict]:
        payload = {
            "engine": "mysql",
            "host": ctx.unique_name(f"sim2real-behav-rds-{tag}-") + ".rds.amazonaws.com",
            "username": "admin",
            "password": f"InitialPassw0rd!23-{tag}",
            "dbname": "mydb",
            "port": 3306,
        }
        secret = sm.create_secret(
            Name=ctx.unique_name(f"sim2real-behav-rds-secret-{tag}-"),
            SecretString=json.dumps(payload),
            Tags=[{"Key": "sim2real:linked-service", "Value": "rds"}],
        )
        arn = secret["ARN"]
        ctx.on_cleanup(lambda a=arn: sm.delete_secret(SecretId=a, ForceDeleteWithoutRecovery=True))
        return arn, payload

    secret_a_arn, payload_a = make_secret("a")
    secret_b_arn, payload_b = make_secret("b")

    original_version_a = _current_version_id(ctx, secret_a_arn)
    original_version_b = _current_version_id(ctx, secret_b_arn)

    role_arn = _create_lambda_role(ctx, [secret_a_arn, secret_b_arn])
    fn_name = ctx.unique_name("sim2real-behav-rotate-")
    fn_arn = _create_rotation_function(ctx, role_arn, fn_name)

    # Scope invoke permission to secret A only.
    _grant_invoke(ctx, fn_name, source_arn=secret_a_arn)

    # Positive control: secret A, whose ARN matches the resource policy condition, rotates.
    sm.rotate_secret(
        SecretId=secret_a_arn,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )
    new_version_a = _poll_for_new_current_version(ctx, secret_a_arn, original_version_a)
    assert new_version_a != original_version_a, "secret A never promoted a new AWSCURRENT version"
    rotated_a = json.loads(sm.get_secret_value(SecretId=secret_a_arn)["SecretString"])
    assert rotated_a["password"] != payload_a["password"], "secret A password unchanged after rotation"

    # Negative: secret B is unrelated and does not match the resource policy's SourceArn.
    code, message = _error_code(
        lambda: sm.rotate_secret(
            SecretId=secret_b_arn,
            RotationLambdaARN=fn_arn,
            RotationRules={"AutomaticallyAfterDays": 30},
            RotateImmediately=True,
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException for secret B, got {code!r}: {message!r}"
    assert message == _CANNOT_INVOKE, f"unexpected RotateSecret refusal message: {message!r}"

    meta_b = sm.describe_secret(SecretId=secret_b_arn)
    stages_b = meta_b["VersionIdsToStages"]
    assert stages_b.get(original_version_b) == ["AWSCURRENT"], (
        f"expected only {original_version_b} staged AWSCURRENT, got {stages_b!r}"
    )
    assert len(stages_b) == 1, f"expected exactly one version for secret B, got {stages_b!r}"
    unchanged_b = json.loads(sm.get_secret_value(SecretId=secret_b_arn)["SecretString"])
    assert unchanged_b["password"] == payload_b["password"], "secret B password changed despite denied rotation"

    # Restore: grant secret B the same scoped invoke permission, and demand the identical call now
    # succeeds.
    _grant_invoke(ctx, fn_name, source_arn=secret_b_arn, statement_id="AllowSecretsManagerInvokeB")
    deadline = time.monotonic() + 60.0
    accepted = False
    while time.monotonic() < deadline:
        accepted = _accepted(
            lambda: sm.rotate_secret(
                SecretId=secret_b_arn,
                RotationLambdaARN=fn_arn,
                RotationRules={"AutomaticallyAfterDays": 30},
                RotateImmediately=True,
            )
        )
        if accepted:
            break
        time.sleep(3)
    assert accepted, "rotate_secret on secret B still denied 60s after the permission grant"
    new_version_b = _poll_for_new_current_version(ctx, secret_b_arn, original_version_b)
    assert new_version_b != original_version_b, "secret B never promoted a new AWSCURRENT version after grant"
    rotated_b = json.loads(sm.get_secret_value(SecretId=secret_b_arn)["SecretString"])
    assert rotated_b["password"] != payload_b["password"], (
        "secret B password unchanged despite permission grant restoring rotation"
    )


_CANNOT_INVOKE = (
    "Secrets Manager cannot invoke the specified Lambda function. Ensure that the function "
    "policy grants access to the principal secretsmanager.amazonaws.com."
)


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _grant_invoke(
    ctx: Any, fn_name: str, source_arn: str | None = None, statement_id: str = "AllowSecretsManagerInvoke"
) -> None:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = {
        "FunctionName": fn_name,
        "StatementId": statement_id,
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
