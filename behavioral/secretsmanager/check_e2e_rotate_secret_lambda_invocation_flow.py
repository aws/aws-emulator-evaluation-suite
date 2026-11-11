"""e2e-rotate-secret-lambda-invocation-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-rotate-secret-lambda-invocation-flow"
GROUP = "server-side"
SERVICES = ["secretsmanager"]

_LAMBDA_CODE = """
import json
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
            new_value = json.dumps({"password": "rotated-" + token[:8]})
            client.put_secret_value(
                SecretId=arn, ClientRequestToken=token, SecretString=new_value, VersionStages=["AWSPENDING"]
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
            SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version
        )
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """RotateSecret with a real Lambda rotation function promotes a new AWSCURRENT version end-to-end."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sm = ctx.client("secretsmanager")

    role_name = ctx.unique_name("sim2real-behav-secmgr-rotrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    policy_name = "rotation-inline-policy"
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

    func_name = ctx.unique_name("sim2real-behav-secmgr-rotfn-")
    code_bytes = _zip_bytes(_LAMBDA_CODE)
    ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
    func_arn = _create_function_with_retry(lam, func_name, role_arn, code_bytes)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))

    secret_name = ctx.unique_name("sim2real-behav-secmgr-rotsecret-")
    original_value = json.dumps({"password": "original-pw-value"})
    created = sm.create_secret(
        Name=secret_name, SecretString=original_value, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    lam.add_permission(
        FunctionName=func_name,
        StatementId="allow-secretsmanager-invoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceArn=secret_arn,
    )

    before = sm.describe_secret(SecretId=secret_arn)
    original_version = next(v for v, st in before["VersionIdsToStages"].items() if "AWSCURRENT" in st)

    new_version = _drive_rotation(sm, secret_arn, func_arn, original_version)

    stages_after = sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
    assert "AWSCURRENT" in stages_after.get(new_version, [])
    assert "AWSPREVIOUS" in stages_after.get(original_version, [])

    current_value = json.loads(sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"])
    previous_value = json.loads(sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPREVIOUS")["SecretString"])
    assert previous_value == {"password": "original-pw-value"}
    assert current_value["password"].startswith("rotated-")
    assert current_value != previous_value


def _zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_function_with_retry(lam, func_name: str, role_arn: str, code_bytes: bytes, timeout_s: float = 90.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code_bytes},
                Timeout=30,
                Tags={"sim2real-check": CHECK},
            )
            return resp["FunctionArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_exc}")


def _drive_rotation(sm, secret_arn: str, lambda_arn: str, original_version: str, timeout_s: float = 180.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            sm.rotate_secret(SecretId=secret_arn, RotationLambdaARN=lambda_arn, RotationRules={"AutomaticallyAfterDays": 1})
        except ClientError as exc:
            last_err = exc
        sub_deadline = time.monotonic() + 20
        while time.monotonic() < sub_deadline:
            desc = sm.describe_secret(SecretId=secret_arn)
            current = next((v for v, st in desc["VersionIdsToStages"].items() if "AWSCURRENT" in st), None)
            if current is not None and current != original_version:
                return current
            time.sleep(3)
    raise AssertionError(f"rotation never promoted a new AWSCURRENT version (last_err={last_err})")


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
