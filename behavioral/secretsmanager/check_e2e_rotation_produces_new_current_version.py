"""e2e-rotation-produces-new-current-version."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-rotation-produces-new-current-version"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]

# A minimal, correct 4-step Secrets Manager rotation function for a generic (non-database)
# secret: createSecret stages a new AWSPENDING value, setSecret is a no-op (there is no
# external system to update), testSecret confirms the pending value is retrievable, and
# finishSecret promotes AWSPENDING to AWSCURRENT (demoting the prior AWSCURRENT to
# AWSPREVIOUS automatically).
_LAMBDA_CODE = '''
import boto3

def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    client = boto3.client("secretsmanager")

    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            current = client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
            new_value = (current.get("SecretString") or "") + "-rotated"
            client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=new_value,
                VersionStages=["AWSPENDING"],
            )
    elif step == "setSecret":
        return
    elif step == "testSecret":
        client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
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
    else:
        raise ValueError("Invalid step: %s" % step)
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """RotateSecret against a real rotation Lambda promotes a new AWSCURRENT, demoting the old one to AWSPREVIOUS."""
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    lambda_client = ctx.client("lambda")

    secret_name = ctx.unique_name("sim2real-rotate-secret-")
    created = sm.create_secret(
        Name=secret_name,
        SecretString="initial-value",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    before_versions = sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]
    original_version_id = next(
        v["VersionId"] for v in before_versions if "AWSCURRENT" in v.get("VersionStages", [])
    )

    role_arn = _create_rotation_role(ctx, iam, secret_arn)
    function_arn = _create_rotation_function(ctx, lambda_client, role_arn)
    _grant_secretsmanager_invoke(lambda_client, function_arn, secret_arn)

    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=function_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )

    def _versions_by_stage():
        versions = sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]
        current = next((v for v in versions if "AWSCURRENT" in v.get("VersionStages", [])), None)
        previous = next((v for v in versions if "AWSPREVIOUS" in v.get("VersionStages", [])), None)
        return current, previous

    current, previous = _poll_until(
        _versions_by_stage,
        lambda cp: cp[0] is not None and cp[0]["VersionId"] != original_version_id and cp[1] is not None,
        timeout_s=120.0,
        interval_s=3.0,
    )

    assert current["VersionId"] != original_version_id, (
        f"expected AWSCURRENT to move off {original_version_id!r}, still current: {current!r}"
    )
    assert previous["VersionId"] == original_version_id, (
        f"expected AWSPREVIOUS to be the demoted original version {original_version_id!r}, got {previous!r}"
    )

    new_value = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]
    old_value = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPREVIOUS")["SecretString"]
    assert old_value == "initial-value", f"expected AWSPREVIOUS value 'initial-value', got {old_value!r}"
    assert new_value == "initial-value-rotated", (
        f"expected AWSCURRENT value 'initial-value-rotated' (the rotation lambda's own transform), got {new_value!r}"
    )

    described = sm.describe_secret(SecretId=secret_arn)
    assert described["RotationEnabled"] is True, (
        f"expected RotationEnabled True after rotate_secret, got {described.get('RotationEnabled')!r}"
    )


# ===== helpers =====

def _ignore_not_found(fn):
    """Run a teardown call; return only when the resource is already gone, raise anything else."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _zip_lambda_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_rotation_role(ctx, iam, secret_arn: str) -> str:
    role_name = ctx.unique_name("sim2real-rotate-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]

    def _cleanup_role():
        _ignore_not_found(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-rotate-inline"))
        _ignore_not_found(
            lambda: iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        )
        _ignore_not_found(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup_role)

    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
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
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-rotate-inline", PolicyDocument=json.dumps(inline_policy)
    )
    return role_arn


def _create_rotation_function(ctx, lambda_client, role_arn: str) -> str:
    function_name = ctx.unique_name("sim2real-rotate-fn-")
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: lambda_client.delete_function(FunctionName=function_name)))

    zip_bytes = _zip_lambda_code(_LAMBDA_CODE)
    deadline = time.monotonic() + 60.0
    last_error = None
    response = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            response = lambda_client.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Publish=True,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as err:
            last_error = err
            # Newly created IAM roles can take a few seconds to become assumable by Lambda.
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(3.0)
    if response is None:
        raise AssertionError(f"rotation function never became creatable: {last_error}")

    lambda_client.get_waiter("function_active").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return response["FunctionArn"]


def _grant_secretsmanager_invoke(lambda_client, function_arn: str, secret_arn: str) -> None:
    function_name = function_arn.split(":")[-1]
    lambda_client.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-secretsmanager-invoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceArn=secret_arn,
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
