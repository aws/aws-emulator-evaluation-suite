"""server-side-managed-rotation-lambda-invocation-enforced."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-managed-rotation-lambda-invocation-enforced"
GROUP = "server-side"
SERVICES = ["secretsmanager"]

# Standard Secrets Manager Lambda rotation template: implements the four
# createSecret/setSecret/testSecret/finishSecret steps that Secrets Manager itself
# invokes server-side. The client only ever calls RotateSecret once.
_ROTATION_HANDLER = r'''
import boto3

def lambda_handler(event, context):
    service_client = boto3.client("secretsmanager")
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    if step == "createSecret":
        try:
            service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except service_client.exceptions.ResourceNotFoundException:
            new_password = service_client.get_random_password(ExcludeCharacters="\"@/\\")["RandomPassword"]
            service_client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=new_password,
                VersionStages=["AWSPENDING"],
            )
    elif step == "setSecret":
        pass
    elif step == "testSecret":
        pass
    elif step == "finishSecret":
        metadata = service_client.describe_secret(SecretId=arn)
        current_version = None
        for version, stages in metadata["VersionIdsToStages"].items():
            if "AWSCURRENT" in stages:
                if version == token:
                    return
                current_version = version
                break
        service_client.update_secret_version_stage(
            SecretId=arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=current_version,
        )
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single RotateSecret call drives the full server-side createSecret ->
    setSecret -> testSecret -> finishSecret Lambda lifecycle: the secret ends up
    with a genuinely new AWSCURRENT value that the client never wrote itself."""
    sm = ctx.client("secretsmanager")
    lambda_arn = _deploy_rotation_lambda(ctx)

    name = ctx.unique_name("sim2real-behav-rot-")
    original_value = "s3cr3t-original-v1"
    sm.create_secret(
        Name=name,
        SecretString=original_value,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    # Add resource-based permission scoped to this secret now that its ARN is known.
    before = sm.describe_secret(SecretId=name)
    secret_arn = before["ARN"]
    original_version = next(v for v, st in before["VersionIdsToStages"].items() if "AWSCURRENT" in st)
    ctx.client("lambda").add_permission(
        FunctionName=lambda_arn,
        StatementId="secretsmanager-invoke-scoped",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceArn=secret_arn,
    )

    sm.rotate_secret(SecretId=name, RotationLambdaARN=lambda_arn)

    description = _poll_until(
        lambda: sm.describe_secret(SecretId=name),
        lambda d: d.get("LastRotatedDate") is not None,
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert description["RotationEnabled"] is True, f"rotation not enabled after RotateSecret: {description}"

    stages_after = description["VersionIdsToStages"]
    new_version = next(v for v, st in stages_after.items() if "AWSCURRENT" in st)
    assert new_version != original_version, (
        f"AWSCURRENT version id did not change after server-side rotation: {stages_after}"
    )
    assert "AWSPREVIOUS" in stages_after.get(original_version, []), (
        f"prior AWSCURRENT version {original_version} was not demoted to AWSPREVIOUS: {stages_after}"
    )

    rotated_value = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")["SecretString"]
    assert rotated_value != original_value, "AWSCURRENT value did not change after server-side rotation"


# ===== helpers =====

def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _deploy_rotation_lambda(ctx) -> str:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-sm-rotrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}],
    )["Role"]["Arn"]

    def _delete_role():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="secrets-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="secrets-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "secretsmanager:GetSecretValue",
                            "secretsmanager:DescribeSecret",
                            "secretsmanager:PutSecretValue",
                            "secretsmanager:UpdateSecretVersionStage",
                            "secretsmanager:GetRandomPassword",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", _ROTATION_HANDLER)

    fn_name = ctx.unique_name("sim2real-sm-rot-fn-")
    function_arn = None
    last_err = None
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=30,
                Publish=True,
                Tags={"sim2real-owner": "behavioral-check"},
            )
            function_arn = resp["FunctionArn"]
            break
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(2)
    if function_arn is None:
        raise AssertionError(f"lambda never became creatable (IAM propagation?): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda state: state == "Active",
        timeout_s=60.0,
        interval_s=3.0,
    )
    return function_arn


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
