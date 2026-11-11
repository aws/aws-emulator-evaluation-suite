"""lambda-secretsmanager-rotate-secret-trigger-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-secretsmanager-rotate-secret-trigger-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "rds", "secretsmanager"]

# The "caller" function: exercises secretsmanager:RotateSecret from inside a Lambda
# handler via boto3 (the sdk-call edge under test).
_CALLER_SOURCE = """
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("secretsmanager")
    try:
        client.rotate_secret(
            SecretId=event["secret_id"],
            RotationLambdaARN=event["rotation_lambda_arn"],
            RotationRules={"AutomaticallyAfterDays": 30},
        )
        return {"ok": True}
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
"""

# The "rotation" function: implements the standard single-user rotation protocol
# (createSecret / setSecret / testSecret / finishSecret) that Secrets Manager itself
# invokes as it drives the secret through its rotation state machine.
_ROTATION_SOURCE = """
import boto3


def handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    client = boto3.client("secretsmanager")

    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            current = client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
            new_value = current["SecretString"] + "-rotated"
            client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=new_value,
                VersionStages=["AWSPENDING"],
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
                    return {"status": "already-current"}
                current_version = version
                break
        client.update_secret_version_stage(
            SecretId=arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=current_version,
        )
    return {"status": "ok"}
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function calls secretsmanager:RotateSecret via boto3; Secrets Manager
    drives the configured rotation Lambda through its protocol and the secret's
    AWSCURRENT version transitions to a freshly rotated value."""
    sm = ctx.client("secretsmanager")
    lam = ctx.client("lambda")

    secret_name = ctx.unique_name("sim2real-behav-secret-")
    seed_value = "seed-value"
    secret = sm.create_secret(
        Name=secret_name,
        SecretString=seed_value,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    initial_version_id = sm.get_secret_value(SecretId=secret_arn)["VersionId"]

    rotation_policy = {
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
    rotation_role_arn = _create_lambda_role(ctx, rotation_policy)
    rotation_func = _create_lambda(ctx, rotation_role_arn, _ROTATION_SOURCE)

    lam.add_permission(
        FunctionName=rotation_func["name"],
        StatementId="AllowSecretsManagerInvoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceArn=secret_arn,
    )

    caller_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:RotateSecret",
                "Resource": secret_arn,
            },
            {
                # RotateSecret additionally requires lambda:InvokeFunction on the
                # rotation function per the API reference's "Required permissions".
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": rotation_func["arn"],
            },
        ],
    }
    caller_role_arn = _create_lambda_role(ctx, caller_policy)
    caller_func = _create_lambda(ctx, caller_role_arn, _CALLER_SOURCE)

    body = _invoke_until_ok(
        ctx,
        caller_func["name"],
        {"secret_id": secret_arn, "rotation_lambda_arn": rotation_func["arn"]},
    )
    assert body.get("ok") is True, body

    final_value = _poll_until_rotated(ctx, secret_arn, initial_version_id, timeout_s=120.0)
    expected_value = seed_value + "-rotated"
    assert final_value == expected_value, f"expected AWSCURRENT {expected_value!r}, got {final_value!r}"

    stages = sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
    assert "AWSPREVIOUS" in stages.get(initial_version_id, []), (
        f"pre-rotation version {initial_version_id} was not demoted to AWSPREVIOUS: {stages}"
    )


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _create_lambda_role(ctx, policy_document):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _zip_code(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _wait_function_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _create_lambda(ctx, role_arn, source, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_bytes = _zip_code(source)
    deadline = time.monotonic() + 90.0
    resp = None
    while resp is None:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags={"sim2real": CHECK},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"]}


def _invoke_json(ctx, function_name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    body_raw = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation error: {body_raw!r}")
    return json.loads(body_raw)


def _invoke_until_ok(ctx, function_name, payload, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    body = None
    while time.monotonic() < deadline:
        body = _invoke_json(ctx, function_name, payload)
        if body.get("ok"):
            return body
        time.sleep(interval_s)
    raise AssertionError(f"caller lambda never reported ok within {timeout_s}s; last body={body!r}")


def _poll_until_rotated(ctx, secret_arn, initial_version_id, timeout_s=120.0, interval_s=5.0):
    sm = ctx.client("secretsmanager")
    deadline = time.monotonic() + timeout_s
    last_value = None
    while time.monotonic() < deadline:
        current = sm.get_secret_value(SecretId=secret_arn)
        last_value = current["SecretString"]
        if current["VersionId"] != initial_version_id:
            return last_value
        time.sleep(interval_s)
    raise AssertionError(
        f"secret {secret_arn} AWSCURRENT version never changed from {initial_version_id} "
        f"within {timeout_s}s (last value observed: {last_value!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
