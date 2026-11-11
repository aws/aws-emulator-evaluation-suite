"""e2e-cross-service-lambda-rotation-consequence."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "e2e-cross-service-lambda-rotation-consequence"
GROUP = "e2e"
SERVICES = ["secretsmanager"]

_LAMBDA_SRC = '''import boto3


def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    client = boto3.client("secretsmanager")
    metadata = client.describe_secret(SecretId=arn)
    if not metadata.get("RotationEnabled", False):
        raise ValueError("secret not enabled for rotation: " + arn)
    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        raise ValueError("version has no stage: " + token)
    if "AWSCURRENT" in versions[token]:
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError("version not AWSPENDING: " + token)

    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            new_value = client.get_random_password(ExcludeCharacters='"@/')["RandomPassword"]
            client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=new_value,
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
        raise ValueError("invalid step: " + step)
'''


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda rotation demotes the prior AWSCURRENT to a still-readable AWSPREVIOUS and yields a new
    AWSCURRENT value whose VersionId matches RotateSecret's response."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-sm-rotconseq-")
    created = sm.create_secret(
        Name=name,
        SecretString="initial-value",
        Tags=[{"Key": "sim2real", "Value": "e2e-cross-service-lambda-rotation-consequence"}],
    )
    secret_arn = created["ARN"]
    v1 = created["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    fn_arn = _create_rotation_lambda(ctx)
    rotate_resp = sm.rotate_secret(SecretId=secret_arn, RotationLambdaARN=fn_arn)
    rotate_version_id = rotate_resp["VersionId"]

    described = _poll_until(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: any("AWSCURRENT" in stages and v != v1 for v, stages in d["VersionIdsToStages"].items()),
        timeout_s=150.0,
        interval_s=5.0,
    )
    stages_by_version = described["VersionIdsToStages"]
    new_current = [v for v, s in stages_by_version.items() if "AWSCURRENT" in s][0]

    assert rotate_version_id == new_current, (
        f"RotateSecret returned VersionId={rotate_version_id!r} but DescribeSecret now labels "
        f"{new_current!r} AWSCURRENT"
    )

    assert "AWSPREVIOUS" in stages_by_version[v1], (
        f"expected the original version {v1!r} to carry AWSPREVIOUS after rotation, "
        f"got stages={stages_by_version[v1]!r}"
    )
    assert "AWSCURRENT" not in stages_by_version[v1], (
        f"expected the original version {v1!r} to lose AWSCURRENT after rotation, "
        f"got stages={stages_by_version[v1]!r}"
    )

    previous_value = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPREVIOUS")["SecretString"]
    assert previous_value == "initial-value", (
        f"expected AWSPREVIOUS to still hold the original value 'initial-value', got {previous_value!r}"
    )

    current_value = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]
    assert current_value != "initial-value", (
        "expected AWSCURRENT to hold a freshly generated password after rotation, "
        "but it still equals the pre-rotation value 'initial-value'"
    )

    listed = {v["VersionId"]: v["VersionStages"] for v in sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]}
    assert "AWSCURRENT" in listed[new_current], (
        f"expected ListSecretVersionIds to report AWSCURRENT for {new_current!r}, got {listed[new_current]!r}"
    )
    assert "AWSPREVIOUS" in listed[v1], (
        f"expected ListSecretVersionIds to report AWSPREVIOUS for {v1!r}, got {listed[v1]!r}"
    )


def _create_rotation_lambda(ctx) -> str:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-sm-rotrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "e2e-cross-service-lambda-rotation-consequence"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "secretsmanager:*", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    }
    policy_name = "sim2real-sm-rotpolicy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _LAMBDA_SRC)
    buf.seek(0)

    fn_name = ctx.unique_name("sim2real-sm-rotate-")
    deadline = time.monotonic() + 40
    last_err = None
    fn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            fn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.lambda_handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=30,
                Tags={"sim2real": "e2e-cross-service-lambda-rotation-consequence"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(4)
    if fn is None:
        raise last_err
    fn_arn = fn["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-sm-invoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
    )
    return fn_arn


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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
