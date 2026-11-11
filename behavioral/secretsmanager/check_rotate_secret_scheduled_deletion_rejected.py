"""rotate-secret-scheduled-deletion-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "rotate-secret-scheduled-deletion-rejected"
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RotateSecret on a secret scheduled for deletion is refused with InvalidRequestException (exact message) and
    leaves its single AWSCURRENT version and no LastRotatedDate; after RestoreSecret the identical call succeeds
    with a new current version.
    """
    sm = ctx.client("secretsmanager")
    fn_arn = _create_rotation_lambda(ctx)

    doomed_name = ctx.unique_name("sim2real-sm-doomed-")
    doomed = sm.create_secret(
        Name=doomed_name, SecretString="doomed-value", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    doomed_arn = doomed["ARN"]
    v1 = doomed["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=doomed_arn, ForceDeleteWithoutRecovery=True))
    sm.delete_secret(SecretId=doomed_arn)  # schedules deletion, default recovery window

    code, message = _error_code(lambda: sm.rotate_secret(SecretId=doomed_arn, RotationLambdaARN=fn_arn))
    assert code == "InvalidRequestException", (
        f"RotateSecret on a secret pending deletion must be rejected with "
        f"InvalidRequestException, got {code!r}"
    )
    assert message == (
        "You can't perform this operation on the secret because it was marked for deletion."
    ), f"unexpected refusal message: {message!r}"

    # effect absent: still exactly the one original version, still AWSCURRENT, no rotation happened
    described = sm.describe_secret(SecretId=doomed_arn)
    stages_by_version = described["VersionIdsToStages"]
    assert list(stages_by_version.keys()) == [v1], (
        f"a rejected RotateSecret must not create any version; expected only {[v1]!r}, "
        f"got {list(stages_by_version.keys())!r}"
    )
    assert "AWSCURRENT" in stages_by_version[v1], (
        f"the original version {v1!r} must remain AWSCURRENT, got stages "
        f"{stages_by_version[v1]!r}"
    )
    assert described.get("LastRotatedDate") is None, (
        f"a rejected rotation must not set LastRotatedDate, got "
        f"{described.get('LastRotatedDate')!r}"
    )

    # restore: cancel the scheduled deletion on the SAME secret, then the identical
    # RotateSecret call must succeed.
    sm.restore_secret(SecretId=doomed_arn)
    restored = sm.describe_secret(SecretId=doomed_arn)
    assert restored.get("DeletedDate") is None, (
        f"RestoreSecret must clear DeletedDate, got {restored.get('DeletedDate')!r}"
    )

    sm.rotate_secret(SecretId=doomed_arn, RotationLambdaARN=fn_arn)
    rotated = _poll_until(
        lambda: sm.describe_secret(SecretId=doomed_arn),
        lambda d: any("AWSCURRENT" in s and v != v1 for v, s in d["VersionIdsToStages"].items()),
        timeout_s=150.0,
        interval_s=5.0,
    )
    new_current = [v for v, s in rotated["VersionIdsToStages"].items() if "AWSCURRENT" in s][0]
    assert new_current != v1, (
        f"RotateSecret after restore must produce a new AWSCURRENT version distinct from "
        f"{v1!r}, got {new_current!r}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                Tags={"sim2real": CHECK},
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


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
