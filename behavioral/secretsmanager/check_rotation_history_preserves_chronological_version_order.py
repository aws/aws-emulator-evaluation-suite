"""rotation-history-preserves-chronological-version-order."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rotation-history-preserves-chronological-version-order"
GROUP = "ordering"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Sequential RotateSecret calls produce versions whose CreatedDate follows the rotation order,
    with the most recently rotated version carrying AWSCURRENT. ListSecretVersionIds' array order
    is undocumented, so only CreatedDate is compared."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-rothist-")
    created = sm.create_secret(Name=name, SecretString="v0")
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    role_arn = _create_rotation_role(ctx, arn)
    fn_arn = _create_rotation_lambda(ctx, role_arn)

    rotation_order = [created["VersionId"]]

    sm.rotate_secret(
        SecretId=arn, RotationLambdaARN=fn_arn, RotationRules={"AutomaticallyAfterDays": 30}
    )
    desc = _wait_rotation_settled(ctx, sm, arn, rotation_order)
    rotation_order.append(_current_version(desc))

    # Ensure the next rotation's CreatedDate lands in a strictly later timestamp bucket.
    _settle_deadline = time.monotonic() + 2.0
    while time.monotonic() < _settle_deadline:
        time.sleep(0.5)

    sm.rotate_secret(SecretId=arn)
    desc = _wait_rotation_settled(ctx, sm, arn, rotation_order)
    rotation_order.append(_current_version(desc))

    versions = sm.list_secret_version_ids(SecretId=arn, IncludeDeprecated=True)["Versions"]
    by_id = {v["VersionId"]: v for v in versions}
    assert set(by_id) == set(rotation_order), (
        f"ListSecretVersionIds did not return the expected rotation versions: "
        f"{sorted(by_id)} vs {rotation_order}"
    )

    dates_in_rotation_order = [by_id[vid]["CreatedDate"] for vid in rotation_order]
    assert dates_in_rotation_order == sorted(dates_in_rotation_order), (
        f"CreatedDate values do not increase monotonically in actual rotation order: "
        f"{dates_in_rotation_order}"
    )

    newest = max(versions, key=lambda v: v["CreatedDate"])
    assert newest["VersionId"] == rotation_order[-1], (
        f"version with the latest CreatedDate {newest['VersionId']} does not match the most "
        f"recently rotated version {rotation_order[-1]}"
    )
    assert "AWSCURRENT" in newest.get("VersionStages", []), (
        f"most recently rotated version {newest['VersionId']} does not carry AWSCURRENT: "
        f"{newest.get('VersionStages')}"
    )


_ROTATION_LAMBDA_CODE = """
import boto3
import json


def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    client = boto3.client("secretsmanager")
    metadata = client.describe_secret(SecretId=arn)
    if not metadata.get("RotationEnabled", False):
        raise ValueError("secret is not enabled for rotation")
    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        raise ValueError("version has no stage for this secret")
    if "AWSCURRENT" in versions[token]:
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError("version not staged AWSPENDING")

    if step == "createSecret":
        _create_secret(client, arn, token)
    elif step == "setSecret":
        pass
    elif step == "testSecret":
        pass
    elif step == "finishSecret":
        _finish_secret(client, arn, token)
    else:
        raise ValueError("invalid step " + str(step))


def _create_secret(client, arn, token):
    try:
        client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
    except client.exceptions.ResourceNotFoundException:
        client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=json.dumps({"rotated": token}),
            VersionStages=["AWSPENDING"],
        )


def _finish_secret(client, arn, token):
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


def _rotation_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _ROTATION_LAMBDA_CODE)
    return buf.getvalue()


def _create_rotation_role(ctx, secret_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rotrole-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_exec_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_policy_arn)
    )

    policy_name = ctx.unique_name("sim2real-rotpolicy-")
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
                "Resource": secret_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_rotation_lambda(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-rotfn-")
    zip_bytes = _rotation_zip_bytes()

    fn_arn = None
    last_err = None
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
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
            fn_arn = resp["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if fn_arn is None:
        if _budget_spent(ctx):
            raise TimeoutError("lambda create_function: the run budget ended first; not graded")
        raise AssertionError(
            f"lambda create_function never succeeded (IAM propagation?): {last_err}"
        )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    became_active = False
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=fn_name)["State"]
        if state == "Active":
            became_active = True
            break
        time.sleep(2)
    if not became_active:
        if _budget_spent(ctx):
            raise TimeoutError(f"lambda function {fn_name} becoming Active: the run budget ended "
                               "first; not graded")
        raise AssertionError(f"lambda function {fn_name} never became Active")

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="AllowSecretsManagerInvoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
    )
    return fn_arn


def _wait_rotation_settled(ctx, sm, secret_id: str, known: list[str], timeout_s=180.0) -> dict:
    """DescribeSecret once a version outside `known` carries AWSCURRENT.

    Rotation runs asynchronously: first a version id outside `known` must exist, then the rotation
    just requested has finished once a new version carries AWSCURRENT.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    phase = "a new version id"
    while True:
        desc = sm.describe_secret(SecretId=secret_id)
        stages = desc.get("VersionIdsToStages", {})
        new = [v for v in stages if v not in known]
        if new:
            phase = f"a new version ({', '.join(new)}) carrying AWSCURRENT"
            if any("AWSCURRENT" in stages[v] for v in new):
                return desc
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"rotation of {secret_id} waiting for {phase}: the run budget ended first; "
                    "not graded")
            raise AssertionError(
                f"rotation of {secret_id} never reached {phase} within {timeout_s}s; "
                f"stages {stages!r}")
        time.sleep(2)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _current_version(desc: dict) -> str:
    for version, labels in desc.get("VersionIdsToStages", {}).items():
        if "AWSCURRENT" in labels:
            return version
    raise AssertionError("no AWSCURRENT version found in DescribeSecret response")


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
