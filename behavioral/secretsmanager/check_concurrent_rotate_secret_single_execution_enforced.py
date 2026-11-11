"""concurrent-rotate-secret-single-execution-enforced."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-rotate-secret-single-execution-enforced"
GROUP = "concurrency"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two back-to-back RotateSecret calls on a secret whose rotation is already configured
    settle to exactly one new version carrying AWSCURRENT (the second meets the first's
    AWSPENDING version) -- never two competing rotations landing two new versions."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-rotate-")
    created = sm.create_secret(
        Name=name,
        SecretString="initial-value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    role_arn = _create_rotation_role(ctx, arn)
    fn_arn = _create_rotation_lambda(ctx, role_arn)

    # Configure rotation and let the first rotation fully settle before the pair of calls.
    sm.rotate_secret(
        SecretId=arn, RotationLambdaARN=fn_arn, RotationRules={"AutomaticallyAfterDays": 30}
    )
    _wait_rotation_settled(sm, arn)

    before_ids = {
        v["VersionId"]
        for v in sm.list_secret_version_ids(SecretId=arn, IncludeDeprecated=True)["Versions"]
    }

    def _rotate():
        return sm.rotate_secret(SecretId=arn)

    # Sequential, so the second call deterministically meets the first's AWSPENDING version
    # (RotateSecret docs: a later call then "assumes that a previous rotation request is still in
    # progress and returns an error"); a true race has no documented outcome.
    results = _run_in_turn([_rotate, _rotate])
    accepted = [r for r, err in results if err is None]
    rejected = [err for _, err in results if err is not None]
    assert len(accepted) >= 1, f"neither RotateSecret call was accepted: {rejected}"
    for err in rejected:
        assert err[0] == "InvalidRequestException", f"unexpected rejection code: {err}"
        expected = "A previous rotation isn't complete. That rotation will be reattempted."
        assert err[1] == expected, f"expected {expected!r}, got {err[1]!r}"

    _wait_rotation_settled(sm, arn)
    after = sm.list_secret_version_ids(SecretId=arn, IncludeDeprecated=True)["Versions"]
    after_ids = {v["VersionId"] for v in after}
    new_ids = after_ids - before_ids
    assert len(new_ids) == 1, (
        f"expected exactly one new version from the two rotations, "
        f"got {len(new_ids)}: {new_ids}"
    )

    current_versions = [
        v["VersionId"] for v in after if "AWSCURRENT" in v.get("VersionStages", [])
    ]
    assert len(current_versions) == 1, (
        f"expected exactly one AWSCURRENT version, found {current_versions}"
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
    deadline = time.monotonic() + 90.0
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
                Tags={"sim2real": CHECK},
            )
            fn_arn = resp["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if fn_arn is None:
        raise AssertionError(
            f"lambda create_function never succeeded (IAM propagation?): {last_err}"
        )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    deadline = time.monotonic() + 60.0
    became_active = False
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=fn_name)["State"]
        if state == "Active":
            became_active = True
            break
        time.sleep(2)
    if not became_active:
        raise AssertionError(f"lambda function {fn_name} never became Active")

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="AllowSecretsManagerInvoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
    )
    return fn_arn


def _wait_rotation_settled(sm, secret_id: str, timeout_s: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = sm.describe_secret(SecretId=secret_id)
        stages = desc.get("VersionIdsToStages", {})
        current_version = None
        pending_version = None
        for version, labels in stages.items():
            if "AWSCURRENT" in labels:
                current_version = version
            if "AWSPENDING" in labels:
                pending_version = version
        if pending_version is None or pending_version == current_version:
            return desc
        time.sleep(2)
    raise AssertionError(f"rotation for {secret_id} did not settle within {timeout_s}s")


def _run_in_turn(fns):
    from botocore.exceptions import ClientError

    def _wrap(fn):
        try:
            return fn(), None
        except ClientError as exc:
            return None, (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    return [_wrap(fn) for fn in fns]


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
