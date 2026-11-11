"""e2e-create-use-rotate-delete-restore."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "e2e-create-use-rotate-delete-restore"
GROUP = "e2e"
SERVICES = ["secretsmanager"]

_MARKED_FOR_DELETION = (
    "You can't perform this operation on the secret because it was marked for deletion."
)

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


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full lifecycle create->write->read->rotate->delete->restore asserts each real
    consequence (new current version, demoted previous version, recoverable secret)."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-sm-lifecycle-")
    created = sm.create_secret(
        Name=name,
        SecretString="seed-value",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    secret_arn = created["ARN"]
    v1 = created["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    # write a new version
    put = sm.put_secret_value(SecretId=secret_arn, SecretString="updated-value")
    v2 = put["VersionId"]
    assert v2 != v1, f"put_secret_value should mint a new version id, got the same id back: {v2!r}"
    current = sm.get_secret_value(SecretId=secret_arn)
    assert current["SecretString"] == "updated-value", (
        f"expected the new AWSCURRENT value 'updated-value', got {current['SecretString']!r}"
    )
    versions = sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]
    by_id = {v["VersionId"]: v["VersionStages"] for v in versions}
    assert "AWSPREVIOUS" in by_id[v1], f"expected v1 {v1} demoted to AWSPREVIOUS, stages were {by_id[v1]!r}"
    assert "AWSCURRENT" in by_id[v2], f"expected v2 {v2} to be AWSCURRENT, stages were {by_id[v2]!r}"

    # rotate: attach a working rotation Lambda and rotate immediately
    fn_arn = _create_rotation_lambda(ctx)
    sm.rotate_secret(SecretId=secret_arn, RotationLambdaARN=fn_arn)
    rotated = _poll_until(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: any(
            "AWSCURRENT" in stages and version != v2 for version, stages in d["VersionIdsToStages"].items()
        ),
        timeout_s=150.0,
        interval_s=5.0,
    )
    v3 = [v for v, stages in rotated["VersionIdsToStages"].items() if "AWSCURRENT" in stages][0]
    assert v3 not in (v1, v2), f"rotation should mint a new current version, got {v3!r} which is v1 or v2"
    rotated_value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert rotated_value != "updated-value", (
        "rotation should replace the secret value, but the post-rotation value is unchanged"
    )

    # delete: secret becomes pending deletion, unversioned reads are rejected
    delete_resp = sm.delete_secret(SecretId=secret_arn)
    assert delete_resp["DeletionDate"] is not None, "delete_secret response should carry a DeletionDate"
    described = sm.describe_secret(SecretId=secret_arn)
    assert described.get("DeletedDate") is not None, (
        f"describe_secret should show DeletedDate after delete, got {described.get('DeletedDate')!r}"
    )
    err = _error(lambda: sm.get_secret_value(SecretId=secret_arn))
    assert err.get("Code") == "InvalidRequestException", (
        f"expected InvalidRequestException reading a secret pending deletion, got {err!r}"
    )
    assert err.get("Message") == _MARKED_FOR_DELETION, (
        f"expected message {_MARKED_FOR_DELETION!r}, got {err.get('Message')!r}"
    )
    # explicit VersionId reads are ALSO rejected while pending deletion (AWS blocks all
    # value reads on a scheduled-for-deletion secret, not just the default/unversioned one).
    err_versioned = _error(lambda: sm.get_secret_value(SecretId=secret_arn, VersionId=v3))
    assert err_versioned.get("Code") == "InvalidRequestException", (
        f"expected InvalidRequestException reading an explicit VersionId while pending deletion, got {err_versioned!r}"
    )
    assert err_versioned.get("Message") == _MARKED_FOR_DELETION, (
        f"expected message {_MARKED_FOR_DELETION!r}, got {err_versioned.get('Message')!r}"
    )

    # restore: back to Active, default read works again with the same current value
    sm.restore_secret(SecretId=secret_arn)
    restored = sm.describe_secret(SecretId=secret_arn)
    assert restored.get("DeletedDate") is None, (
        f"describe_secret should clear DeletedDate after restore, got {restored.get('DeletedDate')!r}"
    )
    final_value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert final_value == rotated_value, (
        f"restored secret should serve the pre-delete current value {rotated_value!r}, got {final_value!r}"
    )


def _create_rotation_lambda(ctx) -> str:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-behav-sm-rotrole-")
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

    fn_name = ctx.unique_name("sim2real-behav-sm-rotate-")
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
                Tags={"sim2real:managed": "true"},
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


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
