"""delete-secret-disables-rotation-and-restore-does-not-reenable-it."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-secret-disables-rotation-and-restore-does-not-reenable-it"
GROUP = "rotation"
SERVICES = ["secretsmanager"]

_NOOP_LAMBDA_SOURCE = (
    "def lambda_handler(event, context):\n"
    "    return {'ok': True, 'step': event.get('Step')}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteSecret turns rotation off (RotationEnabled False, NextRotationDate cleared, Lambda ARN
    kept); RestoreSecret brings the secret back Active with rotation still disabled, and a fresh
    RotateSecret resumes it.
    """
    sm = ctx.client("secretsmanager")

    secret_name = ctx.unique_name("sim2real-behav-delrot-")
    created = sm.create_secret(
        Name=secret_name, SecretString="original-credential",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    original_version = created["VersionId"]
    ctx.on_cleanup(lambda: _reap_secret(sm, secret_arn))

    fn_name = ctx.unique_name("sim2real-behav-delrot-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{fn_name}"))
    role_arn = _create_rotation_role(ctx, secret_arn)
    fn_arn = _create_rotation_function(ctx, fn_name, role_arn)
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-secretsmanager-invoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceArn=secret_arn,
    )

    _poll_ok(
        lambda: sm.rotate_secret(
            SecretId=secret_arn,
            RotationLambdaARN=fn_arn,
            RotationRules={"AutomaticallyAfterDays": 30},
            RotateImmediately=False,
        ),
        timeout_s=90.0,
    )
    scheduled = _poll(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: d.get("RotationEnabled") is True and d.get("NextRotationDate") is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description="RotateSecret to enable rotation and record a NextRotationDate",
    )
    assert scheduled["RotationEnabled"] is True, "setup must enable rotation before this check begins"
    assert scheduled["RotationLambdaARN"] == fn_arn, "setup must record the rotation function"

    # DeleteSecret, recoverable (default 30-day window): turns rotation off. DescribeSecret can
    # lag DeleteSecret by a moment, so poll for DeletedDate rather than reading once.
    delete_resp = sm.delete_secret(SecretId=secret_arn)
    assert delete_resp["DeletionDate"] is not None, "DeleteSecret response must carry a DeletionDate"
    deleted = _poll(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: d.get("DeletedDate") is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description="DescribeSecret to show DeletedDate after a recoverable delete",
    )
    assert deleted.get("DeletedDate") is not None, (
        f"DescribeSecret must show DeletedDate after a recoverable delete, got {deleted.get('DeletedDate')!r}"
    )
    assert deleted.get("RotationEnabled") is False, (
        f"a recoverable DeleteSecret must disable rotation; got RotationEnabled={deleted.get('RotationEnabled')!r}"
    )
    assert "NextRotationDate" not in deleted, (
        f"a recoverable DeleteSecret must clear NextRotationDate; got {deleted.get('NextRotationDate')!r}"
    )
    assert deleted.get("RotationLambdaARN") == fn_arn, (
        "the rotation function association itself must survive the delete "
        f"(only the schedule is disabled); got {deleted.get('RotationLambdaARN')!r}"
    )

    # RestoreSecret: clears the deletion, but does NOT resume the rotation it turned off.
    restore_resp = sm.restore_secret(SecretId=secret_arn)
    assert restore_resp["ARN"] == secret_arn, (
        f"RestoreSecret must echo the secret's ARN {secret_arn!r}, got {restore_resp.get('ARN')!r}"
    )
    restored = _poll(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: d.get("DeletedDate") is None,
        timeout_s=60.0,
        interval_s=3.0,
        description="DescribeSecret to clear DeletedDate after RestoreSecret",
    )
    assert restored.get("DeletedDate") is None, (
        f"RestoreSecret must clear DeletedDate, got {restored.get('DeletedDate')!r}"
    )
    assert restored.get("RotationEnabled") is False, (
        f"RestoreSecret must NOT re-enable the rotation DeleteSecret turned off; "
        f"got RotationEnabled={restored.get('RotationEnabled')!r}"
    )
    assert "NextRotationDate" not in restored, (
        f"a restored secret must still have no scheduled rotation; got {restored.get('NextRotationDate')!r}"
    )
    assert restored.get("RotationLambdaARN") == fn_arn, (
        "the rotation function association must still be there for a later RotateSecret to resume; "
        f"got {restored.get('RotationLambdaARN')!r}"
    )

    # Control: the restored secret is not wedged -- its original value still reads back, and a
    # fresh RotateSecret can resume rotation. GetSecretValue's own consistency can lag
    # DescribeSecret's (which already reported DeletedDate cleared above), so tolerate a brief
    # "marked for deletion" refusal immediately after RestoreSecret.
    current = _poll_through(
        lambda: sm.get_secret_value(SecretId=secret_arn),
        tolerate_code="InvalidRequestException",
        timeout_s=60.0,
    )
    assert (current["VersionId"], current["SecretString"]) == (original_version, "original-credential"), (
        f"the restored secret must still serve its original value; got version={current['VersionId']!r} "
        f"value={current['SecretString']!r}"
    )
    _poll_ok(
        lambda: sm.rotate_secret(SecretId=secret_arn, RotationLambdaARN=fn_arn, RotateImmediately=False),
        timeout_s=90.0,
    )
    resumed = _poll(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: d.get("RotationEnabled") is True and d.get("NextRotationDate") is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description="a fresh RotateSecret after restore to re-enable rotation",
    )
    assert resumed["RotationEnabled"] is True, "a fresh RotateSecret after restore must be able to re-enable rotation"


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"waited {timeout_s}s for {description}; last observation: {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _poll_ok(fn, *, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDeniedException", "ValidationException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"call never succeeded through propagation: {exc}")
            time.sleep(3)


def _poll_through(fn, *, tolerate_code, timeout_s, interval_s=3.0):
    """Retry fn() only while it raises tolerate_code; any other error or an eventual success
    propagates normally."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != tolerate_code:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"call kept raising {tolerate_code} for {timeout_s}s: {exc}")
            time.sleep(interval_s)


def _create_rotation_role(ctx, secret_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-delrot-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-delrot-inline"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps({
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
                    "Resource": secret_arn,
                },
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "*",
                },
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Role"]["Arn"]


def _create_rotation_function(ctx, fn_name, role_arn, timeout_s: float = 90.0):
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _NOOP_LAMBDA_SOURCE)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.lambda_handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=30,
                Tags={"sim2real": CHECK},
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            last = exc
            time.sleep(3.0)
            continue
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
        lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        return resp["FunctionArn"]
    raise AssertionError(f"rotation function never became creatable: {last}")


def _reap_log_group(ctx, group, rounds=6, interval_s=8.0):
    """delete_function does not remove the log group, and a buffered stream can re-create it after
    a delete. Delete, then watch for reappearance; stop after two consecutive absent reads."""
    logs = ctx.client("logs")
    absent_in_a_row = 0
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=group)
            absent_in_a_row = 0
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            absent_in_a_row += 1
            if absent_in_a_row >= 2:
                return
        time.sleep(interval_s)
    raise RuntimeError(f"log group {group} kept reappearing after {rounds} delete rounds")


def _reap_secret(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
