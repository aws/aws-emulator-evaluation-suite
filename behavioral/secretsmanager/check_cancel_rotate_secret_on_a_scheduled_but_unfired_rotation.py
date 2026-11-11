"""cancel-rotate-secret-on-a-scheduled-but-unfired-rotation."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-rotate-secret-on-a-scheduled-but-unfired-rotation"
GROUP = "rotation"
SERVICES = ["secretsmanager"]

_NOOP_LAMBDA_SOURCE = (
    "def lambda_handler(event, context):\n"
    "    print('SIM2REAL_STEP_CALLED ' + event.get('Step', '') + ' ' + event.get('ClientRequestToken', ''))\n"
    "    return {'ok': True, 'step': event.get('Step')}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CancelRotateSecret on a scheduled (RotateImmediately=False) but unfired rotation sets
    RotationEnabled False and clears NextRotationDate, keeping RotationLambdaARN and staging;
    a repeat cancel is a no-op and a fresh RotateSecret re-enables rotation.
    """
    sm = ctx.client("secretsmanager")

    secret_name = ctx.unique_name("sim2real-behav-cancelsched-")
    created = sm.create_secret(
        Name=secret_name, SecretString="original-credential",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    original_version = created["VersionId"]
    ctx.on_cleanup(lambda: _reap_secret(sm, secret_arn))

    fn_name = ctx.unique_name("sim2real-behav-cancelsched-fn-")
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
    assert scheduled.get("NextRotationDate") is not None, "setup must have a scheduled NextRotationDate"
    assert scheduled["RotationLambdaARN"] == fn_arn, "setup must record the rotation function"

    # With RotateImmediately=False, RotateSecret runs an async testSecret invocation that briefly
    # labels a candidate version; wait for it so the cancel does not race it.
    _poll(
        lambda: _logged_steps(ctx, fn_name),
        lambda steps: "testSecret" in steps,
        timeout_s=120.0,
        interval_s=4.0,
        description="RotateSecret's deferred test invocation to run and log testSecret",
    )
    settled = _poll(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: d["VersionIdsToStages"] == {original_version: ["AWSCURRENT"]},
        timeout_s=60.0,
        interval_s=3.0,
        description="the test invocation's candidate version to settle back to just AWSCURRENT",
    )
    assert settled["VersionIdsToStages"] == {original_version: ["AWSCURRENT"]}, (
        f"the staging map must settle back to just AWSCURRENT before cancelling; got {settled['VersionIdsToStages']!r}"
    )

    resp = sm.cancel_rotate_secret(SecretId=secret_arn)
    assert resp["ARN"] == secret_arn, f"CancelRotateSecret must echo the ARN {secret_arn!r}, got {resp.get('ARN')!r}"
    assert resp["Name"] == secret_name, f"CancelRotateSecret must echo the Name {secret_name!r}, got {resp.get('Name')!r}"

    cancelled = sm.describe_secret(SecretId=secret_arn)
    assert cancelled.get("RotationEnabled") is False, (
        f"CancelRotateSecret must disable a scheduled-but-unfired rotation; "
        f"got RotationEnabled={cancelled.get('RotationEnabled')!r}"
    )
    assert "NextRotationDate" not in cancelled, (
        f"CancelRotateSecret must clear the NextRotationDate it never fired; "
        f"got {cancelled.get('NextRotationDate')!r}"
    )
    assert cancelled.get("RotationLambdaARN") == fn_arn, (
        f"CancelRotateSecret must leave the rotation function association so a later RotateSecret "
        f"can resume it; got {cancelled.get('RotationLambdaARN')!r}"
    )
    assert "LastRotatedDate" not in cancelled, (
        f"a cancelled-before-it-fired rotation must never have rotated; "
        f"got LastRotatedDate={cancelled.get('LastRotatedDate')!r}"
    )
    stages = cancelled["VersionIdsToStages"]
    assert stages == {original_version: ["AWSCURRENT"]}, (
        f"cancelling an unfired schedule must leave the staging map untouched; got {stages!r}"
    )
    current = sm.get_secret_value(SecretId=secret_arn)
    assert (current["VersionId"], current["SecretString"]) == (original_version, "original-credential"), (
        f"cancelling an unfired schedule must not change the current value; "
        f"got version={current['VersionId']!r} value={current['SecretString']!r}"
    )

    # Control: a second CancelRotateSecret while already disabled is a tolerated no-op.
    # DescribeSecret can lag the call by a moment, so poll rather than reading once.
    resp2 = sm.cancel_rotate_secret(SecretId=secret_arn)
    assert resp2["ARN"] == secret_arn, "a redundant CancelRotateSecret must still succeed and echo the ARN"
    still = _poll(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: d.get("RotationEnabled") is False,
        timeout_s=60.0,
        interval_s=3.0,
        description="DescribeSecret to keep reporting RotationEnabled=False after a redundant cancel",
    )
    assert still.get("RotationEnabled") is False, "a redundant cancel must not turn rotation back on"

    # Control: the secret is not wedged -- a fresh RotateSecret can resume the schedule.
    _poll_ok(
        lambda: sm.rotate_secret(SecretId=secret_arn, RotationLambdaARN=fn_arn, RotateImmediately=False),
        timeout_s=90.0,
    )
    resumed = _poll(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: d.get("RotationEnabled") is True and d.get("NextRotationDate") is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description="a fresh RotateSecret after cancel to re-enable rotation",
    )
    assert resumed["RotationEnabled"] is True, "a fresh RotateSecret after cancel must be able to re-enable rotation"


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


def _logged_steps(ctx, fn_name):
    logs = ctx.client("logs")
    seen, token = set(), None
    while True:
        kwargs = {"logGroupName": f"/aws/lambda/{fn_name}", "filterPattern": '"SIM2REAL_STEP_CALLED"'}
        if token:
            kwargs["nextToken"] = token
        try:
            resp = logs.filter_log_events(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return seen
            raise
        for e in resp.get("events", []):
            seen.add(e["message"].split("SIM2REAL_STEP_CALLED ", 1)[1].split(" ", 1)[0].strip())
        token = resp.get("nextToken")
        if not token:
            return seen


def _create_rotation_role(ctx, secret_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cancelsched-role-")
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
    policy_name = "sim2real-cancelsched-inline"
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
    """Delete the function's log group until two consecutive reads find it absent.

    delete_function leaves the log group, and buffered logs can re-create it after a delete."""
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
