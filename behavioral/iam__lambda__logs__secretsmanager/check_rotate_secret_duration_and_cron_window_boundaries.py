"""rotate-secret-duration-and-cron-window-boundaries."""
from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _teardown(undo, *not_found: str):
    """Run ``undo()``; a failed delete raises except on the resource's own not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _fingerprint(text: str) -> str:
    """A short digest for failure messages -- never put secret material in an assert."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _refusal(fn):
    """Call ``fn``; return its (Error.Code, Error.Message). Raise, naming it, on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


def _expect_refusal(fn, expected):
    """Call ``fn``; assert the raised (Error.Code, Error.Message) equals ``expected`` exactly."""
    got = _refusal(fn)
    assert got == expected, f"expected refusal {expected!r}, got {got!r}"


def _rotation_package() -> bytes:
    source = """
import boto3


def handler(event, context):
    sm = boto3.client("secretsmanager")
    secret_id, token, step = event["SecretId"], event["ClientRequestToken"], event["Step"]
    if step == "createSecret":
        try:
            sm.get_secret_value(SecretId=secret_id, VersionId=token, VersionStage="AWSPENDING")
        except sm.exceptions.ResourceNotFoundException:
            live = sm.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")
            sm.put_secret_value(SecretId=secret_id, ClientRequestToken=token,
                                 SecretString=live["SecretString"], VersionStages=["AWSPENDING"])
    elif step == "finishSecret":
        meta = sm.describe_secret(SecretId=secret_id)
        current = next(v for v, s in meta["VersionIdsToStages"].items() if "AWSCURRENT" in s)
        if current != token:
            sm.update_secret_version_stage(SecretId=secret_id, VersionStage="AWSCURRENT",
                                            MoveToVersionId=token, RemoveFromVersionId=current)
    # setSecret and testSecret: nothing external to update, so returning is the success signal.
"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _create_rotation_role(iam, role_name: str, ctx) -> str:
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        ),
        "NoSuchEntity",
    ))
    policy_name = "rotate-secret-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Resource": "*", "Action": [
            "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue",
            "secretsmanager:DescribeSecret", "secretsmanager:UpdateSecretVersionStage"]}],
    }))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"
    ))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_rotation_function(lam, func_name: str, role_arn: str, timeout_s: float) -> str:
    """CreateFunction, retried only while the new execution role has not propagated to Lambda."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(
                FunctionName=func_name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.handler", Code={"ZipFile": _rotation_package()},
                Timeout=30, Tags={"sim2real": CHECK},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"CreateFunction never succeeded (role propagation?): {last_exc}")


def _wait_function_active(lam, func_name: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=func_name)
        if cfg.get("State") in ("Active", "Failed"):
            return cfg
        if time.monotonic() >= deadline:
            raise AssertionError(f"the rotation function never left Pending: {cfg.get('State')!r}")
        time.sleep(2)


def _rotate_or_retry_on_propagation(sm, secret_arn: str, func_arn: str, rules: dict, timeout_s: float):
    """RotateSecret test-invokes the function; retried only while its invoke grant propagates."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sm.rotate_secret(
                SecretId=secret_arn, RotationLambdaARN=func_arn,
                RotationRules=rules, RotateImmediately=False,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException",):
                raise
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"RotateSecret never cleared the invoke grant: {last_exc}")


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0) -> None:
    """Delete a Lambda log group until several consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name!r} kept reappearing for {budget_s}s")
            time.sleep(interval_s)


CHECK = "rotate-secret-duration-and-cron-window-boundaries"
GROUP = "error-semantics"
SERVICES = ["iam", "lambda", "logs", "secretsmanager"]

_DURATION_EXCEEDS_RATE = (
    "InvalidParameterException", "Duration cannot be greater than Rate in hour."
)
_DURATION_OUT_OF_BOUNDS = (
    "InvalidParameterException", "Duration must be at least 1 hour, at most 24 hour."
)
_CRON_WINDOW_CROSSES_DAY = (
    "InvalidParameterException", "Starting hour and duration must be within a day."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """RotateSecret accepts a Duration equal to a rate() interval and a cron() window that stays
    inside one UTC day, and refuses a Duration over the interval, under one hour, or a cron()
    window that would cross into the next UTC day, each leaving RotationRules unchanged.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_schedule.html
    """
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    name = ctx.unique_name("sim2real-behav-rotwin-")
    original = "sim2real-rotation-window-original-value"
    created = sm.create_secret(
        Name=name, SecretString=original, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    v1 = created["VersionId"]
    ctx.on_cleanup(_teardown(
        lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True),
        "ResourceNotFoundException",
    ))

    role_name = ctx.unique_name("sim2real-behav-rotwin-role-")
    role_arn = _create_rotation_role(iam, role_name, ctx)

    func_name = ctx.unique_name("sim2real-behav-rotwin-fn-")
    # Registered before the function, so LIFO reaps the log group after the function is deleted.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{func_name}"))
    func_arn = _create_rotation_function(lam, func_name, role_arn, timeout_s=90.0)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=func_name), "ResourceNotFoundException"))
    active = _wait_function_active(lam, func_name, timeout_s=120.0)
    assert active.get("State") == "Active", (
        f"the rotation function never became Active: State={active.get('State')!r}, "
        f"reason={active.get('StateReason')!r}"
    )
    lam.add_permission(
        FunctionName=func_name, StatementId="allow-secretsmanager-invoke",
        Action="lambda:InvokeFunction", Principal="secretsmanager.amazonaws.com", SourceArn=secret_arn,
    )

    def _describe() -> dict:
        return sm.describe_secret(SecretId=secret_arn)

    def _assert_rules_are(schedule: str, duration: str) -> None:
        desc = _describe()
        rules = desc.get("RotationRules", {})
        assert rules.get("ScheduleExpression") == schedule, (
            f"expected ScheduleExpression {schedule!r} to be the stored rule, got {rules.get('ScheduleExpression')!r}"
        )
        assert rules.get("Duration") == duration, (
            f"expected Duration {duration!r} to be the stored rule, got {rules.get('Duration')!r}"
        )

    def _poll_rules_converge(schedule: str, duration: str, budget_s: float = 60.0) -> None:
        """An accepted RotateSecret call's rules become visible on a later read, not necessarily the next one."""
        deadline = time.monotonic() + budget_s
        last = None
        while True:
            last = _describe().get("RotationRules", {})
            if last.get("ScheduleExpression") == schedule and last.get("Duration") == duration:
                return
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"RotationRules never converged to schedule={schedule!r} duration={duration!r}, last {last!r}"
                )
            time.sleep(2)

    def _assert_unchanged_from(schedule: str, duration: str) -> None:
        _assert_rules_are(schedule, duration)
        value = sm.get_secret_value(SecretId=secret_arn)
        assert (value["VersionId"], _fingerprint(value["SecretString"])) == (v1, _fingerprint(original)), (
            "a refused call must not change which version is AWSCURRENT, nor its value"
        )

    # A Duration exactly equal to a rate() schedule's own interval fits the window: accepted.
    _rotate_or_retry_on_propagation(
        sm, secret_arn, func_arn, {"ScheduleExpression": "rate(4 hours)", "Duration": "4h"}, timeout_s=90.0
    )
    _poll_rules_converge("rate(4 hours)", "4h")

    # One hour past the rate's own interval: the window would spill into the next rotation.
    _expect_refusal(
        lambda: sm.rotate_secret(
            SecretId=secret_arn, RotationLambdaARN=func_arn,
            RotationRules={"ScheduleExpression": "rate(4 hours)", "Duration": "5h"},
            RotateImmediately=False,
        ),
        _DURATION_EXCEEDS_RATE,
    )
    _assert_unchanged_from("rate(4 hours)", "4h")

    # A zero-length window is below the one-hour floor, independent of the schedule's own interval.
    _expect_refusal(
        lambda: sm.rotate_secret(
            SecretId=secret_arn, RotationLambdaARN=func_arn,
            RotationRules={"ScheduleExpression": "rate(4 hours)", "Duration": "0h"},
            RotateImmediately=False,
        ),
        _DURATION_OUT_OF_BOUNDS,
    )
    _assert_unchanged_from("rate(4 hours)", "4h")

    # A cron() firing at 22:00 UTC with a 4-hour window would run past midnight into the next day.
    _expect_refusal(
        lambda: sm.rotate_secret(
            SecretId=secret_arn, RotationLambdaARN=func_arn,
            RotationRules={"ScheduleExpression": "cron(0 22 * * ? *)", "Duration": "4h"},
            RotateImmediately=False,
        ),
        _CRON_WINDOW_CROSSES_DAY,
    )
    _assert_unchanged_from("rate(4 hours)", "4h")

    # A cron() firing at 18:00 UTC with the same 4-hour window stays inside the UTC day: accepted.
    _rotate_or_retry_on_propagation(
        sm, secret_arn, func_arn, {"ScheduleExpression": "cron(0 18 * * ? *)", "Duration": "4h"}, timeout_s=90.0
    )
    _poll_rules_converge("cron(0 18 * * ? *)", "4h")

    # RotateImmediately=False throughout: AWSCURRENT must still be the original version and value.
    desc = _describe()
    current = [v for v, labels in desc["VersionIdsToStages"].items() if "AWSCURRENT" in labels]
    assert current == [v1], f"no accepted call here may promote a version; AWSCURRENT is {current!r}"
    value = sm.get_secret_value(SecretId=secret_arn)
    assert (value["VersionId"], _fingerprint(value["SecretString"])) == (v1, _fingerprint(original)), (
        "the secret's current version and value must be untouched by every call in this check"
    )

    sm.cancel_rotate_secret(SecretId=secret_arn)
    deadline = time.monotonic() + 30.0
    desc = _describe()
    while desc.get("RotationEnabled") is not False:
        if time.monotonic() >= deadline:
            raise AssertionError(f"RotationEnabled never cleared after CancelRotateSecret: {desc}")
        time.sleep(2)
        desc = _describe()

    sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    _NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
    deadline = time.monotonic() + 60.0
    last_seen = None
    while True:
        try:
            last_seen = _describe()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message"))
            assert got == _NOT_FOUND, f"expected the forced delete to end in {_NOT_FOUND!r}, got {got!r}"
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"describe_secret never refused after a forced delete; last response {last_seen!r}"
            )
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
