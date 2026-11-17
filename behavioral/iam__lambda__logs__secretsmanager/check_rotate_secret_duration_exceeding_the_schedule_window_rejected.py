"""rotate-secret-duration-exceeding-the-schedule-window-rejected."""
from __future__ import annotations

import datetime
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except on its not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _digest(text: str) -> str:
    """Short digest for diagnostics -- never put secret material in an assert message."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _call(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _expect_error(fn, expected):
    """Call fn(); assert it raises exactly the (Error.Code, Error.Message) pair ``expected``."""
    got = _call(fn)
    assert got == expected, f"expected refusal {expected!r}, got {got!r}"


def _zip_bytes(source: str, filename: str = "lambda_function.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _create_function_with_retry(lam, func_name, role_arn, code_bytes, timeout_s, ctx):
    """CreateFunction, retried only while the new execution role has not propagated."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(
                FunctionName=func_name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.handler", Code={"ZipFile": code_bytes}, Timeout=30,
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"CreateFunction never succeeded (role propagation?): {last_exc}")


def _wait_active(lam, func_name, timeout_s):
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=func_name)
        if cfg.get("State") in ("Active", "Failed"):
            return cfg
        if time.monotonic() >= deadline:
            raise AssertionError(f"the rotation function never left Pending: {cfg.get('State')!r}")
        time.sleep(2)


def _rotate_with_retry(sm, secret_arn, func_arn, rules, timeout_s):
    """RotateSecret test-invokes the Lambda; retried only while its role or invoke grant propagates."""
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
            if code not in ("AccessDeniedException", "ValidationException"):
                raise
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"RotateSecret never succeeded (Lambda/role propagation?): {last_exc}")


def _delete_log_group(ctx, group, appear_s=20, timeout_s=30, quiet_s=10):
    """Delete the function's log group and keep it deleted: a late log batch can recreate it."""
    logs = ctx.client("logs")

    def _present():
        return any(g.get("logGroupName") == group for g in
                   logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", []))

    appear_deadline = time.monotonic() + appear_s
    while not _present():
        if time.monotonic() >= appear_deadline:
            return
        time.sleep(3)
    deadline = time.monotonic() + timeout_s
    absent_since = None
    while True:
        if _present():
            absent_since = None
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        elif absent_since is None:
            absent_since = time.monotonic()
        elif time.monotonic() - absent_since >= quiet_s:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"log group {group!r} kept reappearing for {timeout_s}s")
        time.sleep(3)


CHECK = "rotate-secret-duration-exceeding-the-schedule-window-rejected"
GROUP = "error-semantics"
SERVICES = ["iam", "lambda", "logs", "secretsmanager"]

_DURATION_EXCEEDS_RATE = (
    "InvalidParameterException", "Duration cannot be greater than Rate in hour."
)
_DURATION_EXCEEDS_DAY = (
    "InvalidParameterException", "Duration must be at least 1 hour, at most 24 hour."
)

# A rotation function that implements the four-step contract without touching any external system.
_ROTATION_LAMBDA_SOURCE = """
import boto3


def handler(event, context):
    client = boto3.client("secretsmanager")
    arn, token, step = event["SecretId"], event["ClientRequestToken"], event["Step"]
    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            current = client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
            client.put_secret_value(SecretId=arn, ClientRequestToken=token,
                                    SecretString=current["SecretString"], VersionStages=["AWSPENDING"])
    elif step == "finishSecret":
        meta = client.describe_secret(SecretId=arn)
        current = next(v for v, s in meta["VersionIdsToStages"].items() if "AWSCURRENT" in s)
        if current != token:
            client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT",
                                               MoveToVersionId=token, RemoveFromVersionId=current)
"""


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """RotateSecret refuses a Duration longer than a rate() schedule's own interval, and a Duration
    past the 24-hour window of a days-based schedule, each with InvalidParameterException and the
    stored rules unchanged; a Duration inside a rate() interval succeeds and round-trips.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_RotationRulesType.html
    """
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    name = ctx.unique_name("sim2real-behav-rotdur-")
    original = "sim2real-not-a-real-secret-v1"
    created = sm.create_secret(
        Name=name, SecretString=original, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    v1 = created["VersionId"]
    ctx.on_cleanup(_teardown(
        lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True),
        "ResourceNotFoundException",
    ))

    def _assert_refused_cleanly() -> None:
        desc = sm.describe_secret(SecretId=secret_arn)
        assert not desc.get("RotationEnabled", False), (
            f"a refused call must not enable rotation, got RotationEnabled={desc.get('RotationEnabled')!r}"
        )
        assert not desc.get("RotationRules"), (
            f"a refused call must not persist RotationRules, got {desc.get('RotationRules')}"
        )
        assert "NextRotationDate" not in desc, (
            f"a refused call must not schedule one; response keys were {sorted(desc)}"
        )
        stages = desc["VersionIdsToStages"]
        assert set(stages) == {v1} and set(stages[v1]) == {"AWSCURRENT"}, (
            f"the version map must stay at exactly v1=AWSCURRENT, got {stages}"
        )
        value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
        assert _digest(value) == _digest(original), "the secret material must be untouched by a refusal"

    # A rate() schedule's own interval bounds Duration: 20h cannot fit inside a 4-hour rate.
    _expect_error(
        lambda: sm.rotate_secret(
            SecretId=secret_arn, RotationRules={"ScheduleExpression": "rate(4 hours)", "Duration": "20h"}
        ),
        _DURATION_EXCEEDS_RATE,
    )
    _assert_refused_cleanly()

    # A days-based schedule's window cannot extend past one UTC day (24h).
    _expect_error(
        lambda: sm.rotate_secret(
            SecretId=secret_arn, RotationRules={"AutomaticallyAfterDays": 5, "Duration": "25h"}
        ),
        _DURATION_EXCEEDS_DAY,
    )
    _assert_refused_cleanly()

    # Positive control: a Duration that fits inside the rate() interval clears validation,
    # and with a working rotation function configured the call actually succeeds.
    role_name = ctx.unique_name("sim2real-behav-rotdur-role-")
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
    policy_name = "rotation-duration-inline-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Resource": secret_arn, "Action": [
                "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue",
                "secretsmanager:DescribeSecret", "secretsmanager:UpdateSecretVersionStage"]},
            {"Effect": "Allow", "Resource": "*", "Action": [
                "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]},
        ],
    }))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"
    ))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    func_name = ctx.unique_name("sim2real-behav-rotdur-fn-")
    # Registered before the function, so LIFO reaps the log group after the function is deleted.
    ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{func_name}"))
    func_arn = _create_function_with_retry(
        lam, func_name, role_arn, _zip_bytes(_ROTATION_LAMBDA_SOURCE), timeout_s=90.0, ctx=ctx
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=func_name), "ResourceNotFoundException"))
    active = _wait_active(lam, func_name, timeout_s=120.0)
    assert active.get("State") == "Active", (
        f"the rotation function never became Active: State={active.get('State')!r}, "
        f"reason={active.get('StateReason')!r}"
    )
    lam.add_permission(
        FunctionName=func_name, StatementId="allow-secretsmanager-invoke",
        Action="lambda:InvokeFunction", Principal="secretsmanager.amazonaws.com", SourceArn=secret_arn,
    )

    rules = {"ScheduleExpression": "rate(4 hours)", "Duration": "3h"}
    called_at = datetime.datetime.now(datetime.timezone.utc)
    _rotate_with_retry(sm, secret_arn, func_arn, rules, timeout_s=90.0)

    deadline = time.monotonic() + 60.0
    desc = sm.describe_secret(SecretId=secret_arn)
    while not (desc.get("RotationEnabled") is True and "NextRotationDate" in desc):
        if time.monotonic() >= deadline:
            raise AssertionError(f"RotationEnabled/NextRotationDate never appeared; last {desc}")
        time.sleep(2)
        desc = sm.describe_secret(SecretId=secret_arn)

    assert desc["RotationEnabled"] is True, f"expected RotationEnabled True, got {desc.get('RotationEnabled')!r}"
    assert desc["RotationLambdaARN"] == func_arn, (
        f"expected RotationLambdaARN {func_arn!r}, got {desc.get('RotationLambdaARN')!r}"
    )
    got_rules = desc.get("RotationRules", {})
    assert got_rules.get("ScheduleExpression") == "rate(4 hours)", (
        f"expected ScheduleExpression 'rate(4 hours)' to round-trip, got {got_rules.get('ScheduleExpression')!r}"
    )
    assert got_rules.get("Duration") == "3h", (
        f"expected Duration '3h' to round-trip, got {got_rules.get('Duration')!r}"
    )
    next_rotation = desc["NextRotationDate"].astimezone(datetime.timezone.utc)
    assert called_at < next_rotation <= called_at + datetime.timedelta(days=1, hours=1), (
        f"expected NextRotationDate within a day of the accepted call, got {next_rotation.isoformat()} "
        f"for a call at {called_at.isoformat()}"
    )

    # RotateImmediately=False: AWSCURRENT stays on the original version and value.
    stages = sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
    current = [v for v, labels in stages.items() if "AWSCURRENT" in labels]
    assert current == [v1], f"a deferred rotation must leave AWSCURRENT on {v1!r}, got {current!r}"
    value = sm.get_secret_value(SecretId=secret_arn)
    assert (value["VersionId"], _digest(value["SecretString"])) == (v1, _digest(original)), (
        "a deferred rotation must not change the current version or value"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
