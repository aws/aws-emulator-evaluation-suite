"""rotation-schedule-next-rotation-date-advances."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rotation-schedule-next-rotation-date-advances"
GROUP = "visibility-timeout-ttl"
SERVICES = ["secretsmanager"]

_NOOP_HANDLER = (
    "def lambda_handler(event, context):\n"
    "    return {'status': 'ok', 'step': event.get('Step')}\n"
)

_AUTOMATICALLY_AFTER_DAYS = 45


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After RotateSecret configures RotationRules.AutomaticallyAfterDays, DescribeSecret
    reports RotationEnabled=True and a NextRotationDate consistent with that interval
    (not just an arbitrary/absent value)."""
    sm = ctx.client("secretsmanager")
    lambda_arn = _deploy_noop_lambda(ctx)

    name = ctx.unique_name("sim2real-behav-rotdate-")
    sm.create_secret(Name=name, SecretString="s3cr3t-v1", Tags=_sim2real_tags(CHECK))
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    before = datetime.now(timezone.utc)
    sm.rotate_secret(
        SecretId=name,
        RotationLambdaARN=lambda_arn,
        RotationRules={"AutomaticallyAfterDays": _AUTOMATICALLY_AFTER_DAYS},
        RotateImmediately=False,
    )

    description = _poll_until(
        lambda: sm.describe_secret(SecretId=name),
        lambda d: d.get("RotationEnabled") and d.get("NextRotationDate") is not None,
        timeout_s=60.0,
        interval_s=3.0,
    )

    assert description["RotationEnabled"] is True
    assert description["RotationRules"]["AutomaticallyAfterDays"] == _AUTOMATICALLY_AFTER_DAYS

    next_rotation = description["NextRotationDate"]
    expected = before + timedelta(days=_AUTOMATICALLY_AFTER_DAYS)
    tolerance = timedelta(days=2)
    assert expected - tolerance <= next_rotation <= expected + tolerance, (
        f"NextRotationDate {next_rotation} not within {tolerance} of expected {expected} "
        f"for a {_AUTOMATICALLY_AFTER_DAYS}-day rotation interval"
    )


# ===== helpers =====

def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _sim2real_tags(scenario: str) -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": scenario},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _deploy_noop_lambda(ctx) -> str:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-sm-rotdate-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_sim2real_tags(CHECK),
    )["Role"]["Arn"]

    def _delete_role():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", _NOOP_HANDLER)

    fn_name = ctx.unique_name("sim2real-sm-rotdate-fn-")
    function_arn = None
    last_err = None
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=30,
                Publish=True,
                Tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )
            function_arn = resp["FunctionArn"]
            break
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(2)
    if function_arn is None:
        raise AssertionError(f"lambda never became creatable (IAM propagation?): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda state: state == "Active",
        timeout_s=60.0,
        interval_s=3.0,
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="secretsmanager-invoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceAccount=account_id,
    )
    return function_arn


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
