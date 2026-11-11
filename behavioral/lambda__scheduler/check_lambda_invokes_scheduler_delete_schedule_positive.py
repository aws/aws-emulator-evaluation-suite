"""lambda-invokes-scheduler-delete-schedule-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-invokes-scheduler-delete-schedule-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "scheduler"]

_HANDLER_CODE = """
import json
import boto3

def handler(event, context):
    action = event["action"]
    params = event.get("params", {})
    client = boto3.client("scheduler")
    try:
        result = getattr(client, action)(**params)
        result.pop("ResponseMetadata", None)
        clean = json.loads(json.dumps(result, default=str))
        return {"ok": True, "result": clean}
    except Exception as exc:
        resp = getattr(exc, "response", {}) or {}
        error = resp.get("Error", {}) or {}
        code = error.get("Code", type(exc).__name__)
        return {"ok": False, "error_code": code, "error_message": str(exc)}
"""

_LAMBDA_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_SCHEDULER_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A schedule confirmed present via get_schedule is then deleted by a Lambda handler
    calling scheduler.delete_schedule, and its removal is confirmed absent via subsequent
    list_schedules (and a direct get_schedule 404)."""
    target = _create_scheduler_target(ctx)
    scheduler = ctx.client("scheduler")
    schedule_name = ctx.unique_name("sim2real-sched-")
    scheduler.create_schedule(
        Name=schedule_name,
        ScheduleExpression="rate(1 day)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": target["target_arn"], "RoleArn": target["role_arn"]},
    )
    got_before = scheduler.get_schedule(Name=schedule_name)
    assert got_before["Name"] == schedule_name, (
        f"positive control failed: schedule {schedule_name} not visible right after create: {got_before}"
    )

    role_arn = _create_lambda_role(
        ctx,
        statements=[{"Effect": "Allow", "Action": "scheduler:DeleteSchedule", "Resource": "*"}],
    )
    fn_name = _create_lambda_function(ctx, role_arn)

    out = _invoke_lambda(ctx, fn_name, {"action": "delete_schedule", "params": {"Name": schedule_name}})
    assert out["ok"] is True, f"delete_schedule via lambda failed: {out}"

    def _absent() -> bool:
        names = [s["Name"] for s in scheduler.list_schedules(NamePrefix=schedule_name).get("Schedules", [])]
        return schedule_name not in names

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if _absent():
            break
        time.sleep(2)
    else:
        raise AssertionError(f"schedule {schedule_name} still listed after delete via lambda")

    code, message = _expect_error(lambda: scheduler.get_schedule(Name=schedule_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted schedule {schedule_name}, got {code!r}"
    )
    expected_message = f"Schedule {schedule_name} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _expect_error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _make_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lam-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if statements:
        policy_name = ctx.unique_name("sim2real-lam-pol-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn: str, handler_code: str = _HANDLER_CODE) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-lam-fn-")
    zip_bytes = _make_zip(handler_code)
    last_err: Exception | None = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_for_active(ctx, fn_name)
    return fn_name


def _wait_for_active(ctx, fn_name: str) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=fn_name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda function {fn_name} never became Active")


def _invoke_lambda(ctx, fn_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation crashed: {body}")
    return body


def _create_scheduler_target(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-sched-tgt-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SCHEDULER_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    _wait_for_scheduler_role_ready(ctx, queue_arn, role_arn)
    return {"target_arn": queue_arn, "role_arn": role_arn}


def _wait_for_scheduler_role_ready(ctx, target_arn: str, role_arn: str) -> None:
    """EventBridge Scheduler validates the target role's trust policy synchronously when
    CreateSchedule is called; IAM role propagation can lag a few seconds, so probe with a
    throwaway schedule until the role is accepted."""
    scheduler = ctx.client("scheduler")
    probe_name = ctx.unique_name("sim2real-sched-probe-")
    deadline = time.monotonic() + 60
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            scheduler.create_schedule(
                Name=probe_name,
                ScheduleExpression="rate(1 day)",
                FlexibleTimeWindow={"Mode": "OFF"},
                Target={"Arn": target_arn, "RoleArn": role_arn},
            )
            scheduler.delete_schedule(Name=probe_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ValidationException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"scheduler target role never became usable: {last_err}")


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
