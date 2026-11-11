"""lambda-scheduler-update-schedule-group-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-scheduler-update-schedule-group-positive"
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A schedule created in a new group lives there (not in default); UpdateSchedule edits it in
    place, and an update omitting GroupName misses it with ResourceNotFoundException rather than
    moving it.
    """
    target = _create_scheduler_target(ctx)
    role_arn = _create_lambda_role(
        ctx,
        statements=[
            {"Effect": "Allow", "Action": "scheduler:CreateScheduleGroup", "Resource": "*"},
            {"Effect": "Allow", "Action": "scheduler:CreateSchedule", "Resource": "*"},
            {"Effect": "Allow", "Action": "scheduler:UpdateSchedule", "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": target["role_arn"]},
        ],
    )
    fn_name = _create_lambda_function(ctx, role_arn)

    group_name = ctx.unique_name("sim2real-schedgrp-")
    schedule_name = ctx.unique_name("sim2real-sched-")
    scheduler = ctx.client("scheduler")

    out_group = _invoke_lambda(ctx, fn_name, {"action": "create_schedule_group", "params": {"Name": group_name}})
    assert out_group["ok"] is True, f"create_schedule_group via lambda failed: {out_group}"
    ctx.on_cleanup(lambda: scheduler.delete_schedule_group(Name=group_name))

    out_sched = _invoke_lambda_eventual(
        ctx,
        fn_name,
        {
            "action": "create_schedule",
            "params": {
                "Name": schedule_name,
                "GroupName": group_name,
                "ScheduleExpression": "rate(1 hour)",
                "FlexibleTimeWindow": {"Mode": "OFF"},
                "Target": {"Arn": target["target_arn"], "RoleArn": target["role_arn"]},
            },
        },
    )
    assert out_sched["ok"] is True, f"create_schedule via lambda failed: {out_sched}"
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=schedule_name, GroupName=group_name))

    got = scheduler.get_schedule(Name=schedule_name, GroupName=group_name)
    assert got["GroupName"] == group_name, f"expected schedule in group {group_name!r}, got: {got}"

    # the schedule must NOT be visible in the default group
    default_names = [s["Name"] for s in scheduler.list_schedules(NamePrefix=schedule_name, GroupName="default").get("Schedules", [])]
    assert schedule_name not in default_names, f"{schedule_name!r} unexpectedly visible in the default group: {default_names}"

    out_update = _invoke_lambda(
        ctx,
        fn_name,
        {
            "action": "update_schedule",
            "params": {
                "Name": schedule_name,
                "GroupName": group_name,
                "ScheduleExpression": "rate(2 hours)",
                "FlexibleTimeWindow": {"Mode": "OFF"},
                "Target": {"Arn": target["target_arn"], "RoleArn": target["role_arn"]},
            },
        },
    )
    assert out_update["ok"] is True, f"update_schedule within {group_name!r} failed: {out_update}"
    updated = scheduler.get_schedule(Name=schedule_name, GroupName=group_name)
    assert updated["ScheduleExpression"] == "rate(2 hours)", (
        f"expected the update to take effect, got: {updated}"
    )
    assert updated["GroupName"] == group_name, f"update_schedule must not move the group, got: {updated}"

    # GroupName is part of update_schedule's identity, not a "move" parameter: omitting it
    # defaults to "default", where this schedule does not live, so the call must miss it
    # rather than silently relocating or updating it.
    out_move = _invoke_lambda(
        ctx,
        fn_name,
        {
            "action": "update_schedule",
            "params": {
                "Name": schedule_name,
                "ScheduleExpression": "rate(3 hours)",
                "FlexibleTimeWindow": {"Mode": "OFF"},
                "Target": {"Arn": target["target_arn"], "RoleArn": target["role_arn"]},
            },
        },
    )
    assert out_move["ok"] is False, (
        f"expected update_schedule with no GroupName to miss a schedule living in "
        f"{group_name!r} (it defaults to the 'default' group), got: {out_move}"
    )
    assert out_move["error_code"] == "ResourceNotFoundException", out_move
    unmoved = scheduler.get_schedule(Name=schedule_name, GroupName=group_name)
    assert unmoved["ScheduleExpression"] == "rate(2 hours)", (
        f"the failed default-group update must not have touched the real schedule, got: {unmoved}"
    )


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


def _invoke_lambda_eventual(ctx, fn_name: str, payload: dict[str, Any], timeout: float = 45.0) -> dict[str, Any]:
    """Retry an invoke while the handler reports AccessDeniedException: newly attached IAM
    role policies on the Lambda execution role can take a few seconds to propagate, so the
    first invocation right after create_function may still see stale permissions."""
    deadline = time.monotonic() + timeout
    out: dict[str, Any] = {"ok": False, "error_code": "Unknown"}
    while time.monotonic() < deadline:
        out = _invoke_lambda(ctx, fn_name, payload)
        if out.get("ok") or out.get("error_code") != "AccessDeniedException":
            return out
        time.sleep(3)
    return out


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
    """Delete the log group Lambda creates on a function's first log line, if it exists."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
