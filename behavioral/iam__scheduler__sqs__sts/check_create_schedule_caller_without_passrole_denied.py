"""create-schedule-caller-without-passrole-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-caller-without-passrole-denied"
GROUP = "overly-permissive"
SERVICES = ["iam", "scheduler", "sqs", "sts"]

_SESSION = "sim2real-sched-passrole-probe"
_PROPAGATION_DEADLINE_S = 120


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchedule requires the caller to hold iam:PassRole on the execution role being passed;
    a caller with scheduler:CreateSchedule but no iam:PassRole on that role is denied, while an
    identical caller whose policy also grants iam:PassRole succeeds."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sqs = ctx.client("sqs")

    target_queue_arn = _create_queue(ctx, sqs)
    exec_role_arn, exec_role_name = _create_execution_role(ctx, iam, target_queue_arn)

    denied_caller_arn, denied_session = _create_caller_role(
        ctx, iam, sts, "noperm", _create_schedule_statement()
    )
    granted_caller_arn, granted_session = _create_caller_role(
        ctx, iam, sts, "withperm",
        _create_schedule_statement() + [_pass_role_statement(exec_role_arn)],
    )

    denied_scheduler = _client_as(ctx, denied_session)
    denied_name = ctx.unique_name("sim2real-sched-denied-")
    partition = denied_caller_arn.split(":")[1]
    denied_principal = (
        f"arn:{partition}:sts::{ctx.account}:assumed-role/{denied_caller_arn.rsplit('/', 1)[-1]}/{_SESSION}"
    )
    schedule_arn = f"arn:{partition}:scheduler:{ctx.region}:{ctx.account}:schedule/default/{denied_name}"
    grant_not_yet = (
        "AccessDeniedException",
        f"User: {denied_principal} is not authorized to perform: scheduler:CreateSchedule on resource: "
        f"{schedule_arn} because no identity-based policy allows the scheduler:CreateSchedule action",
    )
    error = _error_response(
        {_SESSION_NOT_YET, grant_not_yet},
        lambda: denied_scheduler.create_schedule(
            Name=denied_name,
            ScheduleExpression="rate(1 hour)",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="DISABLED",
            Target={"Arn": target_queue_arn, "RoleArn": exec_role_arn},
        )
    )
    assert error is not None, "expected CreateSchedule to be denied without iam:PassRole"
    assert error["Error"]["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got {error['Error']['Code']!r}: "
        f"{error['Error'].get('Message')!r}"
    )
    expected_message = (
        f"User: {denied_principal} is not authorized to perform: iam:PassRole on resource: {exec_role_arn} "
        "because no identity-based policy allows the iam:PassRole action"
    )
    assert error["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error['Error'].get('Message')!r}"
    )

    sched_control = ctx.client("scheduler")
    names = {
        s["Name"]
        for page in sched_control.get_paginator("list_schedules").paginate()
        for s in page["Schedules"]
    }
    assert denied_name not in names, (
        f"a schedule named {denied_name!r} exists despite the denied CreateSchedule call"
    )

    granted_scheduler = _client_as(ctx, granted_session)
    granted_name = ctx.unique_name("sim2real-sched-granted-")
    _create_schedule_retrying(
        ctx,
        granted_scheduler,
        Name=granted_name,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": target_queue_arn, "RoleArn": exec_role_arn},
    )

    got = sched_control.get_schedule(Name=granted_name)
    assert got["Target"]["RoleArn"] == exec_role_arn, (
        f"the granted caller's schedule has RoleArn {got['Target']['RoleArn']!r}, "
        f"expected {exec_role_arn!r}"
    )


def _create_queue(ctx, sqs) -> str:
    name = ctx.unique_name("sim2real-sched-passrole-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_execution_role(ctx, iam, queue_arn: str) -> tuple[str, str]:
    """The role EventBridge Scheduler assumes to invoke the target; its own permissions are
    irrelevant here since the probe calls never reach invocation time."""
    name = ctx.unique_name("sim2real-sched-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="exec",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}
        ),
    )
    return arn, name


def _create_schedule_statement() -> list:
    return [{"Effect": "Allow", "Action": ["scheduler:CreateSchedule", "scheduler:GetSchedule"], "Resource": "*"}]


def _pass_role_statement(role_arn: str) -> dict:
    return {
        "Effect": "Allow",
        "Action": "iam:PassRole",
        "Resource": role_arn,
        "Condition": {"StringEquals": {"iam:PassedToService": "scheduler.amazonaws.com"}},
    }


def _create_caller_role(ctx, iam, sts, tag: str, statements: list) -> tuple[str, dict]:
    """A dedicated role the runner's own credentials may assume (trusted by this account's root), carrying exactly `statements`."""
    name = ctx.unique_name(f"sim2real-sched-caller-{tag}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.put_role_policy(
        RoleName=name, PolicyName="probe", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements})
    )
    return arn, _assume(sts, arn)


def _assume(sts, role_arn: str) -> dict:
    """Fresh credentials for `role_arn`. A new role's trust exposes no condition to poll; the
    bounded AccessDenied retry at first use is what makes this correct."""
    deadline = time.monotonic() + _PROPAGATION_DEADLINE_S
    while True:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _client_as(ctx, creds: dict):
    return ctx.client(
        "scheduler",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


_SESSION_NOT_YET = ("UnrecognizedClientException", "The security token included in the request is invalid.")


def _error_response(transient: set, fn):
    """The error response fn() raises, retrying only while the refusal is one of the exact
    `transient` (code, message) pairs of a not-yet-propagated session or grant."""
    deadline = time.monotonic() + _PROPAGATION_DEADLINE_S
    while True:
        try:
            fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) in transient and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return exc.response
        return None


def _create_schedule_retrying(ctx, scheduler, **kwargs) -> None:
    """A freshly-assumed role's session can briefly read as UnrecognizedClientException, and the
    role's own IAM grant can lag; retry past both within a bound."""
    name = kwargs["Name"]
    deadline = time.monotonic() + _PROPAGATION_DEADLINE_S
    while True:
        try:
            scheduler.create_schedule(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("UnrecognizedClientException", "AccessDeniedException") or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name))


def _delete_schedule(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_role(iam, name: str) -> None:
    for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=name, PolicyName=pname)
    iam.delete_role(RoleName=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
