"""xsvc-rds-scheduler-stop-db-instance-denied-without-permission-reaches-rds-with-it."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-rds-scheduler-stop-db-instance-denied-without-permission-reaches-rds-with-it"
GROUP = "permission-boundary"
SERVICES = ["events", "rds", "scheduler"]

_TARGET = "arn:aws:scheduler:::aws-sdk:rds:stopDBInstance"
#: The at() instant's lead over the CreateSchedule call that carries it.
_FIRE_OFFSET_S = 30
_RETRY_POLICY = {"MaximumRetryAttempts": 1, "MaximumEventAgeInSeconds": 60}
_DELIVERY_TIMEOUT_S = 180
# RDS's query-protocol codes, not "AccessDeniedException" / "DBInstanceNotFoundFault".
_DENIED_CODE = "AccessDenied"
_NOT_FOUND_CODE = "DBInstanceNotFound"


# timing:real-time — schedule: 30 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """A Scheduler stopDBInstance schedule whose role lacks rds:StopDBInstance fires at its at()
    instant and is dead-lettered with IAM's AccessDenied; the same Input under a role allowed the
    action passes IAM and dead-letters with RDS's own DBInstanceNotFound for the absent instance.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
    """
    sch = ctx.client("scheduler")

    db_id = _xname(ctx, "db")
    dlq = _create_queue(ctx)
    control_dlq = _create_queue(ctx)
    denied_role = _create_role(ctx, [
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dlq["arn"]}])
    account = denied_role.split(":")[4]
    db_arn = f"arn:aws:rds:{ctx.region}:{account}:db:{db_id}"
    permitted_role = _create_role(ctx, [
        {"Effect": "Allow", "Action": "rds:StopDBInstance", "Resource": db_arn},
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": control_dlq["arn"]}])

    # CreateSchedule validates Input against the SDK shape: the RDS query spelling
    # "DBInstanceIdentifier" is rejected with ValidationException.
    target_input = json.dumps({"DbInstanceIdentifier": db_id})

    # CreateSchedule only checks that Scheduler can assume the role, so both outcomes surface at
    # fire time, after the at() instant.
    denied_sched, denied_nominal = _create_schedule(ctx, {
        "Arn": _TARGET, "RoleArn": denied_role, "Input": target_input,
        "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": dlq["arn"]}})
    permitted_sched, permitted_nominal = _create_schedule(ctx, {
        "Arn": _TARGET, "RoleArn": permitted_role, "Input": target_input,
        "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": control_dlq["arn"]}})
    _assert_before(denied_nominal)
    _assert_before(permitted_nominal)

    got = sch.get_schedule(Name=denied_sched)
    denied_arn = got["Arn"]
    expected_expr = f"at({denied_nominal.strftime('%Y-%m-%dT%H:%M:%S')})"
    assert got["ScheduleExpression"] == expected_expr, (
        f"GetSchedule echoes ScheduleExpression {got['ScheduleExpression']!r}, expected "
        f"{expected_expr!r}"
    )
    assert got["Target"]["RoleArn"] == denied_role and got["Target"]["Input"] == target_input, (
        f"GetSchedule echoes Target {got['Target']!r}; expected RoleArn {denied_role!r} and "
        f"Input {target_input!r}"
    )
    assert got["Target"]["RetryPolicy"] == _RETRY_POLICY, (
        f"GetSchedule echoes RetryPolicy {got['Target'].get('RetryPolicy')!r}, expected "
        f"{_RETRY_POLICY!r}"
    )
    permitted_arn = sch.get_schedule(Name=permitted_sched)["Arn"]

    dead = _await_message(ctx, dlq["url"], timeout_s=_FIRE_OFFSET_S + _DELIVERY_TIMEOUT_S,
                          description="the denied stopDBInstance reaching the schedule DLQ")
    arrived = datetime.datetime.now(datetime.timezone.utc)
    assert arrived >= denied_nominal, (
        f"the dead-letter arrived at {arrived.isoformat()}, before the at() instant "
        f"{denied_nominal.isoformat()}"
    )
    attrs = {k: v.get("StringValue") for k, v in (dead.get("MessageAttributes") or {}).items()}
    assert attrs.get("ERROR_CODE") == _DENIED_CODE, (
        f"ERROR_CODE is {attrs.get('ERROR_CODE')!r}, expected {_DENIED_CODE!r}; attrs {attrs!r}"
    )
    # message varies: the assumed-role session name is a per-invocation 32-hex id Scheduler mints
    # and exposes nowhere else (it is not EXECUTION_ID); every other part is asserted exactly.
    message = attrs.get("ERROR_MESSAGE") or ""
    expected_message = _expected_denial(db_arn, denied_role, _session_of(message, denied_role))
    assert message == expected_message, (
        f"ERROR_MESSAGE is {attrs.get('ERROR_MESSAGE')!r}, expected {expected_message!r}"
    )
    assert attrs.get("RETRY_ATTEMPTS") == "0", (
        f"RETRY_ATTEMPTS is {attrs.get('RETRY_ATTEMPTS')!r}; a non-retryable denial must spend 0"
    )
    assert attrs.get("SCHEDULE_ARN") == denied_arn, (
        f"SCHEDULE_ARN is {attrs.get('SCHEDULE_ARN')!r}, expected {denied_arn!r}"
    )
    assert attrs.get("TARGET_ARN") == _TARGET, (
        f"TARGET_ARN is {attrs.get('TARGET_ARN')!r}, expected {_TARGET!r}"
    )
    assert json.loads(dead["Body"]) == {"DbInstanceIdentifier": db_id}, (
        f"dead-letter body {dead['Body']!r} is not the schedule Input {target_input!r}"
    )

    # Positive control: the permitted role passes IAM, so RDS itself answers for the instance.
    ctrl = _await_message(ctx, control_dlq["url"],
                          timeout_s=_FIRE_OFFSET_S + _DELIVERY_TIMEOUT_S,
                          description="the permitted stopDBInstance reaching its DLQ")
    c_attrs = {k: v.get("StringValue") for k, v in (ctrl.get("MessageAttributes") or {}).items()}
    assert c_attrs.get("ERROR_CODE") == _NOT_FOUND_CODE, (
        f"permitted leg ERROR_CODE is {c_attrs.get('ERROR_CODE')!r}, expected "
        f"{_NOT_FOUND_CODE!r} -- the allowed call must pass IAM and reach RDS; attrs {c_attrs!r}"
    )
    expected_nf = f"DBInstance {db_id} not found."
    assert c_attrs.get("ERROR_MESSAGE") == expected_nf, (
        f"permitted leg ERROR_MESSAGE is {c_attrs.get('ERROR_MESSAGE')!r}, expected {expected_nf!r}"
    )
    assert c_attrs.get("SCHEDULE_ARN") == permitted_arn, (
        f"SCHEDULE_ARN is {c_attrs.get('SCHEDULE_ARN')!r}, expected {permitted_arn!r}"
    )

    # The control's arrival is the window a second letter for either leg had to arrive in.
    extra = _drain(ctx, dlq["url"], window_s=2.0)
    assert not extra, f"more than one dead-letter for one denial: {[m['Body'] for m in extra]!r}"
    c_extra = _drain(ctx, control_dlq["url"], window_s=2.0)
    assert not c_extra, (
        f"more than one dead-letter for one not-found: {[m['Body'] for m in c_extra]!r}")


def _fire_at() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + \
        datetime.timedelta(seconds=_FIRE_OFFSET_S)


def _assert_before(nominal: datetime.datetime) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    assert now < nominal, (
        f"setup overran the scheduled instant ({nominal.isoformat()} <= {now.isoformat()})"
    )


def _session_of(message: str, role_arn: str) -> str:
    """The session segment that follows this check's role name in the denial, required to be
    the 32 lowercase hex characters Scheduler mints per invocation."""
    marker = f":assumed-role/{role_arn.rsplit('/', 1)[-1]}/"
    session = message.split(marker, 1)[1].split(" ", 1)[0] if marker in message else ""
    assert len(session) == 32 and all(c in "0123456789abcdef" for c in session), (
        f"no 32-hex Scheduler session after {marker!r} in ERROR_MESSAGE {message!r}"
    )
    return session


def _expected_denial(db_arn: str, role_arn: str, session: str) -> str:
    """RDS's refusal of the schedule role's stopDBInstance call, built from the instance ARN, the
    role this check created and the invocation's session name."""
    account = db_arn.split(":")[4]
    role_name = role_arn.rsplit("/", 1)[-1]
    return (f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{session} is not authorized "
            f"to perform: rds:StopDBInstance on resource: {db_arn} because no identity-based "
            f"policy allows the rds:StopDBInstance action")


_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true"}
_ROLE_PROPAGATION_S = 90


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _create_queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(ctx, url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"]
    return {"url": url, "arn": arn}


def _delete_queue(ctx, url: str) -> None:
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
                "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            raise


def _create_role(ctx, statements: list) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    return arn


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pname)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _create_schedule(ctx, target: dict) -> tuple:
    """CreateSchedule assumes the role to validate it; retry the IAM-propagation
    ValidationException within a bound, each attempt at a fresh at() instant. Returns
    (name, nominal instant)."""
    sch = ctx.client("scheduler")
    name = _xname(ctx, "sched")
    deadline = time.monotonic() + _budget_s(ctx, _ROLE_PROPAGATION_S)
    while True:
        nominal = _fire_at()
        try:
            sch.create_schedule(
                Name=name, ScheduleExpression=f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})",
                ScheduleExpressionTimezone="UTC", FlexibleTimeWindow={"Mode": "OFF"},
                State="ENABLED", Target=target)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationException" \
                    or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name))
    return name, nominal


def _delete_schedule(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_message(ctx, url: str, *, timeout_s: float, description: str) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5,
                                   MessageAttributeNames=["All"]).get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: run budget ended before anything arrived")
    raise AssertionError(f"{description}: nothing arrived within {timeout_s:.0f}s")


def _drain(ctx, url: str, *, window_s: float) -> list:
    """Receive-and-delete everything visible for a bounded window."""
    sqs = ctx.client("sqs")
    out: list = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait = int(max(1, min(5, deadline - time.monotonic())))
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait,
                                     MessageAttributeNames=["All"]).get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
