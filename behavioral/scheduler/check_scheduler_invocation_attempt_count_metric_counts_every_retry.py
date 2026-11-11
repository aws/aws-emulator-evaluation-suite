"""scheduler-invocation-attempt-count-metric-counts-every-retry."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-invocation-attempt-count-metric-counts-every-retry"
GROUP = "server-side"
SERVICES = ["scheduler"]

_FIRE_OFFSET_S = 120
_MAX_RETRY_ATTEMPTS = 2
# Loose so event age is never the binding bound. The valid range is [60, 86400].
_MAX_EVENT_AGE_S = 900
_DELIVERY_TIMEOUT_S = 300
_DLQ_TIMEOUT_S = 300
_METRIC_TIMEOUT_S = 420
# `_FREEZE_READS` consecutive reads this far apart must agree before the exact counts are asserted,
# so a partially-published minute is not read as a final count.
_METRIC_SETTLE_S = 30
_FREEZE_READS = 3

_NAMESPACE = "AWS/Scheduler"


# timing:real-time — schedule: 120 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/monitoring-cloudwatch.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "concern:metrics", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A healthy and a permanently denied one-time schedule, in separate groups, publish exact
    AWS/Scheduler counts: attempts 1 and 1 (AccessDenied is not retried), target errors 0 and 1,
    dropped 0 and 1, and 1 dead-lettered.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/monitoring-cloudwatch.html
    """
    cw = ctx.client("cloudwatch")
    sch = ctx.client("scheduler")

    queue_ok = _create_queue(ctx, "sim2real-behav-sched-metric-ok-")
    queue_err = _create_queue(ctx, "sim2real-behav-sched-metric-err-")
    dlq = _create_queue(ctx, "sim2real-behav-sched-metric-dlq-")

    # One role for both schedules: it may send to the healthy queue and to the DLQ, and is
    # deliberately NOT granted sqs:SendMessage on queue_err. So the failing arm fails for exactly
    # one reason, and the dead-letter delivery itself still succeeds.
    role_arn = _scheduler_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": [queue_ok["arn"], dlq["arn"]],
            }
        ],
    )

    group_ok = _create_group(ctx, "sim2real-behav-sched-grp-ok-")
    group_err = _create_group(ctx, "sim2real-behav-sched-grp-err-")

    # Anchor the instant AFTER provisioning: IAM propagation can hold CreateSchedule off, and an
    # at() instant computed before that could already be in the past when the call is accepted.
    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    nominal = datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0
    ) + datetime.timedelta(seconds=_FIRE_OFFSET_S)
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"

    marker_ok = ctx.unique_name("ok-")
    name_ok = _create_schedule(
        ctx,
        GroupName=group_ok,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue_ok["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker_ok}),
        },
    )
    name_err = _create_schedule(
        ctx,
        GroupName=group_err,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue_err["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": ctx.unique_name("err-")}),
            "RetryPolicy": {
                "MaximumRetryAttempts": _MAX_RETRY_ATTEMPTS,
                "MaximumEventAgeInSeconds": _MAX_EVENT_AGE_S,
            },
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        },
    )

    # Both occurrences must have actually happened before any metric can be expected. The healthy
    # delivery is read off the real queue; the failing one is read off its DLQ, which proves the
    # retry policy was exhausted rather than still in flight.
    delivered = _await_body(
        ctx,
        queue_ok["url"],
        lambda b: b.get("marker") == marker_ok,
        timeout_s=_DELIVERY_TIMEOUT_S,
        description=f"the healthy schedule {name_ok} in group {group_ok}",
    )
    assert delivered["marker"] == marker_ok, (
        f"the healthy schedule delivered {delivered!r}, expected a body carrying marker "
        f"{marker_ok!r}"
    )
    dlq_msg = _await_dlq_message(
        ctx,
        dlq["url"],
        timeout_s=_DLQ_TIMEOUT_S,
        description=f"the failing schedule {name_err} in group {group_err}",
    )
    dlq_attrs = dlq_msg["MessageAttributes"]
    error_code = dlq_attrs["ERROR_CODE"]["StringValue"]
    assert "AccessDenied" in error_code, (
        f"the failing arm must fail for the ONE reason this check engineered (no sqs:SendMessage on "
        f"the target queue); the dead-letter event reports ERROR_CODE={error_code!r}, which is not "
        f"an AccessDenied-family code, so the attempt counts below would not be attributable"
    )

    # ---- the terminal read: an independent side-channel at CloudWatch, not at Scheduler ----
    def _read_all() -> dict[str, dict[str, float]]:
        end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=2)
        return {
            "ok": {
                metric: _metric_sum(cw, metric, group_ok, window_start, end)
                for metric in ("InvocationAttemptCount", "TargetErrorCount",
                               "InvocationDroppedCount")
            },
            "err": {
                metric: _metric_sum(cw, metric, group_err, window_start, end)
                for metric in ("InvocationAttemptCount", "TargetErrorCount",
                               "InvocationDroppedCount", "InvocationsSentToDeadLetterCount")
            },
        }

    # Scheduler does not retry an AccessDenied-class target failure, so the "err" arm records one
    # attempt despite MaximumRetryAttempts=2.
    expected_attempts = 1
    seen = _poll_until(
        _read_all,
        lambda s: s["ok"]["InvocationAttemptCount"] >= 1
        and s["err"]["InvocationAttemptCount"] >= expected_attempts,
        timeout_s=_METRIC_TIMEOUT_S,
        interval_s=20.0,
        description=(
            f"{_NAMESPACE} InvocationAttemptCount to reach 1 for ScheduleGroup={group_ok} and "
            f"{expected_attempts} for ScheduleGroup={group_err} after both occurrences were "
            f"observed at their destinations"
        ),
    )
    # A minute can publish in pieces, so consecutive reads must agree before exact counts are asserted.
    seen = _read_until_frozen(_read_all, seen)

    assert seen["ok"]["InvocationAttemptCount"] == 1, (
        f"a one-time schedule that delivered successfully must record exactly 1 "
        f"InvocationAttemptCount for its own ScheduleGroup {group_ok}, got "
        f"{seen['ok']['InvocationAttemptCount']!r}"
    )
    # A successful delivery publishes no TargetErrorCount datapoint, which sums to 0.
    assert seen["ok"]["TargetErrorCount"] == 0, (
        f"a schedule whose delivery succeeded must record 0 TargetErrorCount for ScheduleGroup "
        f"{group_ok}, got {seen['ok']['TargetErrorCount']!r}"
    )
    assert seen["ok"]["InvocationDroppedCount"] == 0, (
        f"a schedule whose delivery succeeded must record 0 InvocationDroppedCount for "
        f"ScheduleGroup {group_ok}, got {seen['ok']['InvocationDroppedCount']!r}"
    )
    assert seen["err"]["InvocationAttemptCount"] == expected_attempts, (
        f"an AccessDenied-class target failure is a permanent failure that Scheduler does not "
        f"retry, so InvocationAttemptCount must be exactly {expected_attempts} for ScheduleGroup "
        f"{group_err} despite MaximumRetryAttempts={_MAX_RETRY_ATTEMPTS} being configured, got "
        f"{seen['err']['InvocationAttemptCount']!r} (the healthy control in the same run recorded "
        f"{seen['ok']['InvocationAttemptCount']!r}, so the metric pipeline itself is live)"
    )
    assert seen["err"]["TargetErrorCount"] == expected_attempts, (
        f"the one, unretried attempt returned {error_code!r}, so TargetErrorCount must equal "
        f"{expected_attempts} for ScheduleGroup {group_err}, got "
        f"{seen['err']['TargetErrorCount']!r}"
    )
    assert seen["err"]["InvocationDroppedCount"] == 1, (
        f"the one permanently-denied occurrence must record exactly 1 InvocationDroppedCount for "
        f"ScheduleGroup {group_err} (once per dropped occurrence, not once per attempt), got "
        f"{seen['err']['InvocationDroppedCount']!r}"
    )
    assert seen["err"]["InvocationsSentToDeadLetterCount"] == 1, (
        f"exactly one dead-letter event was received off {dlq['url']}, so "
        f"InvocationsSentToDeadLetterCount must be 1 for ScheduleGroup {group_err}, got "
        f"{seen['err']['InvocationsSentToDeadLetterCount']!r}"
    )
    # Both schedules are one-time, so both must be present-and-completed rather than gone: read
    # them back through an operation neither created them nor published a metric.
    for name, group in ((name_ok, group_ok), (name_err, group_err)):
        described = sch.get_schedule(Name=name, GroupName=group)
        assert described["GroupName"] == group, (
            f"schedule {name} reports GroupName {described['GroupName']!r}, not the group "
            f"{group!r} whose metric dimension the counts above were read under"
        )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts can fail with ValidationException; `_create_schedule` retries within this bound.
_CREATE_TIMEOUT_S = 180


def _create_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=_MANAGED_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _scheduler_role(ctx, statements: list[dict]) -> str:
    """An IAM role EventBridge Scheduler can assume, carrying exactly `statements`."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scheduler-target",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_group(ctx, prefix: str) -> str:
    """Create-or-adopt a schedule group, tolerating ConflictException."""
    sch = ctx.client("scheduler")
    name = ctx.unique_name(prefix)
    try:
        sch.create_schedule_group(Name=name, Tags=_MANAGED_TAGS_KV)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConflictException":
            raise
    ctx.on_cleanup(lambda: _delete_group(ctx, name))
    return name


def _delete_group(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule_group(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException within a bound.

    The cleanup is registered from the name passed to the accepted call -- never re-looked-up.
    """
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while True:
        try:
            sch.create_schedule(Name=name, **kwargs)
            break
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateSchedule still refused after {_CREATE_TIMEOUT_S}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name, kwargs.get("GroupName")))
    return name


def _delete_schedule(ctx, name: str, group: str | None = None) -> None:
    extra = {"GroupName": group} if group else {}
    try:
        ctx.client("scheduler").delete_schedule(Name=name, **extra)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _await_body(ctx, queue_url: str, predicate, *, timeout_s: float, description: str) -> dict:
    """Poll SQS until a JSON body satisfying `predicate` arrives. Raises on timeout."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            raw = msg.get("Body", "")
            try:
                body = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                seen.append(raw)
                continue
            if isinstance(body, dict) and predicate(body):
                return body
            seen.append(raw)
    raise AssertionError(
        f"{description}: nothing matching arrived within {timeout_s}s. Bodies seen: {seen!r}"
    )


def _await_dlq_message(ctx, queue_url: str, *, timeout_s: float, description: str) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=20,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg
    raise AssertionError(f"{description}: no dead-letter event arrived within {timeout_s}s")


def _metric_sum(cw, metric_name: str, group: str, start, end) -> float:
    """Sum of every `Sum` datapoint for one AWS/Scheduler metric in one schedule group.

    No datapoints sums to 0, which the caller compares by exact equality.
    """
    resp = cw.get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=[{"Name": "ScheduleGroup", "Value": group}],
        StartTime=start,
        EndTime=end,
        Period=60,
        Statistics=["Sum"],
    )
    return float(sum(dp["Sum"] for dp in resp.get("Datapoints", [])))


def _read_until_frozen(read, first):
    """`_FREEZE_READS` consecutive identical reads, or an AssertionError.

    A CloudWatch minute can publish in pieces, so an exact count read once may be a partial.
    """
    values = [first]
    for _ in range(_FREEZE_READS - 1):
        time.sleep(_METRIC_SETTLE_S)
        values.append(read())
    assert all(v == values[0] for v in values), (
        f"{_NAMESPACE} counts were still moving across {_FREEZE_READS} reads "
        f"{_METRIC_SETTLE_S}s apart, so no exact count can be asserted: {values!r}"
    )
    return values[0]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry with a stated reason. RAISES on timeout; never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"waited {timeout_s}s for {description}; last observation was {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
