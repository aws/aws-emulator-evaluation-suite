"""scheduler-disabled-schedule-does-not-invoke-target."""

from __future__ import annotations

import datetime
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-disabled-schedule-does-not-invoke-target"

GROUP = "event-propagation"

SERVICES = ["scheduler", "sqs"]

# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException; this bounds the retry.
_CREATE_SCHEDULE_TIMEOUT_S = 180


# timing:real-time — schedule: 120 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A DISABLED schedule does not invoke its SQS target once its due time passes, while an ENABLED
    twin due at the same instant on the same queue does; enabling the same schedule then delivers.
    """
    scheduler = ctx.client("scheduler")

    queue = _create_queue(ctx)
    # Account id comes off the queue ARN so the check stays inside its declared SERVICES set.
    account = queue["arn"].split(":")[4]
    role_arn = _scheduler_role(ctx, queue["arn"], account)
    _allow_role_to_send(ctx, queue, role_arn)

    fire_at = _at_expression(seconds_ahead=120)
    enabled_marker = ctx.unique_name("enabled-")
    disabled_marker = ctx.unique_name("disabled-")
    enabled_name = _create_schedule(
        ctx, fire_at, queue["arn"], role_arn, {"marker": enabled_marker}, state="ENABLED"
    )
    disabled_name = _create_schedule(
        ctx, fire_at, queue["arn"], role_arn, {"marker": disabled_marker}, state="DISABLED"
    )

    described = scheduler.get_schedule(Name=disabled_name)
    assert described["State"] == "DISABLED", (
        f"State=DISABLED must round-trip through GetSchedule, got {described.get('State')!r}"
    )

    # The enabled twin's arrival proves the shared due time has passed on the same dispatcher.
    _, seen = _await_body(
        ctx,
        queue["url"],
        lambda b: b.get("marker") == enabled_marker,
        timeout_s=330,
        description=f"the ENABLED schedule {enabled_name} delivering {enabled_marker}",
    )

    leaked = [b for b in seen if b.get("marker") == disabled_marker]
    assert not leaked, (
        f"a DISABLED schedule must not invoke its target, but {len(leaked)} payload(s) for "
        f"{disabled_name} were delivered: {leaked!r}"
    )
    still_there = scheduler.get_schedule(Name=disabled_name)
    assert still_there["State"] == "DISABLED", (
        f"the disabled schedule must not flip itself to {still_there.get('State')!r}"
    )

    # The enabled twin's arrival ended the poll above, so keep watching for a late delivery.
    late = [
        b
        for b in _drain_bodies(ctx, queue["url"], window_s=60.0)
        if b.get("marker") == disabled_marker
    ]
    assert not late, (
        f"a DISABLED schedule must not invoke its target, but {len(late)} payload(s) for "
        f"{disabled_name} arrived after the ENABLED twin had already fired: {late!r}"
    )

    # Control: the same schedule, once enabled, delivers, so State alone caused the silence.
    control_at = _at_expression(seconds_ahead=90)
    scheduler.update_schedule(
        Name=disabled_name,
        ScheduleExpression=control_at,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": disabled_marker}),
        },
    )
    body, _ = _await_body(
        ctx,
        queue["url"],
        lambda b: b.get("marker") == disabled_marker,
        timeout_s=300,
        description=(
            f"the same schedule {disabled_name}, once ENABLED, delivering {disabled_marker}"
        ),
    )
    assert body["marker"] == disabled_marker, body


def _at_expression(*, seconds_ahead: int) -> str:
    """A one-time `at(...)` expression `seconds_ahead` from now, in UTC."""
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        seconds=seconds_ahead
    )
    return f"at({when.strftime('%Y-%m-%dT%H:%M:%S')})"


def _create_schedule(
    ctx, expression: str, queue_arn: str, role_arn: str, payload: dict, *, state: str
) -> str:
    """Create a one-time schedule targeting the queue with `payload` as its Input."""
    scheduler = ctx.client("scheduler")
    name = _xname(ctx, f"sched-{state.lower()}")
    deadline = time.monotonic() + _CREATE_SCHEDULE_TIMEOUT_S
    last_exc = None
    while True:
        try:
            scheduler.create_schedule(
                Name=name,
                ScheduleExpression=expression,
                ScheduleExpressionTimezone="UTC",
                FlexibleTimeWindow={"Mode": "OFF"},
                State=state,
                Target={
                    "Arn": queue_arn,
                    "RoleArn": role_arn,
                    "Input": json.dumps(payload),
                },
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            last_exc = exc
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateSchedule for {name} still refused after "
                    f"{_CREATE_SCHEDULE_TIMEOUT_S}s of IAM role propagation: {last_exc!r}"
                ) from last_exc
            time.sleep(3)
    ctx.on_cleanup(lambda: ctx.client("scheduler").delete_schedule(Name=name))
    return name


def _scheduler_role(ctx, queue_arn: str, account: str) -> str:
    """An IAM role EventBridge Scheduler can assume to send to exactly this queue."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role-scheduler")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account}},
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sqs:SendMessage",
                        "Resource": queue_arn,
                    }
                ],
            }
        ),
    )
    return resp["Role"]["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    """Delete the role after removing its attached and inline policies, which IAM requires."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _allow_role_to_send(ctx, queue: dict, role_arn: str) -> None:
    """Grant the scheduler role SendMessage in the queue policy; best effort, as the identity
    policy alone suffices in-account."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
            }
        ],
    }
    try:
        ctx.client("sqs").set_queue_attributes(
            QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
        )
    except Exception:
        pass


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _await_body(
    ctx, queue_url: str, predicate, *, timeout_s=180.0, description="scheduled delivery"
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Poll SQS until a JSON body satisfying predicate arrives; return (matched, all seen)."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(body, dict):
                continue
            seen.append(body)
            if predicate(body):
                return body, seen
    raise AssertionError(
        f"{description} not delivered within {timeout_s}s. Bodies seen: {seen!r}"
    )


def _drain_bodies(
    ctx, queue_url: str, *, window_s: float = 60.0, max_total: int = 10
) -> list[dict[str, Any]]:
    """Drain a queue over a bounded window and return every JSON body seen.

    Meaningful only after a positive control on the same queue proved the dispatcher ran.
    """
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(body, dict):
                seen.append(body)
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
