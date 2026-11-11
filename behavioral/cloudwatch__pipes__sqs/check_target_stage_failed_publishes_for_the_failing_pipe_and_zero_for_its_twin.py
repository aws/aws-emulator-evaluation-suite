"""target-stage-failed-publishes-for-the-failing-pipe-and-zero-for-its-twin."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "target-stage-failed-publishes-for-the-failing-pipe-and-zero-for-its-twin"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "pipes", "sqs"]

_PIPE_READY_BUDGET_S = 300.0
_METRIC_BUDGET_S = 900.0
_DELIVERY_BUDGET_S = 300.0
#: The twin's absence hold, a fixed window read after the positive metric has landed.
_ABSENCE_HOLD_S = 10.0
_ROLE_PROPAGATION_BUDGET_S = 180.0
_POLL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-monitoring.html
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c4",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A pipe whose role cannot write its target publishes TargetStageFailed >= 1 (Unit "None") per
    PipeName, while a healthy twin on identical wiring delivers and publishes an explicit zero.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-monitoring.html"""
    pipes = ctx.client("pipes")
    cw = ctx.client("cloudwatch")

    # --- the failing pipe: role can read the source but NOT write the target ------------------- #
    bad_source, bad_source_arn = _queue(ctx, "badsrc-")
    bad_target, bad_target_arn = _queue(ctx, "badtgt-")
    bad_role = _pipe_role(ctx, source_arn=bad_source_arn, target_arn=None)
    bad_pipe = _pipe(ctx, pipes, "failing-", bad_source_arn, bad_target_arn, bad_role)

    # --- the healthy twin: identical, except the role CAN write the target --------------------- #
    ok_source, ok_source_arn = _queue(ctx, "oksrc-")
    ok_target, ok_target_arn = _queue(ctx, "oktgt-")
    ok_role = _pipe_role(ctx, source_arn=ok_source_arn, target_arn=ok_target_arn)
    ok_pipe = _pipe(ctx, pipes, "healthy-", ok_source_arn, ok_target_arn, ok_role)

    for name in (bad_pipe, ok_pipe):
        state = _poll_until(
            lambda n=name: pipes.describe_pipe(Name=n)["CurrentState"],
            lambda s: s == "RUNNING",
            timeout_s=_budget_s(ctx, _PIPE_READY_BUDGET_S), ctx=ctx,
            interval_s=_POLL_S,
            description=f"pipe {name} reaching RUNNING",
            terminal_bad={"CREATE_FAILED", "START_FAILED", "STOPPED"},
        )
        assert state == "RUNNING", f"pipe {name} settled at CurrentState {state!r}, expected RUNNING"

    marker = ctx.unique_name("probe-")
    body = json.dumps({"probe": CHECK, "marker": marker})
    ctx.client("sqs").send_message(QueueUrl=ok_source, MessageBody=body)
    ctx.client("sqs").send_message(QueueUrl=bad_source, MessageBody=body)

    # ---- the twin really delivered ------------------------------------------------------------ #
    delivered = _drain_until(
        ctx,
        ok_target,
        want=1,
        timeout_s=_budget_s(ctx, _DELIVERY_BUDGET_S),
        description=f"the healthy pipe {ok_pipe} delivering to its target queue",
    )
    assert marker in delivered[0], (
        f"the healthy pipe's target received {delivered[0]!r}, which does not carry the marker "
        f"{marker!r}; the twin must demonstrably work before the failing pipe's metric means anything"
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=25)

    def _dps(pipe_name: str, metric: str) -> list[dict]:
        return cw.get_metric_statistics(
            Namespace="AWS/EventBridge/Pipes",
            MetricName=metric,
            Dimensions=[{"Name": "PipeName", "Value": pipe_name}],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum", "SampleCount", "Maximum"],
        )["Datapoints"]

    def _sum(pipe_name: str, metric: str) -> float | None:
        dps = _dps(pipe_name, metric)
        return float(sum(d["Sum"] for d in dps)) if dps else None

    # Pipes metric delivery is best-effort, so the failure is held to >= 1, never an exact count.
    failed = _poll_until(
        lambda: _sum(bad_pipe, "TargetStageFailed"),
        lambda v: v is not None and v >= 1.0,
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S), ctx=ctx,
        interval_s=_POLL_S,
        description=(
            f"AWS/EventBridge/Pipes TargetStageFailed reaching >= 1 for PipeName={bad_pipe}, whose "
            f"execution role has no sqs:SendMessage on its target queue"
        ),
    )
    assert failed >= 1.0, (
        f"AWS/EventBridge/Pipes TargetStageFailed Sum for PipeName={bad_pipe} read {failed!r}, "
        f"expected at least 1.0 — the pipe's role cannot write its target, so every attempt must "
        f"fail at the TARGET stage. No exact count is demanded: Pipes documents metric delivery as "
        f"best-effort, so a pinned number would be asserting against AWS's own stated behaviour"
    )

    # Only this metric's unit is asserted: under best-effort delivery EventCount may be absent.
    dps = _dps(bad_pipe, "TargetStageFailed")
    assert dps, (
        f"AWS/EventBridge/Pipes TargetStageFailed vanished on re-read for {bad_pipe}: {dps!r}"
    )
    units = {d.get("Unit") for d in dps}
    assert units == {"None"}, (
        f"AWS/EventBridge/Pipes TargetStageFailed datapoints for PipeName={bad_pipe} carry Unit(s) "
        f"{units!r}, expected exactly {{'None'}}. The Pipes monitoring table gives Units 'None' for "
        f"its count-like metrics; 'Count' is the natural wrong answer and this is where it shows"
    )

    # ListMetrics can lag GetMetricStatistics by up to 15 minutes for a fresh metric, so poll.
    sets = _poll_until(
        lambda: _dimension_sets(cw, "AWS/EventBridge/Pipes", "PipeName", bad_pipe),
        lambda s: bool(s),
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S), ctx=ctx,
        interval_s=_POLL_S,
        description=(
            f"ListMetrics cataloging the AWS/EventBridge/Pipes series naming PipeName={bad_pipe}"
        ),
    )
    assert sets == {("PipeName",)}, (
        f"ListMetrics reports dimension sets {sorted(sets)!r} for the AWS/EventBridge/Pipes series "
        f"naming PipeName={bad_pipe}; the monitoring page gives PipeName as the per-pipe dimension "
        f"(with AwsAccountId used for the account-level Concurrency/Invocations series), so the "
        f"per-pipe series must carry PipeName alone"
    )

    # ---- the healthy twin reports an explicit zero ("will be 0 if no executions failed") ------- #
    twin_zero = _poll_until(
        lambda: _sum(ok_pipe, "TargetStageFailed"),
        lambda v: v is not None,
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S), ctx=ctx,
        interval_s=_POLL_S,
        description=(
            f"AWS/EventBridge/Pipes TargetStageFailed EXISTING for the healthy PipeName={ok_pipe}; "
            f"the docs say the value 'will be 0 if no executions failed', so the series must be "
            f"materialised rather than omitted"
        ),
    )
    assert twin_zero == 0.0, (
        f"AWS/EventBridge/Pipes TargetStageFailed Sum for the healthy PipeName={ok_pipe} read "
        f"{twin_zero!r}, expected exactly 0.0. Its target was delivered to successfully (the message "
        f"carrying marker {marker!r} was read off the target queue), so any non-zero failure count "
        f"means failures are being attributed across pipes"
    )
    assert failed > twin_zero, (
        f"the failing pipe reported TargetStageFailed={failed!r} and the healthy twin "
        f"{twin_zero!r}; the whole contract is that the two are DISTINGUISHABLE, and equal values "
        f"mean 'refused to deliver' cannot be told from 'never ran'"
    )
    _assert_stays(
        lambda: _sum(ok_pipe, "TargetStageFailed"),
        0.0,
        hold_s=_ABSENCE_HOLD_S,
        interval_s=_POLL_S,
        description=(
            f"the healthy pipe {ok_pipe} keeps reporting TargetStageFailed == 0 while the failing "
            f"twin reports {failed!r} on identical wiring"
        ),
    )

    # ---- and nothing was delivered to the failing pipe's target -------------------------------- #
    leaked = _received_count(ctx, bad_target)
    assert leaked == 0, (
        f"the failing pipe's target queue yielded {leaked} message(s); its role has no "
        f"sqs:SendMessage on that queue, so the TargetStageFailed count above must correspond to a "
        f"real non-delivery"
    )


def _queue(ctx, label: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-cwpipes-{label}"),
        tags={"sim2real": "cloudwatch__pipes__sqs"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _pipe_role(ctx, *, source_arn: str, target_arn: str | None) -> str:
    """Create a pipe role that can drain the source and, only when target_arn is given, write it."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-cwpipes-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "pipes.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__pipes__sqs"}],
    )["Role"]["Arn"]
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
                "sqs:GetQueueAttributes",
            ],
            "Resource": source_arn,
        }
    ]
    if target_arn is not None:
        statements.append(
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn}
        )
    policy_name = "sim2real-pipe"
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return arn


def _pipe(ctx, pipes, label: str, source_arn: str, target_arn: str, role_arn: str) -> str:
    name = ctx.unique_name(f"sim2real-cwpipes-{label}")[:64]
    _retry_on_role_propagation(
        ctx,
        lambda: pipes.create_pipe(
            Name=name,
            RoleArn=role_arn,
            Source=source_arn,
            Target=target_arn,
            SourceParameters={
                "SqsQueueParameters": {"BatchSize": 1, "MaximumBatchingWindowInSeconds": 0}
            },
            DesiredState="RUNNING",
            Tags={"sim2real": "cloudwatch__pipes__sqs"},
        ),
        description=f"CreatePipe {name} accepting the freshly created role {role_arn}",
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=name))
    return name


def _retry_on_role_propagation(ctx, call, *, description: str):
    from botocore.exceptions import ClientError

    budget_s = _budget_s(ctx, _ROLE_PROPAGATION_BUDGET_S)
    deadline = time.monotonic() + budget_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in {"ValidationException", "AccessDeniedException"}:
                raise
            last = exc
            time.sleep(_POLL_S)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} never succeeded within {budget_s:.0f}s; last refusal {last!r}"
    )


def _drain_until(ctx, queue_url: str, *, want: int, timeout_s: float, description: str) -> list[str]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    bodies: list[str] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if len(bodies) >= want:
            return bodies
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description}: only {len(bodies)} of {want} messages arrived within {timeout_s}s; "
        f"bodies were {bodies!r}"
    )


def _received_count(ctx, queue_url: str) -> int:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    msgs = resp.get("Messages", [])
    for m in msgs:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return len(msgs)


def _dimension_sets(cw, namespace: str, dim_name: str, dim_value: str) -> set[tuple[str, ...]]:
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": dim_name, "Value": dim_value}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


def _poll_until(
    probe, predicate, *, timeout_s, interval_s, description, terminal_bad=frozenset(), ctx=None
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if isinstance(last, str) and last in terminal_bad:
            raise AssertionError(
                f"{description}: reached the terminal failure value {last!r}, which the poll's "
                f"target set excludes"
            )
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _assert_stays(probe, expected, *, hold_s, interval_s=_POLL_S, description="reading"):
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description}: read {got!r}, expected it to stay {expected!r} for the whole {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
