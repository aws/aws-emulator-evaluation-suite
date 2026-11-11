"""cfn-metric-breach-rolls-back-only-the-update-it-triggers."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-metric-breach-rolls-back-only-the-update-it-triggers"

GROUP = "deploy_rollback"

SERVICES = ["cloudformation", "cloudwatch", "sqs"]

_METRIC_NAMESPACE = "sim2real/cfn"

_TEMPLATE = json.dumps({
    "Parameters": {"QueueName": {"Type": "String"}, "Timeout": {"Type": "Number"}},
    "Resources": {
        "Queue": {"Type": "AWS::SQS::Queue",
                  "Properties": {"QueueName": {"Ref": "QueueName"},
                                 "VisibilityTimeout": {"Ref": "Timeout"}}},
    },
})

_ALARM_TYPE = "AWS::CloudWatch::Alarm"


# timing:real-time — metric: 60 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:metrics",
      "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A PutMetricData breach that drives a trigger alarm to ALARM inside an update's 5-minute
    monitoring window rolls that update back with a reason naming only that alarm, while the earlier
    completed update, whose own trigger alarm breaches at the same time, stays applied.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-rollback-triggers.html
    """
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")

    queue_name = _xname(ctx, "rbm-queue")
    alarms = {role: (_xname(ctx, f"rbm-{role}-alarm"), _xname(ctx, f"rbm-{role}-metric"))
              for role in ("first", "second")}
    stack_holder: dict[str, str | None] = {"name": None}

    def _delete_alarms() -> None:
        try:
            cw.delete_alarms(AlarmNames=[name for name, _m in alarms.values()])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise

    def _delete_queue() -> None:
        try:
            _delete_queue_by_name_if_present(sqs, queue_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "QueueDoesNotExist":
                raise

    def _confirm_stack_deleted(name: str) -> None:
        final = _poll_until(
            lambda: _stack_status(cfn, name),
            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
            timeout_s=300.0, interval_s=3.0, description=f"delete stack {name}")
        if final == "DELETE_FAILED":
            raise RuntimeError(f"stack {name} ended DELETE_FAILED — its resources are stranded")

    def _teardown() -> None:
        name = stack_holder["name"]
        steps: list[tuple[str, Any]] = [("alarm delete", _delete_alarms)]
        if name:
            steps.append((f"stack {name} delete_stack call", lambda: cfn.delete_stack(StackName=name)))
        steps.append((f"queue {queue_name} delete-by-name", _delete_queue))
        if name:
            steps.append((f"stack {name} delete confirmation", lambda: _confirm_stack_deleted(name)))
        leaks: list = []
        for label, step in steps:
            try:
                step()
            except Exception as exc:  # noqa: BLE001 - collected, then raised below
                leaks.append((f"{label} failed: {type(exc).__name__}: {exc}", exc))
        if leaks:
            raise RuntimeError("; ".join(m for m, _ in leaks)) from leaks[0][1]

    ctx.on_cleanup(_teardown)

    arns: dict[str, str] = {}
    for role, (alarm_name, metric_name) in alarms.items():
        cw.put_metric_alarm(
            AlarmName=alarm_name, AlarmDescription="sim2real cfn metric-driven rollback trigger",
            Namespace=_METRIC_NAMESPACE, MetricName=metric_name, Statistic="Maximum", Period=60,
            EvaluationPeriods=1, Threshold=1.0,
            ComparisonOperator="GreaterThanOrEqualToThreshold", TreatMissingData="notBreaching",
            Tags=[{"Key": "sim2real", "Value": "cfn-rollback-trigger-metric"}])
        arns[role] = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]
        # With no datapoints and notBreaching every evaluation yields OK, so OK set here holds
        # until a published datapoint breaches.
        cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK",
                           StateReason="start the rollback trigger at OK")
    for role, (alarm_name, _m) in alarms.items():
        state = _alarm_state(cw, alarm_name)
        assert state == "OK", f"the {role} trigger alarm must start OK, got {state!r}"

    # Named before the create so the teardown deletes a stack whose create never reaches a status.
    stack_holder["name"] = _xname(ctx, "rbm-stack")
    stack, status = _create_stack_and_wait(
        ctx, _TEMPLATE, stack_name=stack_holder["name"],
        parameters={"QueueName": queue_name, "Timeout": "30"}, timeout_s=_budget_s(ctx, 600.0))
    assert status == "CREATE_COMPLETE", f"setup stack ended in {status!r}"
    queue_url = _physical_id(cfn, stack, "Queue")
    assert _visibility_timeout(sqs, queue_url) == "30", (
        f"setup did not take: {_visibility_timeout(sqs, queue_url)!r}"
    )

    # ---- Update 1: trigger = first alarm (OK), zero-minute window: completes and is stored ----
    first_trigger = [{"Arn": arns["first"], "Type": _ALARM_TYPE}]
    first = _update_stack_and_wait(
        ctx, stack, parameters={"QueueName": queue_name, "Timeout": "45"},
        rollback_configuration={"RollbackTriggers": first_trigger, "MonitoringTimeInMinutes": 0},
        timeout_s=_budget_s(ctx, 600.0))
    assert first == "UPDATE_COMPLETE", (
        f"with its trigger alarm at OK the first update must complete, got {first!r}"
    )
    assert _visibility_timeout(sqs, queue_url) == "45", (
        f"the first update did not land: {_visibility_timeout(sqs, queue_url)!r}"
    )
    stored = cfn.describe_stacks(StackName=stack)["Stacks"][0].get("RollbackConfiguration", {})
    assert stored.get("RollbackTriggers") == first_trigger, (
        f"DescribeStacks must report the first update's trigger list, got {stored!r}"
    )

    # ---- Update 2: trigger = second alarm, 5-minute window; both metrics breach mid-window ----
    events_before = {e["EventId"] for e in _stack_events(cfn, stack)}
    cfn.update_stack(
        StackName=stack, UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "QueueName", "ParameterValue": queue_name},
                    {"ParameterKey": "Timeout", "ParameterValue": "60"}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        RollbackConfiguration={
            "RollbackTriggers": [{"Arn": arns["second"], "Type": _ALARM_TYPE}],
            "MonitoringTimeInMinutes": 5,
        })
    # The resource change landing is the observable sign that the monitoring window is open.
    _poll_until(lambda: _visibility_timeout(sqs, queue_url), lambda v: v == "60",
                timeout_s=_budget_s(ctx, 300.0), interval_s=3.0,
                description="queue VisibilityTimeout updated to 60 (monitoring window open)")
    for _alarm_name, metric_name in alarms.values():
        _push_metric(cw, metric_name, 5.0)
    for role, (alarm_name, _m) in alarms.items():
        armed = _poll_until(
            lambda n=alarm_name: _alarm_state(cw, n), lambda s: s == "ALARM",
            timeout_s=_budget_s(ctx, 300.0), interval_s=5.0,
            description=f"the {role} alarm {alarm_name} reaching ALARM after PutMetricData")
        assert armed == "ALARM", f"the {role} alarm must reach ALARM, got {armed!r}"
        assert _has_alarm_history_transition(cw, alarm_name, "OK", "ALARM"), (
            f"DescribeAlarmHistory for {alarm_name!r} must record an OK->ALARM StateUpdate"
        )

    triggered = _poll_until(lambda: _stack_status(cfn, stack), lambda s: s in _UPDATE_TERMINAL,
                            timeout_s=_budget_s(ctx, 600.0), interval_s=3.0,
                            description=f"update of stack {stack} after the breach")
    assert triggered == "UPDATE_ROLLBACK_COMPLETE", (
        f"the breached trigger alarm must roll the second update back, got {triggered!r}"
    )
    new = [e for e in _stack_events(cfn, stack) if e["EventId"] not in events_before]
    rolling = [e.get("ResourceStatusReason") for e in new
               if e["ResourceStatus"] == "UPDATE_ROLLBACK_IN_PROGRESS"]
    second_alarm = alarms["second"][0]
    assert rolling == [f"The following CloudWatch Alarms were in ALARM state: {second_alarm}"], (
        f"the rollback reason must name exactly the second update's trigger alarm; got {rolling!r}"
    )
    reverted = _visibility_timeout(sqs, queue_url)
    assert reverted == "45", (
        f"the rollback must restore the first update's value and leave that completed update in "
        f"place although its own trigger alarm is now in ALARM; the queue reports {reverted!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}

_UPDATE_TERMINAL = {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_FAILED", "GONE"}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alarm_state(cw, alarm_name: str) -> str:
    return cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]


def _push_metric(cw, metric_name: str, value: float) -> None:
    cw.put_metric_data(Namespace=_METRIC_NAMESPACE, MetricData=[{
        "MetricName": metric_name, "Value": value, "Unit": "Count",
        "Timestamp": datetime.now(timezone.utc),
    }])


def _has_alarm_history_transition(cw, alarm_name: str, old_state: str, new_state: str) -> bool:
    """Whether DescribeAlarmHistory records a StateUpdate old_state -> new_state, paginated."""
    token = None
    while True:
        kwargs: dict[str, Any] = {"AlarmName": alarm_name, "HistoryItemType": "StateUpdate"}
        if token:
            kwargs["NextToken"] = token
        page = cw.describe_alarm_history(**kwargs)
        for item in page.get("AlarmHistoryItems", []):
            data = json.loads(item["HistoryData"])
            if (data.get("oldState", {}).get("stateValue") == old_state
                    and data.get("newState", {}).get("stateValue") == new_state):
                return True
        token = page.get("NextToken")
        if not token:
            return False


def _queue_url_or_none(sqs, name: str) -> str | None:
    try:
        return sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == _NO_SUCH_QUEUE:
            return None
        raise


def _delete_queue_by_name_if_present(sqs, name: str) -> None:
    """Queue teardown by name; already-deleted is not an error."""
    url = _queue_url_or_none(sqs, name)
    if url:
        sqs.delete_queue(QueueUrl=url)


def _visibility_timeout(sqs, url: str) -> str:
    return sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"]


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return "GONE"
        raise


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    """The PhysicalResourceId CloudFormation currently records for a logical id."""
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id)["StackResourceDetail"]["PhysicalResourceId"]


def _stack_events(cfn, name: str) -> list[dict[str, Any]]:
    """Every event for a stack, oldest first, paginated."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _create_stack_and_wait(ctx, template: str, *, stack_name: str, parameters=None,
                           timeout_s=600.0) -> tuple[str, str]:
    """create_stack, then poll to a terminal status which is RETURNED rather than asserted. The
    caller's combined teardown deletes the stack."""
    cfn = ctx.client("cloudformation")
    ctx.verify_account_safety()
    kwargs: dict[str, Any] = {
        "StackName": stack_name, "TemplateBody": template, "Tags": _tags_kv(),
        "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v}
                                for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    status = _poll_until(lambda: _stack_status(cfn, stack_name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=timeout_s, interval_s=3.0,
                         description=f"create stack {stack_name}")
    return stack_name, status


def _update_stack_and_wait(ctx, name: str, *, parameters, rollback_configuration,
                           timeout_s=600.0) -> str:
    """Update a stack with the previous template and poll to a terminal status, RETURNED."""
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=name, UsePreviousTemplate=True,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        RollbackConfiguration=rollback_configuration)
    return _poll_until(lambda: _stack_status(cfn, name), lambda s: s in _UPDATE_TERMINAL,
                       timeout_s=timeout_s, interval_s=3.0,
                       description=f"update of stack {name}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
