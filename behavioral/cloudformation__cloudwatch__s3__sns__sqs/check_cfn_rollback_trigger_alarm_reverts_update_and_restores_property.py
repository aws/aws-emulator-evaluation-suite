"""cfn-rollback-trigger-alarm-reverts-update-and-restores-property."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rollback-trigger-alarm-reverts-update-and-restores-property"

GROUP = "deploy_rollback"

SERVICES = ["cloudformation", "cloudwatch", "s3", "sns", "sqs"]

_TEMPLATE = json.dumps({
    "Parameters": {"QueueName": {"Type": "String"}, "Timeout": {"Type": "Number"}},
    "Resources": {
        "Queue": {"Type": "AWS::SQS::Queue",
                  "Properties": {"QueueName": {"Ref": "QueueName"},
                                 "VisibilityTimeout": {"Ref": "Timeout"}}},
    },
})


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:metrics",
      "plane:control")
def run(ctx) -> None:
    """An update with a RollbackConfiguration trigger on an alarm in ALARM ends UPDATE_ROLLBACK_COMPLETE
    with the queue property reverted; the same update with no trigger completes and keeps it.
    """
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")

    alarm_name = _xname(ctx, "rbtrig-a")
    queue_name = _xname(ctx, "rbtrig-q")
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, queue_name))

    # TreatMissingData=breaching means the alarm is in ALARM on its own, with nothing to publish;
    # set_alarm_state gets it there immediately instead of waiting out an evaluation period, and
    # 'breaching' is what stops the next evaluation returning it to INSUFFICIENT_DATA mid-update.
    cw.put_metric_alarm(
        AlarmName=alarm_name, AlarmDescription="sim2real cfn rollback trigger",
        Namespace="sim2real/xsvc", MetricName=alarm_name, Statistic="Sum", Period=60,
        EvaluationPeriods=1, Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold", TreatMissingData="breaching",
        Tags=[{"Key": "sim2real", "Value": "cfn-rollback-trigger"}])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM",
                       StateReason="sim2real: arm the CloudFormation rollback trigger")
    alarm_state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM", timeout_s=300.0, interval_s=5.0,
        description=f"alarm {alarm_name} in ALARM")
    assert alarm_state == "ALARM", (
        f"the trigger alarm must be in ALARM before the update starts, got {alarm_state!r}"
    )

    stack, status = _create_stack_and_wait(
        ctx, _TEMPLATE, stack_name=_xname(ctx, "rbtrig-s"),
        parameters={"QueueName": queue_name, "Timeout": "30"}, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"setup stack ended in {status!r}"
    queue_url = _physical_id(cfn, stack, "Queue")
    assert _visibility_timeout(sqs, queue_url) == "30", (
        f"setup did not take: {_visibility_timeout(sqs, queue_url)!r}"
    )

    # ---- the update the alarm must undo ----
    triggered = _update_stack_and_wait(
        ctx, stack, parameters={"QueueName": queue_name, "Timeout": "45"},
        rollback_configuration={
            "RollbackTriggers": [{"Arn": alarm_arn, "Type": "AWS::CloudWatch::Alarm"}],
            "MonitoringTimeInMinutes": 1,
        }, timeout_s=900.0)
    assert triggered == "UPDATE_ROLLBACK_COMPLETE", (
        f"expected the alarm to force a rollback, got {triggered!r}"
    )

    # 1. CloudFormation must attribute it to the trigger, not to a resource failure.
    reason = _failure_text(cfn, stack)
    assert "alarm" in reason.lower(), (
        f"the stack must say the rollback came from the trigger alarm; reasons were {reason!r}"
    )
    assert alarm_name in reason, (
        f"the rollback reason must name the alarm {alarm_name!r}; got {reason!r}"
    )

    # 2. The property is back where it was -- read from SQS, not from the stack's own record.
    reverted = _visibility_timeout(sqs, queue_url)
    assert reverted == "30", (
        f"rollback must restore the pre-update property, the queue reports {reverted!r}"
    )
    recorded = {p["ParameterKey"]: p.get("ParameterValue")
                for p in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Parameters"]}
    assert recorded["Timeout"] == "30", (
        f"DescribeStacks still reports the rolled-back parameter as {recorded!r}"
    )

    # ---- Control: the identical update with an empty trigger list must stick ----
    control = _update_stack_and_wait(
        ctx, stack, parameters={"QueueName": queue_name, "Timeout": "45"},
        rollback_configuration={"RollbackTriggers": []}, timeout_s=900.0)
    assert control == "UPDATE_COMPLETE", (
        f"without a trigger the identical update must succeed, got {control!r}; the first "
        f"rollback would otherwise be explained by an invalid update rather than by the alarm"
    )
    assert _visibility_timeout(sqs, queue_url) == "45", (
        f"the control update did not land: {_visibility_timeout(sqs, queue_url)!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}

_UPDATE_TERMINAL = {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_FAILED", "GONE"}


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


def _queue_url_or_none(sqs, name: str) -> str | None:
    try:
        return sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == _NO_SUCH_QUEUE:
            return None
        raise


def _delete_queue_by_name_if_present(sqs, name: str) -> None:
    """Best-effort queue teardown by name; already-deleted is not an error."""
    url = _queue_url_or_none(sqs, name)
    if url:
        sqs.delete_queue(QueueUrl=url)


def _visibility_timeout(sqs, url: str) -> str:
    return sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"]


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


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


def _failure_text(cfn, name: str) -> str:
    """Every reason CloudFormation recorded for a stack, plus its StackStatusReason, joined.

    Which event carries the rollback-trigger reason is not part of the claim.
    """
    parts = [e.get("ResourceStatusReason") or "" for e in _stack_events(cfn, name)]
    try:
        parts.append(
            cfn.describe_stacks(StackName=name)["Stacks"][0].get("StackStatusReason") or "")
    except ClientError:
        pass
    return " | ".join(p for p in parts if p)


def _delete_stack_and_wait(ctx, name: str, *, timeout_s=900.0) -> None:
    """Delete a stack and wait for it to go; teardown, so a failure PRINTS rather than raises."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
        final = _poll_until(lambda: _stack_status(cfn, name),
                            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                            timeout_s=timeout_s, interval_s=5.0,
                            description=f"delete stack {name}")
        if final == "DELETE_FAILED":
            raise RuntimeError(
                f"stack {name} ended DELETE_FAILED — its resources are stranded"
            )
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"stack {name} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


def _create_stack_and_wait(ctx, template: str, *, stack_name=None, parameters=None,
                           capabilities=None, timeout_s=900.0) -> tuple[str, str]:
    """create_stack, then poll to a terminal status which is RETURNED rather than asserted."""
    cfn = ctx.client("cloudformation")
    ctx.verify_account_safety()
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name, "TemplateBody": template, "Tags": _tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v}
                                for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    status = _poll_until(lambda: _stack_status(cfn, name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=timeout_s, interval_s=5.0,
                         description=f"create stack {name}")
    return name, status


def _update_stack_and_wait(ctx, name: str, *, template=None, parameters=None, capabilities=None,
                           rollback_configuration=None, timeout_s=900.0) -> str:
    """Update a stack and poll to a terminal status, which is RETURNED rather than asserted."""
    cfn = ctx.client("cloudformation")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if template is None:
        kwargs["UsePreviousTemplate"] = True
    else:
        kwargs["TemplateBody"] = template
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v}
                                for k, v in parameters.items()]
    if rollback_configuration is not None:
        kwargs["RollbackConfiguration"] = rollback_configuration
    cfn.update_stack(**kwargs)
    return _poll_until(lambda: _stack_status(cfn, name), lambda s: s in _UPDATE_TERMINAL,
                       timeout_s=timeout_s, interval_s=5.0,
                       description=f"update of stack {name}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
