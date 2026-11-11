"""obs-cloudformation-2-rollback-trigger-invalid-type-rejected."""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cloudformation-2-rollback-trigger-invalid-type-rejected"

GROUP = "deploy_rollback"

SERVICES = ["cloudformation", "cloudwatch", "sqs"]

_TEMPLATE = json.dumps({
    "Parameters": {"QueueName": {"Type": "String"}},
    "Resources": {
        "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": {"Ref": "QueueName"}}},
    },
})


# timing:real-time — metric: 300 s https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RollbackConfiguration.html
@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:e2e",
      "plane:control", "timing:real-time")
def run(ctx) -> None:
    """CreateStack rejects a RollbackTrigger whose Type is not a declared trigger type before any
    resource is created (no stack exists afterwards), while the identical request with
    `AWS::CloudWatch::Alarm` reaches CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")

    alarm_name = _xname(ctx, "obs2-neg-alarm")
    queue_name = _xname(ctx, "obs2-neg-queue")

    cw.put_metric_alarm(
        AlarmName=alarm_name, AlarmDescription="sim2real cfn rollback-trigger-type negative",
        Namespace="sim2real/cfn", MetricName=_xname(ctx, "obs2-neg-metric"), Statistic="Maximum",
        Period=60, EvaluationPeriods=1, Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold", TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "cfn-rollback-trigger-type-negative"}])
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]

    # One combined teardown fires every delete before any blocking wait, so a slow stack-delete
    # confirmation cannot hold up the alarm and queue deletes.
    stack_holder: dict[str, str | None] = {"name": None}

    def _delete_alarm() -> None:
        try:
            cw.delete_alarms(AlarmNames=[alarm_name])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise

    def _delete_queue() -> None:
        try:
            _delete_queue_by_name_if_present(sqs, queue_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("QueueDoesNotExist", _NO_SUCH_QUEUE):
                raise

    def _confirm_stack_deleted(name: str) -> None:
        final = _poll_until(
            lambda: _stack_status(cfn, name),
            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
            timeout_s=45.0, interval_s=2.0, description=f"delete stack {name}")
        if final == "DELETE_FAILED":
            raise AssertionError(f"stack {name} ended DELETE_FAILED; its resources are stranded")

    def _teardown() -> None:
        name = stack_holder["name"]
        steps = [_delete_alarm]
        if name:
            steps.append(lambda: cfn.delete_stack(StackName=name))
        steps.append(_delete_queue)
        if name:
            steps.append(lambda: _confirm_stack_deleted(name))
        problems: list[Exception] = []
        for step in steps:
            try:
                step()
            except Exception as exc:  # noqa: BLE001 - collected, raised below
                problems.append(exc)
        if problems:
            raise RuntimeError("; ".join(map(repr, problems))) from problems[0]

    ctx.on_cleanup(_teardown)

    # ---- Negative: an unsupported Type must be refused, and nothing created ----
    broken_stack = _xname(ctx, "obs2-neg-stack")
    code, message = _create_stack_expect_error(
        ctx, broken_stack, parameters={"QueueName": queue_name},
        rollback_triggers=[{"Arn": alarm_arn, "Type": "AWS::CloudWatch::Metric"}])
    assert code == "ValidationError", (
        f"expected ValidationError for an unsupported RollbackTrigger Type, got {code!r}"
    )
    expected = "Rollback Trigger Type not supported"
    assert message == expected, f"expected {expected!r}, got {message!r}"
    after = _stack_status(cfn, broken_stack)
    assert after == "GONE", (
        f"a rejected CreateStack must not have created anything; DescribeStacks reports "
        f"{after!r} for {broken_stack!r}"
    )

    # ---- Positive control: the identical template and alarm, with the real Type, succeeds ----
    good_stack, status = _create_stack_and_wait(
        ctx, _TEMPLATE, stack_name=_xname(ctx, "obs2-neg-good-stack"),
        parameters={"QueueName": queue_name},
        rollback_triggers=[{"Arn": alarm_arn, "Type": "AWS::CloudWatch::Alarm"}],
        timeout_s=600.0, register_cleanup=False)
    stack_holder["name"] = good_stack
    assert status == "CREATE_COMPLETE", (
        f"the control create, differing only in Type, must succeed; got {status!r}"
    )
    assert _stack_status(cfn, good_stack) == "CREATE_COMPLETE", (
        "the control stack must still be there to prove the first rejection was about Type, "
        "not about the alarm, the template or the account"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _client_error(fn) -> tuple[str, str]:
    """The AWS error (code, message) for a call expected to fail; raises if it unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code = err.get("Code")
        if not code:
            raise AssertionError(f"ClientError with no Error.Code: {exc.response!r}") from exc
        return code, err.get("Message", "")
    raise AssertionError("expected a ClientError, the call succeeded instead")


def _create_stack_expect_error(ctx, stack_name: str, *, parameters, rollback_triggers) -> tuple[str, str]:
    cfn = ctx.client("cloudformation")

    def _call():
        cfn.create_stack(
            StackName=stack_name, TemplateBody=_TEMPLATE, Tags=_tags_kv(),
            Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
            RollbackConfiguration={"RollbackTriggers": rollback_triggers,
                                   "MonitoringTimeInMinutes": 5})
    return _client_error(_call)


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


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    import time
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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
                           capabilities=None, rollback_triggers=None,
                           timeout_s=900.0, register_cleanup=True) -> tuple[str, str]:
    """create_stack, then poll to a terminal status which is RETURNED rather than asserted.

    register_cleanup=False lets the caller fold the stack delete into a SINGLE combined teardown
    alongside other resources instead of this helper registering its own, separate, blocking one.
    """
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
    if rollback_triggers is not None:
        kwargs["RollbackConfiguration"] = {"RollbackTriggers": rollback_triggers,
                                           "MonitoringTimeInMinutes": 5}
    cfn.create_stack(**kwargs)
    if register_cleanup:
        ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    status = _poll_until(lambda: _stack_status(cfn, name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=timeout_s, interval_s=5.0,
                         description=f"create stack {name}")
    return name, status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
