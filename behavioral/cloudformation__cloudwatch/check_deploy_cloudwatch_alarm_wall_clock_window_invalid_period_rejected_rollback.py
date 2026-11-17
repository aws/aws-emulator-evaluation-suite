"""deploy-cloudwatch-alarm-wall-clock-window-invalid-period-rejected-rollback."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cloudwatch-alarm-wall-clock-window-invalid-period-rejected-rollback"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch"]

_TERMINAL_STACK_STATUSES = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})

_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _poll_stack_status(cf, stack_id: str, *, budget_s: float = 300.0) -> str:
    """Poll DescribeStacks for ``stack_id`` until its status is terminal; return that status."""
    deadline = time.monotonic() + budget_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {budget_s:.0f}s")
        time.sleep(3)


def _destroy_stack(cf, stack_id: str, *, budget_s: float = 300.0) -> None:
    """Delete ``stack_id`` and wait for DELETE_COMPLETE; raise naming the cause otherwise."""
    current = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if current == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _poll_stack_status(cf, stack_id, budget_s=budget_s)
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


def _events(cf, stack_id: str) -> list:
    """Every DescribeStackEvents row of ``stack_id``, oldest first."""
    rows = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cf.describe_stack_events(**kwargs)
        rows.extend(page["StackEvents"])
        token = page.get("NextToken")
        if not token:
            return rows[::-1]
        kwargs["NextToken"] = token


def _create_failed_reason(cf, stack_id: str, logical_id: str) -> str:
    """The single CREATE_FAILED ResourceStatusReason of ``logical_id`` in ``stack_id``."""
    rows = [e.get("ResourceStatusReason") for e in _events(cf, stack_id)
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(rows) == 1, f"expected one CREATE_FAILED row for {logical_id!r}, got {rows!r}"
    return rows[0]


def _masked_handler_error(reason: str, account: str, *names: str) -> tuple:
    """``(message, HandlerErrorCode)`` of a resource-handler reason, with volatile parts masked."""
    match = _HANDLER_REASON.match(reason or "")
    assert match is not None, f"not a resource-handler failure reason: {reason!r}"
    message = match["message"]
    message = re.sub(r"(?:Extended )?Request ID: [^,;)]+", "Request ID: <id>", message)
    message = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", message)
    message = message.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        message = message.replace(name, "<name>")
    return message, match["code"]


def _template(alarm_name: str, namespace: str, period: int) -> str:
    return json.dumps({
        "Resources": {
            "Alarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": alarm_name,
                    "Namespace": namespace,
                    "MetricName": "ProbeSignal",
                    "Statistic": "Average",
                    "Period": period,
                    "EvaluationPeriods": 1,
                    "Threshold": 50.0,
                    "ComparisonOperator": "GreaterThanThreshold",
                    "EvaluationWindow": {"WallClockWindow": {}},
                },
            },
        },
    })


_REJECTED = (
    "Wall Clock evaluation period must be 1 minute, 5 minutes, 1 hour, 1 day or 1 week. "
    "(Service: CloudWatch, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "GeneralServiceException",
)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed alarm with a wall clock evaluation window and a Period of 120 seconds is
    rejected and rolled back with CloudWatch's exact message; the same alarm at Period 300 deploys.
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("Sim2RealBehavWallClockNeg")

    good_stack_name = ctx.unique_name("sim2real-behav-cwwcgoodstk-")
    good_alarm_name = ctx.unique_name("sim2real-behav-cwwcgoodalm-")
    good_stack_id = cf.create_stack(
        StackName=good_stack_name, TemplateBody=_template(good_alarm_name, namespace, 300),
        Tags=[{"Key": "sim2real", "Value": good_stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _destroy_stack(cf, good_stack_id))
    status = _poll_stack_status(cf, good_stack_id)
    assert status == "CREATE_COMPLETE", f"positive-control stack ended {status!r}"
    good_alarms = cw.describe_alarms(AlarmNames=[good_alarm_name])["MetricAlarms"]
    assert len(good_alarms) == 1, f"expected the control alarm {good_alarm_name!r}, got {good_alarms!r}"
    assert good_alarms[0]["EvaluationWindow"] == {"WallClockWindow": {}}, (
        f"expected the control's EvaluationWindow to be a wall clock window, "
        f"got {good_alarms[0]['EvaluationWindow']!r}"
    )

    bad_stack_name = ctx.unique_name("sim2real-behav-cwwcbadstk-")
    bad_alarm_name = ctx.unique_name("sim2real-behav-cwwcbadalm-")
    bad_stack_id = cf.create_stack(
        StackName=bad_stack_name, TemplateBody=_template(bad_alarm_name, namespace, 120),
        Tags=[{"Key": "sim2real", "Value": bad_stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _destroy_stack(cf, bad_stack_id))
    status = _poll_stack_status(cf, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"invalid-period stack ended {status!r}"

    reason = _create_failed_reason(cf, bad_stack_id, "Alarm")
    got = _masked_handler_error(reason, ctx.account, bad_stack_name, bad_alarm_name)
    assert got == _REJECTED, f"CREATE_FAILED (masked message, handler code) {got!r}, expected {_REJECTED!r}"

    bad_alarms = cw.describe_alarms(AlarmNames=[bad_alarm_name])["MetricAlarms"]
    assert bad_alarms == [], f"expected no alarm named {bad_alarm_name!r} after rollback, got {bad_alarms!r}"

    # The control, built before the rejection, is unaffected by it.
    still = cw.describe_alarms(AlarmNames=[good_alarm_name])["MetricAlarms"]
    assert len(still) == 1, f"control alarm {good_alarm_name!r} vanished after the rejection, got {still!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
