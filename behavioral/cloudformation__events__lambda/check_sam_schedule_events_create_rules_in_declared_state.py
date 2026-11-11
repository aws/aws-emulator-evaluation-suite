"""sam-schedule-events-create-rules-in-declared-state."""

from __future__ import annotations

import json
import time
from pathlib import Path

from behavioral_harness import tags

CHECK = "sam-schedule-events-create-rules-in-declared-state"
GROUP = "deploy"
SERVICES = ["cloudformation", "events", "lambda"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = "sam_schedule_events"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each Schedule event becomes an EventBridge rule targeting the function, ENABLED by default and
    DISABLED for `Enabled: false`, with a resource-policy grant scoped to that rule's ARN.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-schedule.html
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-sam-sched-")
    stack = ctx.unique_name("sim2real-sam-sched-")
    body = (DEPLOYMENTS / _TEMPLATE / "template.yaml").read_text()

    stack_id = _create_stack(ctx, cfn, stack, body, {"FunctionName": fn})
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]

    rule_arns = set()
    for logical, schedule, state in (("FnTick", "rate(1 day)", "ENABLED"),
                                     ("FnPaused", "rate(7 days)", "DISABLED")):
        name = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical)[
            "StackResourceDetail"]["PhysicalResourceId"]
        rule = events.describe_rule(Name=name)
        got = (rule["ScheduleExpression"], rule["State"])
        assert got == (schedule, state), f"{logical}: (schedule, state) {got!r}, expected {(schedule, state)!r}"
        targets = events.list_targets_by_rule(Rule=name)["Targets"]
        assert [t["Arn"] for t in targets] == [fn_arn], (
            f"{logical} must target exactly the function; got {targets!r}")
        rule_arns.add(rule["Arn"])

    statements = json.loads(lam.get_policy(FunctionName=fn)["Policy"])["Statement"]
    grants = {(s["Principal"].get("Service"), s["Action"],
               s.get("Condition", {}).get("ArnLike", {}).get("AWS:SourceArn")) for s in statements}
    want = {("events.amazonaws.com", "lambda:InvokeFunction", arn) for arn in rule_arns}
    assert grants == want, f"one events grant per rule ARN expected; got {grants!r}"


def _poll(probe, done, *, timeout_s: float, interval_s: float = 3.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by StackId and wait for DELETE_COMPLETE; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _create_stack(ctx, cfn, name: str, body: str, params: dict) -> str:
    """Create the stack with its delete registered at once; assert CREATE_COMPLETE."""
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Capabilities=_CAPS,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {name} ended {status}: {_failures(cfn, stack_id)!r}"
    return stack_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
