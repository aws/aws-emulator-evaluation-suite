"""deploy-cloudformation-alarm-mute-rule-malformed-schedule-rejected-rollback."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-alarm-mute-rule-malformed-schedule-rejected-rollback"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "Schedule is malformed. (Service: CloudWatch, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "GeneralServiceException",
)
_NO_MUTE_RULE = ("ResourceNotFoundException", "")


# CloudFormation's resource-handler wrapping of the service error; the request id, token and
# SDK attempt count vary.
@tags(
    "axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control",
)
def run(ctx) -> None:
    """A CFN AlarmMuteRule with a malformed schedule expression is rejected and the stack rolls
    back creating nothing, while the identical template with a valid expression succeeds.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAlarmMuteRule.html
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    bad_stack_name = ctx.unique_name("sim2real-behav-mutebad-")
    bad_mute_name = ctx.unique_name("sim2real-behav-mutebad-")
    target_alarm_name = ctx.unique_name("sim2real-behav-mutetarget-")

    def _template(expression: str, name: str) -> str:
        return json.dumps({
            "Resources": {
                "MuteRule": {
                    "Type": "AWS::CloudWatch::AlarmMuteRule",
                    "Properties": {
                        "Name": name,
                        "Rule": {"Schedule": {"Expression": expression, "Duration": "PT1H"}},
                        "MuteTargets": {"AlarmNames": [target_alarm_name]},
                    },
                },
            },
        })

    # ---- Negative: a malformed cron expression is refused and nothing is created. ----
    bad_id = create_stack(ctx, cf, bad_stack_name, _template("not-a-valid-cron", bad_mute_name))
    bad_status = wait_stack(cf, bad_id, timeout_s=180.0)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a malformed schedule expression should roll the stack back, got {bad_status!r}"
    )
    reason = failed_reason(stack_events(cf, bad_id), "MuteRule")
    got_error = handler_reason(reason, ctx.account, bad_stack_name, bad_mute_name)
    assert got_error == _REJECTED, f"CREATE_FAILED reason: expected {_REJECTED!r}, got {got_error!r}"

    expect_error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=bad_mute_name), *_NO_MUTE_RULE)

    # ---- Positive control: the identical template with a valid expression succeeds. ----
    good_stack_name = ctx.unique_name("sim2real-behav-mutegood-")
    good_mute_name = ctx.unique_name("sim2real-behav-mutegood-")
    good_id = create_stack(ctx, cf, good_stack_name, _template("cron(0 4 * * *)", good_mute_name))
    good_status = wait_stack(cf, good_id, timeout_s=180.0)
    assert good_status == "CREATE_COMPLETE", (
        f"the control create, differing only in the schedule expression, must succeed; "
        f"got {good_status!r}"
    )
    good = cw.get_alarm_mute_rule(AlarmMuteRuleName=good_mute_name)
    assert good["MuteTargets"] == {"AlarmNames": [target_alarm_name]}, (
        f"expected the control's mute target {[target_alarm_name]!r}, got {good['MuteTargets']!r}"
    )
    assert good["Name"] == good_mute_name, f"expected the control's name, got {good['Name']!r}"
    want_rule = {"Schedule": {"Expression": "cron(0 4 * * *)", "Duration": "PT1H", "Timezone": "UTC"}}
    assert good["Rule"] == want_rule, f"expected the control's rule {want_rule!r}, got {good['Rule']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
