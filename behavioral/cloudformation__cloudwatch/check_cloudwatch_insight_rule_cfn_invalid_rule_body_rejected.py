"""cloudwatch-insight-rule-cfn-invalid-rule-body-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "cloudwatch-insight-rule-cfn-invalid-rule-body-rejected"
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


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "INVALID_RULE_BODY: MissingKey encountered at Contribution in the RuleBody. "
    "(Service: CloudWatch, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _rule_body(log_group: str, *, valid: bool) -> dict:
    body = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": [log_group],
        "LogFormat": "JSON",
        "AggregateOn": "Count",
    }
    if valid:
        body["Contribution"] = {"Keys": ["$.clientIp"], "Filters": []}
    return body


def _template(rule_name: str, log_group: str, *, valid: bool) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Rule": {
                "Type": "AWS::CloudWatch::InsightRule",
                "Properties": {
                    "RuleName": rule_name,
                    "RuleState": "ENABLED",
                    "RuleBody": json.dumps(_rule_body(log_group, valid=valid)),
                },
            },
        },
    })


def _find_rule(cw, rule_name):
    """The rule named ``rule_name``; DescribeInsightRules has no paginator, so every page is read."""
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = cw.describe_insight_rules(**kwargs)
        for rule in page.get("InsightRules", []):
            if rule["Name"] == rule_name:
                return rule
        token = page.get("NextToken")
        if not token:
            return None


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation InsightRule with a RuleBody missing the required Contribution key is
    rejected and rolled back with CloudWatch's exact message; a rule body differing only by
    that key deploys and is visible through DescribeInsightRules.
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    good_stack = ctx.unique_name("sim2real-xsvc-cwirulebad-good-")
    good_rule = ctx.unique_name("sim2real-xsvc-cwirulebad-good-")
    good_lg = ctx.unique_name("sim2real-xsvc-cwirulebad-good-lg-")

    bad_stack = ctx.unique_name("sim2real-xsvc-cwirulebad-bad-")
    bad_rule = ctx.unique_name("sim2real-xsvc-cwirulebad-bad-")
    bad_lg = ctx.unique_name("sim2real-xsvc-cwirulebad-bad-lg-")

    # ---- positive control: the same resource type, valid RuleBody, succeeds ----
    good_id = create_stack(ctx, cf, good_stack, _template(good_rule, good_lg, valid=True))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"positive-control stack status is {status!r}"
    rule = _find_rule(cw, good_rule)
    assert rule is not None, (
        f"positive-control rule {good_rule!r} not visible in DescribeInsightRules"
    )
    assert rule["State"] == "ENABLED", (
        f"positive-control rule State is {rule['State']!r}, expected 'ENABLED'"
    )
    want_body = _rule_body(good_lg, valid=True)
    assert json.loads(rule["Definition"]) == want_body, (
        f"positive-control rule Definition is {rule['Definition']!r}, expected {want_body!r}"
    )

    # ---- negative: RuleBody missing Contribution is rejected ----
    bad_id = create_stack(ctx, cf, bad_stack, _template(bad_rule, bad_lg, valid=False))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"invalid-RuleBody stack status is {status!r}"

    reason = failed_reason(stack_events(cf, bad_id), "Rule")
    got = handler_reason(reason, ctx.account, bad_stack, bad_rule, bad_lg)
    assert got == _REJECTED, f"CREATE_FAILED (masked message, handler code) {got!r}, expected {_REJECTED!r}"
    assert _find_rule(cw, bad_rule) is None, (
        f"rejected rule {bad_rule!r} is visible in DescribeInsightRules after rollback"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
