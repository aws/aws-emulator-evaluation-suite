"""deploy-route53-healthcheck-invalid-insufficient-data-status-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-route53-healthcheck-invalid-insufficient-data-status-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch", "route53"]

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


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


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
    "Invalid XML ; javax.xml.stream.XMLStreamException: org.xml.sax.SAXParseException; "
    "lineNumber: 1; columnNumber: <n>; cvc-pattern-valid: Value 'Bogus' is not facet-valid with "
    "respect to pattern '[Hh][Ee][Aa][Ll][Tt][Hh][Yy]|[Uu][Nn][Hh][Ee][Aa][Ll][Tt][Hh][Yy]|"
    "[Ll][Aa][Ss][Tt][Kk][Nn][Oo][Ww][Nn][Ss][Tt][Aa][Tt][Uu][Ss]' for type "
    "'InsufficientDataHealthStatus'. (Service: Route53, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(alarm_name: str, metric_name: str, insufficient_data_status: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Alarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": alarm_name,
                    "Namespace": "sim2real/healthcheck",
                    "MetricName": metric_name,
                    "Statistic": "Average",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanThreshold",
                },
            },
            "Hc": {
                "Type": "AWS::Route53::HealthCheck",
                "Properties": {
                    "HealthCheckConfig": {
                        "Type": "CLOUDWATCH_METRIC",
                        "AlarmIdentifier": {
                            "Name": {"Ref": "Alarm"}, "Region": {"Ref": "AWS::Region"},
                        },
                        "InsufficientDataHealthStatus": insufficient_data_status,
                    },
                },
            },
        },
        "Outputs": {"HcRef": {"Value": {"Ref": "Hc"}}, "AlarmRef": {"Value": {"Ref": "Alarm"}}},
    })


def _checks_on(route53, alarm_name):
    """Every health check, across all pages, whose CloudWatch alarm is ``alarm_name``."""
    return [h for h in paginate(route53, "list_health_checks", "HealthChecks")
            if h["HealthCheckConfig"].get("AlarmIdentifier", {}).get("Name") == alarm_name]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Route53 HealthCheck whose InsufficientDataHealthStatus is not an enum value fails.

    Route53's exact XML validation refusal is graded and neither the health check nor its alarm
    exists after the rollback, while the same template with Healthy deploys and reads back.
    """
    route53 = ctx.client("route53")
    cw = ctx.client("cloudwatch")
    cfn = ctx.client("cloudformation")
    good_alarm = ctx.unique_name("sim2real-r53hcposalarm-")
    bad_alarm = ctx.unique_name("sim2real-r53hcnegalarm-")
    metric = ctx.unique_name("sim2realr53hcmetric")

    # Positive control: the same template, InsufficientDataHealthStatus given a valid value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-r53hcpos-"),
                           _template(good_alarm, metric, "Healthy"))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    checks = _checks_on(route53, good_alarm)
    got = [(h["Id"], h["HealthCheckConfig"]["InsufficientDataHealthStatus"]) for h in checks]
    assert got == [(out["HcRef"], "Healthy")], f"control health checks {got!r}"
    alarms = [a["AlarmName"] for a in paginate(cw, "describe_alarms", "MetricAlarms",
                                               AlarmNames=[good_alarm])]
    assert alarms == [out["AlarmRef"]] == [good_alarm], f"control alarm {alarms!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-r53hcneg-"),
                          _template(bad_alarm, metric, "Bogus"))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"invalid-status stack ended {status!r}"
    message, code = handler_reason(failed_reason(stack_events(cfn, bad_id), "Hc"), ctx.account)
    # The parser position moves with the request's region and name lengths: mask it too.
    got = (re.sub(r"columnNumber: \d+", "columnNumber: <n>", message), code)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Route53 and CloudWatch, before any delete.
    assert _checks_on(route53, bad_alarm) == [], "a health check on the rolled-back alarm exists"
    left = paginate(cw, "describe_alarms", "MetricAlarms", AlarmNames=[bad_alarm])
    assert left == [], f"the rolled-back alarm is still described: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
