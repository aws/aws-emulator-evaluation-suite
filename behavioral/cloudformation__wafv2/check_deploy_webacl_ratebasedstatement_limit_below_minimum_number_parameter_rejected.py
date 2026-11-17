"""deploy-webacl-ratebasedstatement-limit-below-minimum-number-parameter-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-webacl-ratebasedstatement-limit-below-minimum-number-parameter-rejected"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "wafv2"]

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


def _visibility(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _tag(value):
    """A template tag the propagated stack tag (key sim2real) never carries."""
    return [{"Key": "sim2real-waf", "Value": value}]


def _marker_pages(fn, key, **kw):
    """Every ``key`` item across NextMarker pages of a WAFv2 list call (no paginator)."""
    out = []
    while True:
        page = fn(**kw)
        out += page.get(key, [])
        if not page.get("NextMarker") or not page.get(key):
            return out
        kw = {**kw, "NextMarker": page["NextMarker"]}


_MIN_LIMIT = 10  # WAFv2 RateBasedStatement.Limit's documented minimum


def _template(webacl_name, limit_param_default=None):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "RateLimitParam": {"Type": "Number"},
            "PriorityParam": {"Type": "Number"},
        },
        "Resources": {
            "WebACL": {
                "Type": "AWS::WAFv2::WebACL",
                "Properties": {
                    "Name": webacl_name,
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "VisibilityConfig": _visibility(webacl_name.replace("-", "")),
                    "Rules": [
                        {
                            "Name": "RateRule",
                            "Priority": {"Ref": "PriorityParam"},
                            "Action": {"Block": {}},
                            "Statement": {
                                "RateBasedStatement": {
                                    "Limit": {"Ref": "RateLimitParam"},
                                    "AggregateKeyType": "IP",
                                }
                            },
                            "VisibilityConfig": _visibility("RateRuleMetric"),
                        }
                    ],
                    "Tags": _tag("webacl"),
                },
            }
        },
        "Outputs": {
            "WebACLId": {"Value": {"Fn::GetAtt": "WebACL.Id"}},
            "WebACLArn": {"Value": {"Fn::GetAtt": "WebACL.Arn"}},
        },
    })


def _rejected(account, name, bad_limit):
    return (
        f"1 validation error detected: Value '{bad_limit}' at "
        "'rules.1.member.statement.rateBasedStatement.limit' failed to satisfy constraint: "
        f"Member must have value greater than or equal to {_MIN_LIMIT} (Service: Wafv2, "
        "Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
        "GeneralServiceException",
    )


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A WebACL rule's RateBasedStatement Limit, given as a Ref to a Number parameter below
    WAFv2's minimum, fails to create with WAFv2's exact validation reason and leaves no web
    ACL of its name; the same template with a valid value deploys and reads back the limit."""
    cf = ctx.client("cloudformation")
    wafv2 = ctx.client("wafv2")
    webacl_name = ctx.unique_name("sim2real-xsvc-wafv2-numrefneg-acl-")
    bad_limit = _MIN_LIMIT - 1

    def own_web_acls():
        return [r["ARN"] for r in _marker_pages(wafv2.list_web_acls, "WebACLs", Scope="REGIONAL")
                if r["Name"] == webacl_name]

    bad_id = create_stack(
        ctx, cf, ctx.unique_name("sim2real-xsvc-wafv2-numrefnegstack-"), _template(webacl_name),
        Parameters=[
            {"ParameterKey": "RateLimitParam", "ParameterValue": str(bad_limit)},
            {"ParameterKey": "PriorityParam", "ParameterValue": "5"},
        ],
    )
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    expected = _rejected(ctx.account, webacl_name, bad_limit)
    got = handler_reason(failed_reason(stack_events(cf, bad_id), "WebACL"), ctx.account,
                         webacl_name)
    assert got == expected, f"handler reason {got!r}, expected {expected!r}"
    listed = own_web_acls()
    assert listed == [], f"web ACLs named {webacl_name!r} after the rollback: {listed!r}"

    # Positive control: the same template with a valid Limit value.
    good_limit = _MIN_LIMIT
    stack = ctx.unique_name("sim2real-xsvc-wafv2-numrefnegstack-good-")
    good_id = create_stack(
        ctx, cf, stack, _template(webacl_name),
        Parameters=[
            {"ParameterKey": "RateLimitParam", "ParameterValue": str(good_limit)},
            {"ParameterKey": "PriorityParam", "ParameterValue": "5"},
        ],
    )
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cf, good_id)
    assert own_web_acls() == [out["WebACLArn"]], f"web ACLs named {webacl_name!r}: {own_web_acls()!r}"
    acl = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=out["WebACLId"])["WebACL"]
    limit = acl["Rules"][0]["Statement"]["RateBasedStatement"]["Limit"]
    assert limit == good_limit, f"control web ACL Limit {limit!r}, expected {good_limit!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
