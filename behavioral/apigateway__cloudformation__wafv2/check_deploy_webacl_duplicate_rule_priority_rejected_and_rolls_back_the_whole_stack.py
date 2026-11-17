"""deploy-webacl-duplicate-rule-priority-rejected-and-rolls-back-the-whole-stack."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-webacl-duplicate-rule-priority-rejected-and-rolls-back-the-whole-stack"
GROUP = "cloudformation"
SERVICES = ["apigateway", "cloudformation", "wafv2"]

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})
_STACK_BUDGET_S = 300.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll ``probe()`` until ``predicate`` holds; raise naming the last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s; last was {last!r}")


def _stack_status_or_gone(cfn, stack_name):
    """A stack's status, reading a name DescribeStacks no longer resolves as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ValidationError" and "does not exist" in (err.get("Message") or ""):
            return "DELETE_COMPLETE"
        raise


def _delete_stack(cfn, stack_name):
    """Delete the stack and wait for DELETE_COMPLETE; raise naming the failed resources."""
    status = _stack_status_or_gone(cfn, stack_name)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_name)
    final = _poll_until(lambda: _stack_status_or_gone(cfn, stack_name),
                         lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED"},
                         timeout_s=_STACK_BUDGET_S, description=f"stack {stack_name} delete")
    if final != "DELETE_COMPLETE":
        reasons = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                   for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
                   if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_name} delete ended {final!r}: {reasons!r}")


def _rule(name: str, priority: int, metric: str) -> dict:
    return {
        "Name": name,
        "Priority": priority,
        "Action": {"Count": {}},
        "Statement": {
            "ByteMatchStatement": {
                "SearchString": "probe",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            },
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": metric,
        },
    }


def _template(*, api_name: str, webacl_name: str, rules: list[dict]) -> str:
    """An API Gateway REST API alongside a REGIONAL WebACL carrying ``rules``."""
    return json.dumps({
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": api_name},
            },
            "WebAcl": {
                "Type": "AWS::WAFv2::WebACL",
                "Properties": {
                    "Name": webacl_name,
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": False,
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": webacl_name.replace("-", ""),
                    },
                    "Rules": rules,
                },
            },
        },
    })


def _masked_handler_reason(reason: str) -> str:
    """``reason`` with its per-call request id, request token and attempt count blanked out."""
    text = re.sub(r"Request ID: [0-9a-f-]+", "Request ID: <request-id>", reason)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <request-token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text


def _rest_api_gone(ag, api_name: str) -> bool:
    """True once no REST API named ``api_name`` is listed (rollback deletes it)."""
    for page in ag.get_paginator("get_rest_apis").paginate():
        if any(a["name"] == api_name for a in page["items"]):
            return False
    return True


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """CloudFormation rejects a WebACL whose rules share one Priority and rolls the whole stack
    back, leaving no REST API it would otherwise have created beside it.
    """
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    wafv2 = ctx.client("wafv2")

    # ---- positive control: two rules with distinct priorities deploy cleanly ------------------
    good_api_name = ctx.unique_name("sim2real-xsvc-api-")
    good_webacl_name = ctx.unique_name("sim2real-xsvc-acl-")
    good_stack_name = ctx.unique_name("sim2real-xsvc-stk-")
    good_rules = [_rule("First", 0, good_webacl_name.replace("-", "") + "a"),
                  _rule("Second", 1, good_webacl_name.replace("-", "") + "b")]

    cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=_template(api_name=good_api_name, webacl_name=good_webacl_name,
                                rules=good_rules),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack_name))

    good_status = _poll_until(lambda: _stack_status_or_gone(cfn, good_stack_name),
                               lambda s: s in _STACK_TERMINAL,
                               timeout_s=_STACK_BUDGET_S, description=f"stack {good_stack_name}")
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack_name!r} (distinct priorities) ended {good_status!r}, "
        f"not CREATE_COMPLETE"
    )
    good_resources = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.list_stack_resources(StackName=good_stack_name)["StackResourceSummaries"]
    }
    good_webacl_id = good_resources["WebAcl"].split("|")[1]
    read_back = wafv2.get_web_acl(Name=good_webacl_name, Scope="REGIONAL", Id=good_webacl_id)
    priorities = sorted(r["Priority"] for r in read_back["WebACL"]["Rules"])
    assert priorities == [0, 1], (
        f"the control WebACL's two rules must read back with priorities 0 and 1; got {priorities!r}"
    )

    # ---- break exactly one thing: both rules now share Priority 0 -----------------------------
    bad_api_name = ctx.unique_name("sim2real-xsvc-api-")
    bad_webacl_name = ctx.unique_name("sim2real-xsvc-acl-")
    bad_stack_name = ctx.unique_name("sim2real-xsvc-stk-")
    bad_rules = [_rule("First", 0, bad_webacl_name.replace("-", "") + "a"),
                 _rule("Second", 0, bad_webacl_name.replace("-", "") + "b")]

    cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=_template(api_name=bad_api_name, webacl_name=bad_webacl_name, rules=bad_rules),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack_name))

    bad_status = _poll_until(lambda: _stack_status_or_gone(cfn, bad_stack_name),
                              lambda s: s in _STACK_TERMINAL,
                              timeout_s=_STACK_BUDGET_S, description=f"stack {bad_stack_name}")
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a WebACL with two rules at the same Priority must fail the stack and roll it back; "
        f"{bad_stack_name!r} ended {bad_status!r}"
    )

    events = cfn.describe_stack_events(StackName=bad_stack_name)["StackEvents"]
    failed = [e for e in events
              if e["LogicalResourceId"] == "WebAcl" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert failed, f"expected a CREATE_FAILED event for WebAcl; events were {events!r}"
    reason = _masked_handler_reason(failed[0]["ResourceStatusReason"])
    expected_reason = (
        'Resource handler returned message: "Error reason: You have a duplicate priority. '
        'Priorities must be unique., field: RULE, parameter: 0 (Service: Wafv2, Status Code: '
        '400, Request ID: <request-id>) (SDK Attempt Count: <n>)" '
        "(RequestToken: <request-token>, HandlerErrorCode: InvalidRequest)"
    )
    assert reason == expected_reason, (
        f"the WebAcl CREATE_FAILED reason, with its request id/token masked, must read "
        f"{expected_reason!r}; got {reason!r}"
    )

    # ---- the effect is absent: the REST API the same template requested was never left behind -
    assert _rest_api_gone(ag, bad_api_name), (
        f"a REST API named {bad_api_name!r} survived a stack that rolled back"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
