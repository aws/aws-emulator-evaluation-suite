"""deploy-webacl-rulegroup-ipset-regexpatternset-provisioned-then-removed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-webacl-rulegroup-ipset-regexpatternset-provisioned-then-removed"
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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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

_GONE = ("WAFNonexistentItemException",
         "AWS WAF couldn’t perform the operation because your resource doesn’t exist.")


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


def _tags(wafv2, arn):
    info = wafv2.list_tags_for_resource(ResourceARN=arn)["TagInfoForResource"]
    return {t["Key"]: t["Value"] for t in info.get("TagList", []) if not t["Key"].startswith("aws:")}


_RULE_GROUP_CAPACITY = 10  # measured WCU cost of the ByteMatchStatement rule below


def _template(regex_name, ipset_name, rulegroup_name, webacl_name, member_cidr, pattern):
    byte_rule_metric = "ByteRuleMetric"
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RegexSet": {
                "Type": "AWS::WAFv2::RegexPatternSet",
                "Properties": {
                    "Name": regex_name,
                    "Scope": "REGIONAL",
                    "RegularExpressionList": [pattern],
                    "Tags": _tag("regexset"),
                },
            },
            "IPSet": {
                "Type": "AWS::WAFv2::IPSet",
                "Properties": {
                    "Name": ipset_name,
                    "Scope": "REGIONAL",
                    "IPAddressVersion": "IPV4",
                    "Addresses": [member_cidr],
                    "Tags": _tag("ipset"),
                },
            },
            "RuleGroup": {
                "Type": "AWS::WAFv2::RuleGroup",
                "Properties": {
                    "Name": rulegroup_name,
                    "Scope": "REGIONAL",
                    "Capacity": _RULE_GROUP_CAPACITY,
                    "VisibilityConfig": _visibility(rulegroup_name.replace("-", "")),
                    "Rules": [
                        {
                            "Name": "ByteRule",
                            "Priority": 0,
                            "Action": {"Block": {}},
                            "Statement": {
                                "ByteMatchStatement": {
                                    "SearchString": "blocked",
                                    "FieldToMatch": {"UriPath": {}},
                                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                    "PositionalConstraint": "CONTAINS",
                                }
                            },
                            "VisibilityConfig": _visibility(byte_rule_metric),
                        }
                    ],
                    "Tags": _tag("rulegroup"),
                },
            },
            "WebACL": {
                "Type": "AWS::WAFv2::WebACL",
                "Properties": {
                    "Name": webacl_name,
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "VisibilityConfig": _visibility(webacl_name.replace("-", "")),
                    "Rules": [
                        {
                            "Name": "RuleGroupRule",
                            "Priority": 0,
                            "OverrideAction": {"None": {}},
                            "Statement": {
                                "RuleGroupReferenceStatement": {
                                    "Arn": {"Fn::GetAtt": "RuleGroup.Arn"}}
                            },
                            "VisibilityConfig": _visibility("RuleGroupRuleMetric"),
                        },
                        {
                            "Name": "IPSetRule",
                            "Priority": 1,
                            "Action": {"Block": {}},
                            "Statement": {
                                "IPSetReferenceStatement": {"Arn": {"Fn::GetAtt": "IPSet.Arn"}}
                            },
                            "VisibilityConfig": _visibility("IPSetRuleMetric"),
                        },
                        {
                            "Name": "RegexRule",
                            "Priority": 2,
                            "Action": {"Block": {}},
                            "Statement": {
                                "RegexPatternSetReferenceStatement": {
                                    "Arn": {"Fn::GetAtt": "RegexSet.Arn"},
                                    "FieldToMatch": {"UriPath": {}},
                                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                }
                            },
                            "VisibilityConfig": _visibility("RegexRuleMetric"),
                        },
                    ],
                    "Tags": _tag("webacl"),
                },
            },
        },
        "Outputs": {
            "RegexSetRef": {"Value": {"Ref": "RegexSet"}},
            "RegexSetArn": {"Value": {"Fn::GetAtt": "RegexSet.Arn"}},
            "RegexSetId": {"Value": {"Fn::GetAtt": "RegexSet.Id"}},
            "IPSetRef": {"Value": {"Ref": "IPSet"}},
            "IPSetArn": {"Value": {"Fn::GetAtt": "IPSet.Arn"}},
            "IPSetId": {"Value": {"Fn::GetAtt": "IPSet.Id"}},
            "RuleGroupRef": {"Value": {"Ref": "RuleGroup"}},
            "RuleGroupArn": {"Value": {"Fn::GetAtt": "RuleGroup.Arn"}},
            "RuleGroupId": {"Value": {"Fn::GetAtt": "RuleGroup.Id"}},
            "WebACLRef": {"Value": {"Ref": "WebACL"}},
            "WebACLArn": {"Value": {"Fn::GetAtt": "WebACL.Arn"}},
            "WebACLId": {"Value": {"Fn::GetAtt": "WebACL.Id"}},
            "WebACLLabelNamespace": {"Value": {"Fn::GetAtt": "WebACL.LabelNamespace"}},
        },
    })


@tags("axis:happy-path", "cap:c2", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack provisions a WebACL, RuleGroup, IPSet and RegexPatternSet whose Refs
    match WAFv2's own listings and whose properties, rules and tags read back exactly, and deleting
    the stack leaves every one of the four not-found through WAFv2's own API."""
    cf = ctx.client("cloudformation")
    wafv2 = ctx.client("wafv2")
    stack = ctx.unique_name("sim2real-xsvc-wafv2-stack-")
    regex_name = ctx.unique_name("sim2real-xsvc-wafv2-regex-")
    ipset_name = ctx.unique_name("sim2real-xsvc-wafv2-ipset-")
    rulegroup_name = ctx.unique_name("sim2real-xsvc-wafv2-rg-")
    webacl_name = ctx.unique_name("sim2real-xsvc-wafv2-acl-")
    member_cidr = "203.0.113.0/24"  # RFC 5737 TEST-NET-3
    pattern = "^/blocked$"

    stack_id = create_stack(ctx, cf, stack, _template(regex_name, ipset_name, rulegroup_name,
                                                      webacl_name, member_cidr, pattern))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Each Ref is "<Name>|<Id>|REGIONAL" with the Id and ARN WAFv2 lists for the declared name.
    kinds = (
        ("RegexSet", regex_name, wafv2.list_regex_pattern_sets, "RegexPatternSets"),
        ("IPSet", ipset_name, wafv2.list_ip_sets, "IPSets"),
        ("RuleGroup", rulegroup_name, wafv2.list_rule_groups, "RuleGroups"),
        ("WebACL", webacl_name, wafv2.list_web_acls, "WebACLs"),
    )
    for logical, name, lister, key in kinds:
        listed = [(e["Id"], e["ARN"]) for e in _marker_pages(lister, key, Scope="REGIONAL")
                  if e["Name"] == name]
        got = (listed, out[f"{logical}Ref"])
        want = ([(out[f"{logical}Id"], out[f"{logical}Arn"])],
                f"{name}|{out[f'{logical}Id']}|REGIONAL")
        assert got == want, f"{logical} (listed, Ref) {got!r}, expected {want!r}"
        got = _tags(wafv2, out[f"{logical}Arn"])
        want = {"sim2real": stack, "sim2real-waf": logical.lower()}
        assert got == want, f"{logical} tags {got!r}, expected {want!r}"

    got = wafv2.get_regex_pattern_set(Name=regex_name, Scope="REGIONAL",
                                      Id=out["RegexSetId"])["RegexPatternSet"]
    assert got["RegularExpressionList"] == [{"RegexString": pattern}], (
        f"RegularExpressionList {got['RegularExpressionList']!r}"
    )
    got = wafv2.get_ip_set(Name=ipset_name, Scope="REGIONAL", Id=out["IPSetId"])["IPSet"]
    assert (got["IPAddressVersion"], got["Addresses"]) == ("IPV4", [member_cidr]), (
        f"IPSet (IPAddressVersion, Addresses) {(got['IPAddressVersion'], got['Addresses'])!r}"
    )
    got = wafv2.get_rule_group(Name=rulegroup_name, Scope="REGIONAL",
                               Id=out["RuleGroupId"])["RuleGroup"]
    rule = got["Rules"][0]
    read = (got["Capacity"], got["VisibilityConfig"], rule["Name"], rule["Priority"],
            rule["Action"], rule["Statement"]["ByteMatchStatement"]["SearchString"],
            rule["VisibilityConfig"])
    want = (_RULE_GROUP_CAPACITY, _visibility(rulegroup_name.replace("-", "")), "ByteRule", 0,
            {"Block": {}}, b"blocked", _visibility("ByteRuleMetric"))
    assert read == want, f"RuleGroup reads {read!r}, expected {want!r}"

    acl = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=out["WebACLId"])["WebACL"]
    namespace = f"awswaf:{ctx.account}:webacl:{webacl_name}:"
    read = (out["WebACLLabelNamespace"], acl["LabelNamespace"], acl["DefaultAction"],
            acl["VisibilityConfig"])
    want = (namespace, namespace, {"Allow": {}}, _visibility(webacl_name.replace("-", "")))
    assert read == want, f"WebACL (GetAtt namespace, namespace, default, visibility) {read!r}"
    rules = sorted((r["Priority"], r["Name"], r.get("Action"), r.get("OverrideAction"),
                    r["VisibilityConfig"]["MetricName"]) for r in acl["Rules"])
    want = [(0, "RuleGroupRule", None, {"None": {}}, "RuleGroupRuleMetric"),
            (1, "IPSetRule", {"Block": {}}, None, "IPSetRuleMetric"),
            (2, "RegexRule", {"Block": {}}, None, "RegexRuleMetric")]
    assert rules == want, f"WebACL rules (priority, name, action, override, metric) {rules!r}"
    by_name = {r["Name"]: r["Statement"] for r in acl["Rules"]}
    regex_stmt = by_name["RegexRule"]["RegexPatternSetReferenceStatement"]
    got = (by_name["RuleGroupRule"]["RuleGroupReferenceStatement"]["ARN"],
           by_name["IPSetRule"]["IPSetReferenceStatement"]["ARN"],
           regex_stmt["ARN"], regex_stmt["TextTransformations"])
    want = (out["RuleGroupArn"], out["IPSetArn"], out["RegexSetArn"],
            [{"Priority": 0, "Type": "NONE"}])
    assert got == want, f"WebACL references {got!r}, expected {want!r}"

    delete_stack(cf, stack_id)
    expect_error(lambda: wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL",
                                           Id=out["WebACLId"]), *_GONE)
    expect_error(lambda: wafv2.get_rule_group(Name=rulegroup_name, Scope="REGIONAL",
                                              Id=out["RuleGroupId"]), *_GONE)
    expect_error(lambda: wafv2.get_ip_set(Name=ipset_name, Scope="REGIONAL",
                                          Id=out["IPSetId"]), *_GONE)
    expect_error(lambda: wafv2.get_regex_pattern_set(Name=regex_name, Scope="REGIONAL",
                                                     Id=out["RegexSetId"]), *_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
