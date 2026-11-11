"""deploy-loggingconfiguration-provisioned-then-removed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-loggingconfiguration-provisioned-then-removed"
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


def _template(webacl_name, log_group_name, with_logging=True):
    resources = {
        "WebACL": {
            "Type": "AWS::WAFv2::WebACL",
            "Properties": {
                "Name": webacl_name,
                "Scope": "REGIONAL",
                "DefaultAction": {"Allow": {}},
                "VisibilityConfig": _visibility(webacl_name.replace("-", "")),
                "Tags": _tag("webacl"),
            },
        },
        "LogGroup": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {"LogGroupName": log_group_name, "RetentionInDays": 1},
        },
    }
    outputs = {
        "WebACLArn": {"Value": {"Fn::GetAtt": "WebACL.Arn"}},
        "WebACLId": {"Value": {"Fn::GetAtt": "WebACL.Id"}},
    }
    if with_logging:
        resources["LoggingConfig"] = {
            "Type": "AWS::WAFv2::LoggingConfiguration",
            "Properties": {
                "ResourceArn": {"Fn::GetAtt": "WebACL.Arn"},
                "LogDestinationConfigs": [{"Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:"
                                           f"${{AWS::AccountId}}:log-group:{log_group_name}"}],
            },
        }
        outputs["LoggingConfigRef"] = {"Value": {"Ref": "LoggingConfig"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


@tags("axis:happy-path", "cap:c2", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation LoggingConfiguration's Ref is its web ACL's ARN and its destination reads
    back exactly through WAFv2; an update dropping it leaves GetLoggingConfiguration not-found while
    the web ACL answers, and deleting the stack removes the web ACL."""
    cf = ctx.client("cloudformation")
    wafv2 = ctx.client("wafv2")
    stack = ctx.unique_name("sim2real-xsvc-wafv2-logstack-")
    webacl_name = ctx.unique_name("sim2real-xsvc-wafv2-logacl-")
    log_group_name = ctx.unique_name("aws-waf-logs-sim2real-xsvc-")

    stack_id = create_stack(ctx, cf, stack, _template(webacl_name, log_group_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    webacl_arn = out["WebACLArn"]
    listed = [a["ARN"] for a in _marker_pages(wafv2.list_web_acls, "WebACLs", Scope="REGIONAL")
              if a["Name"] == webacl_name]
    assert listed == [webacl_arn], f"ListWebACLs {listed!r} for GetAtt Arn {webacl_arn!r}"
    got = _tags(wafv2, webacl_arn)
    assert got == {"sim2real": stack, "sim2real-waf": "webacl"}, f"web ACL tags {got!r}"

    # Ref for AWS::WAFv2::LoggingConfiguration is the ResourceArn (the web ACL's ARN).
    assert out["LoggingConfigRef"] == webacl_arn, (
        f"Ref(LoggingConfig) {out['LoggingConfigRef']!r}, expected the web ACL ARN {webacl_arn!r}"
    )
    partition = stack_id.split(":")[1]
    destination = f"arn:{partition}:logs:{ctx.region}:{ctx.account}:log-group:{log_group_name}"
    got = wafv2.get_logging_configuration(ResourceArn=webacl_arn)["LoggingConfiguration"]
    got = (got["ResourceArn"], got["LogDestinationConfigs"])
    assert got == (webacl_arn, [destination]), f"logging configuration reads {got!r}"

    # Child first: the update drops the logging configuration while the web ACL still answers.
    cf.update_stack(StackName=stack_id,
                    TemplateBody=_template(webacl_name, log_group_name, with_logging=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"logging-dropping update ended {status!r}"
    expect_error(lambda: wafv2.get_logging_configuration(ResourceArn=webacl_arn), *_GONE)
    acl = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=out["WebACLId"])["WebACL"]
    assert acl["ARN"] == webacl_arn, f"web ACL after the update reads {acl['ARN']!r}"

    delete_stack(cf, stack_id)
    expect_error(lambda: wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL",
                                           Id=out["WebACLId"]), *_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
