"""deploy-ec2-traffic-mirror-filter-and-rule-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-traffic-mirror-filter-and-rule-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

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

_SOURCE_CIDR = "10.120.0.0/24"
_DEST_CIDR = "10.120.1.0/24"
_RULE_NUMBER = 100
_PORT_RANGE = {"FromPort": 443, "ToPort": 443}


def _template(name, port_range=None, with_rule=True):
    resources = {"Filter": {"Type": "AWS::EC2::TrafficMirrorFilter", "Properties": {
        "Description": "sim2real traffic mirror filter",
        "NetworkServices": ["amazon-dns"],
        "Tags": [{"Key": "sim2real-tmf", "Value": name}],
    }}}
    outputs = {"FilterId": {"Value": {"Ref": "Filter"}}}
    if with_rule:
        resources["Rule"] = {"Type": "AWS::EC2::TrafficMirrorFilterRule", "Properties": {
            "TrafficMirrorFilterId": {"Ref": "Filter"},
            "TrafficDirection": "ingress",
            "RuleNumber": _RULE_NUMBER,
            "RuleAction": "accept",
            "SourceCidrBlock": _SOURCE_CIDR,
            "DestinationCidrBlock": _DEST_CIDR,
            "Protocol": 6,
            "DestinationPortRange": port_range or _PORT_RANGE,
        }}
        outputs["RuleId"] = {"Value": {"Ref": "Rule"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _filters(ec2, stack):
    """``(id, description, network services, own tags)`` of each filter with the stack tag."""
    return [(f["TrafficMirrorFilterId"], f["Description"], f["NetworkServices"],
             {t["Key"]: t["Value"] for t in f.get("Tags", []) if not t["Key"].startswith("aws:")})
            for f in paginate(ec2, "describe_traffic_mirror_filters", "TrafficMirrorFilters",
                              Filters=[{"Name": "tag:sim2real", "Values": [stack]}])]


def _rules(ec2, filter_id):
    """The filter's rules; DescribeTrafficMirrorFilterRules has no botocore paginator."""
    rows, kw = [], {}
    while True:
        page = ec2.describe_traffic_mirror_filter_rules(TrafficMirrorFilterId=filter_id, **kw)
        rows.extend(page["TrafficMirrorFilterRules"])
        if not page.get("NextToken"):
            break
        kw = {"NextToken": page["NextToken"]}
    return [(r["TrafficMirrorFilterRuleId"], r["TrafficDirection"], r["RuleNumber"],
             r["RuleAction"], r["SourceCidrBlock"], r["DestinationCidrBlock"], r["Protocol"],
             r["DestinationPortRange"]) for r in rows]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation TrafficMirrorFilter and its rule read back through EC2 by independent
    reads; an update dropping the rule removes it while the filter answers, and deleting the
    stack removes the filter.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2tmf-")

    stack_id = create_stack(ctx, cfn, stack, _template(stack))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    filter_id, rule_id = out["FilterId"], out["RuleId"]
    want = [(filter_id, "sim2real traffic mirror filter", ["amazon-dns"],
             {"sim2real": stack, "sim2real-tmf": stack})]
    assert _filters(ec2, stack) == want, f"filters by stack tag {_filters(ec2, stack)!r}"
    want = [(rule_id, "ingress", _RULE_NUMBER, "accept", _SOURCE_CIDR, _DEST_CIDR, 6,
             _PORT_RANGE)]
    assert _rules(ec2, filter_id) == want, f"rules of the filter {_rules(ec2, filter_id)!r}"

    # The rule's own delete: an update drops it while the same filter still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, with_rule=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"rule-removing update ended {status!r}"
    refused = ("InvalidTrafficMirrorFilterRuleId.NotFound", f"{rule_id} does not exist")
    expect_error(
        lambda: ec2.describe_traffic_mirror_filter_rules(
        TrafficMirrorFilterRuleIds=[rule_id]),
        *refused,
    )
    assert [f[0] for f in _filters(ec2, stack)] == [filter_id], "filter gone after the update"

    delete_stack(cfn, stack_id)
    refused = ("InvalidTrafficMirrorFilterId.NotFound", f"{filter_id} does not exist")
    expect_error(
        lambda: ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id]),
        *refused,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
