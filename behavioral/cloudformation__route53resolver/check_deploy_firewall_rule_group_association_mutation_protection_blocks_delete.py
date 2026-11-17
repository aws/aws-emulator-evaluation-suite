"""deploy-firewall-rule-group-association-mutation-protection-blocks-delete."""

from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-firewall-rule-group-association-mutation-protection-blocks-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "route53resolver"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_TRACE_ID_RE = re.compile(r'Trace Id: "[0-9a-f-]+"')


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, timeout_s, description, interval_s=5.0):
    """Call ``probe`` until ``done(result)``; return the result.

    A spent run budget raises TimeoutError (not graded); the wait's own deadline fails the check.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} not met within {timeout_s:.0f}s: {last!r}")
        time.sleep(interval_s)


def wait_stack(ctx, cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    return _poll(
        ctx,
        lambda: cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"],
        lambda status: status in terminal,
        timeout_s,
        f"stack {stack_id} reaching one of {sorted(terminal)}",
        interval_s=2.0,
    )


def delete_stack(ctx, cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(ctx, cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        ctx, cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def create_stack(ctx, cf, r53r, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises,
    and its association's MutationProtection is disabled first, whatever state the create reached.
    """
    created = {}
    ctx.on_cleanup(
        lambda: (
            _unprotect_and_delete(ctx, r53r, cf, created["StackId"])
            if created.get("StackId")
            else None
        )
    )
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
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
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
    text = _TRACE_ID_RE.sub('Trace Id: "<trace-id>"', m["message"])
    return masked(text, account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

_DOMAIN = "blocked.example.com."


def _template(
    domain_list_name, rule_group_name, assoc_name, priority=101, mutation_protection="ENABLED"
) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.214.0.0/16"}},
                "DomainList": {
                    "Type": "AWS::Route53Resolver::FirewallDomainList",
                    "Properties": {"Name": domain_list_name, "Domains": [_DOMAIN]},
                },
                "RuleGroup": {
                    "Type": "AWS::Route53Resolver::FirewallRuleGroup",
                    "Properties": {
                        "Name": rule_group_name,
                        "FirewallRules": [
                            {
                                "FirewallDomainListId": {"Ref": "DomainList"},
                                "Priority": 100,
                                "Action": "BLOCK",
                                "BlockResponse": "NXDOMAIN",
                            }
                        ],
                    },
                },
                "Association": {
                    "Type": "AWS::Route53Resolver::FirewallRuleGroupAssociation",
                    "DependsOn": ["RuleGroup", "Vpc"],
                    "Properties": {
                        "FirewallRuleGroupId": {"Ref": "RuleGroup"},
                        "VpcId": {"Ref": "Vpc"},
                        "Priority": priority,
                        "MutationProtection": mutation_protection,
                        "Name": assoc_name,
                    },
                },
            },
            "Outputs": {
                "VpcRef": {"Value": {"Ref": "Vpc"}},
                "RuleGroupRef": {"Value": {"Ref": "RuleGroup"}},
                "AssocRef": {"Value": {"Ref": "Association"}},
                "AssocArn": {"Value": {"Fn::GetAtt": ["Association", "Arn"]}},
            },
        }
    )


def _association_id(cf, stack_id):
    """The stack's live Association physical id, or None when it has none (never created, or
    already deleted)."""
    rows = paginate(cf, "list_stack_resources", "StackResourceSummaries", StackName=stack_id)
    ids = [
        r.get("PhysicalResourceId")
        for r in rows
        if r["LogicalResourceId"] == "Association"
        and r["ResourceStatus"] not in ("DELETE_COMPLETE", "CREATE_FAILED")
    ]
    return ids[0] if ids and ids[0] else None


def _unprotect_and_delete(ctx, r53r, cf, stack_id):
    """Disable the association's MutationProtection, wait for Resolver to apply it, then delete
    the stack by StackId and raise unless it reaches DELETE_COMPLETE."""
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status != "DELETE_IN_PROGRESS":
        wait_stack(ctx, cf, stack_id, _TERMINAL, 300.0)
    assoc_id = _association_id(cf, stack_id)
    if assoc_id is not None:
        r53r.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id, MutationProtection="DISABLED"
        )
        _poll(
            ctx,
            lambda: r53r.get_firewall_rule_group_association(
                FirewallRuleGroupAssociationId=assoc_id
            )["FirewallRuleGroupAssociation"],
            lambda a: (a["Status"], a["MutationProtection"]) == ("COMPLETE", "DISABLED"),
            120.0,
            f"association {assoc_id} COMPLETE with MutationProtection DISABLED",
            interval_s=2.0,
        )
    delete_stack(ctx, cf, stack_id)


_REJECTED_CODE = "InvalidRequest"


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation FirewallRuleGroupAssociation's MutationProtection reads back through
    Route 53 Resolver exactly as templated; while it is ENABLED, deleting the stack is refused
    and the association survives untouched, until disabling the protection unblocks the delete.
    """
    cfn = ctx.client("cloudformation")
    r53r = ctx.client("route53resolver")

    domain_list_name = ctx.unique_name("sim2real-r53rmp-")
    rule_group_name = ctx.unique_name("sim2real-r53rmp-")
    assoc_name = ctx.unique_name("sim2real-r53rmp-")

    stack_id = create_stack(
        ctx,
        cfn,
        r53r,
        ctx.unique_name("sim2real-r53rmp-"),
        _template(domain_list_name, rule_group_name, assoc_name),
    )
    status = wait_stack(ctx, cfn, stack_id, timeout_s=300.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    assoc_id = out["AssocRef"]
    partition = stack_id.split(":")[1]
    want_arn = (
        f"arn:{partition}:route53resolver:{ctx.region}:{ctx.account}:"
        f"firewall-rule-group-association/{assoc_id}"
    )

    assoc = _poll(
        ctx,
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE",
        120.0,
        f"association {assoc_id} COMPLETE",
        interval_s=2.0,
    )
    got = (
        assoc["Arn"],
        assoc["Name"],
        assoc["MutationProtection"],
        assoc["Priority"],
        assoc["VpcId"],
        assoc["FirewallRuleGroupId"],
    )
    want = (want_arn, assoc_name, "ENABLED", 101, out["VpcRef"], out["RuleGroupRef"])
    assert got == want, f"Resolver reads the association as {got!r}, expected {want!r}"
    assert out["AssocArn"] == want_arn, f"GetAtt Arn was {out['AssocArn']!r}, expected {want_arn!r}"

    # Negative: deleting the stack while MutationProtection is ENABLED is refused.
    cfn.delete_stack(StackName=stack_id)
    status = wait_stack(ctx, cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s=300.0)
    assert status == "DELETE_FAILED", f"expected DELETE_FAILED, got {status!r}"
    message, code = handler_reason(
        failed_reason(stack_events(cfn, stack_id), "Association", status="DELETE_FAILED"),
        ctx.account,
    )
    want_message = (
        f"Invalid request provided: DisassociateFirewallRuleGroupRequest"
        f"(FirewallRuleGroupAssociationId={assoc_id})"
    )
    assert (message, code) == (want_message, _REJECTED_CODE), (
        f"delete-refusal reason {(message, code)!r}, expected {(want_message, _REJECTED_CODE)!r}"
    )

    # Effect absent: the association survives, unaffected, under Resolver's own read.
    unaffected = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
        "FirewallRuleGroupAssociation"
    ]
    assert (unaffected["Status"], unaffected["MutationProtection"], unaffected["Priority"]) == (
        "COMPLETE",
        "ENABLED",
        101,
    ), f"association after the refused delete: {unaffected!r}"

    # Positive control: dropping the protection directly unblocks the very same delete.
    _unprotect_and_delete(ctx, r53r, cfn, stack_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
