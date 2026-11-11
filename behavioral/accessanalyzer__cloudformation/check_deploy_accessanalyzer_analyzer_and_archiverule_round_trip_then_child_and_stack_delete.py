"""deploy-accessanalyzer-analyzer-and-archiverule-round-trip-then-child-and-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-accessanalyzer-analyzer-and-archiverule-round-trip-then-child-and-stack-delete"
GROUP = "deploy"
SERVICES = ["accessanalyzer", "cloudformation"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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


def is_subsequence(want, rows):
    """True when ``want`` occurs in ``rows`` in order (gaps allowed)."""
    it = iter(rows)
    return all(w in it for w in want)


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

_ANALYZER_NOT_FOUND = ("ResourceNotFoundException", "Analyzer not found")
_RULE_NOT_FOUND = ("ResourceNotFoundException", "Archive rule not found")
_FILTER = {"resourceType": {"Eq": ["AWS::S3::Bucket"]}}


def _template(analyzer_name, with_rule, rule_name=None, tag_value=None):
    resources = {
        "Analyzer": {
            "Type": "AWS::AccessAnalyzer::Analyzer",
            "Properties": {
                "AnalyzerName": analyzer_name,
                "Type": "ACCOUNT",
                "Tags": [{"Key": "sim2real-analyzer", "Value": tag_value}],
            },
        },
    }
    outputs = {
        "AnalyzerRef": {"Value": {"Ref": "Analyzer"}},
        "AnalyzerArn": {"Value": {"Fn::GetAtt": ["Analyzer", "Arn"]}},
    }
    if with_rule:
        resources["ArchiveRule"] = {
            "Type": "AWS::AccessAnalyzer::ArchiveRule",
            "DependsOn": "Analyzer",
            "Properties": {
                "AnalyzerName": analyzer_name,
                "RuleName": rule_name,
                "Filter": _FILTER,
            },
        }
        outputs["ArchiveRuleRef"] = {"Value": {"Ref": "ArchiveRule"}}
        outputs["ArchiveRuleArn"] = {"Value": {"Fn::GetAtt": ["ArchiveRule", "Arn"]}}
        outputs["ArchiveRuleCreatedAt"] = {"Value": {"Fn::GetAtt": ["ArchiveRule", "CreatedAt"]}}
        outputs["ArchiveRuleUpdatedAt"] = {"Value": {"Fn::GetAtt": ["ArchiveRule", "UpdatedAt"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _own_analyzer(aa, name):
    """The ACCOUNT-type analyzer named ``name``, from an independent paginated list read."""
    found = [a for a in paginate(aa, "list_analyzers", "analyzers", type="ACCOUNT")
             if a["name"] == name]
    return found


def _own_archive_rule(aa, analyzer_name, rule_name):
    """The archive rule named ``rule_name``, from an independent paginated list read."""
    found = [r for r in paginate(aa, "list_archive_rules", "archiveRules",
                                 analyzerName=analyzer_name) if r["ruleName"] == rule_name]
    return found


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
      "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """A CloudFormation Access Analyzer and its archive rule read back through Access Analyzer.

    Ref, GetAtt and every templated property match an independent ListAnalyzers/ListArchiveRules
    read; removing the rule in an update leaves the same analyzer; deleting the stack removes both.
    """
    cf = ctx.client("cloudformation")
    aa = ctx.client("accessanalyzer")
    stack = ctx.unique_name("sim2real-cfnaa-rt-")
    analyzer = ctx.unique_name("sim2real-cfnaa-rt-an-")
    rule = ctx.unique_name("sim2real-cfnaa-rt-rule-")

    # One ACCOUNT analyzer per account and Region: the stack can create it only in a clean slot.
    prior = [a["name"] for a in paginate(aa, "list_analyzers", "analyzers", type="ACCOUNT")]
    assert prior == [], f"precondition: {len(prior)} ACCOUNT analyzer(s) already hold the slot"

    stack_id = create_stack(ctx, cf, stack, _template(analyzer, True, rule, analyzer))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    rows = decisive_rows(stack_events(cf, stack_id))
    want = [("Analyzer", "CREATE_COMPLETE"), ("ArchiveRule", "CREATE_COMPLETE")]
    assert is_subsequence(want, rows), f"expected {want!r} as a subsequence of {rows!r}"

    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    analyzer_arn = f"arn:{partition}:access-analyzer:{ctx.region}:{ctx.account}:analyzer/{analyzer}"
    archive_rule_arn = f"{analyzer_arn}/archive-rule/{rule}"
    assert (out["AnalyzerRef"], out["AnalyzerArn"]) == (analyzer_arn, analyzer_arn), (
        f"Analyzer Ref {out['AnalyzerRef']!r}, GetAtt Arn {out['AnalyzerArn']!r}, "
        f"expected {analyzer_arn!r}"
    )
    assert (out["ArchiveRuleRef"], out["ArchiveRuleArn"]) == (archive_rule_arn, archive_rule_arn), (
        f"ArchiveRule Ref {out['ArchiveRuleRef']!r}, GetAtt Arn {out['ArchiveRuleArn']!r}, "
        f"expected {archive_rule_arn!r}"
    )

    # Ref against an independent read (ListAnalyzers by type), never a read keyed by the Ref.
    listed = _own_analyzer(aa, analyzer)
    assert len(listed) == 1, f"ListAnalyzers(type=ACCOUNT) found {listed!r} for name {analyzer!r}"
    assert listed[0]["arn"] == analyzer_arn, f"listed arn {listed[0]['arn']!r} != {analyzer_arn!r}"

    got = aa.get_analyzer(analyzerName=analyzer)["analyzer"]
    assert got["arn"] == analyzer_arn, f"GetAnalyzer arn {got['arn']!r} != {analyzer_arn!r}"
    assert got["type"] == "ACCOUNT", f"GetAnalyzer type {got['type']!r} != 'ACCOUNT'"
    assert got["name"] == analyzer, f"GetAnalyzer name {got['name']!r} != {analyzer!r}"
    assert got["status"] == "ACTIVE", f"GetAnalyzer status {got['status']!r} != 'ACTIVE'"
    own_tags = {k: v for k, v in got["tags"].items() if not k.startswith("aws:")}
    assert own_tags == {"sim2real-analyzer": analyzer, "sim2real": stack}, f"tags {own_tags!r}"
    created_at = got["createdAt"]

    # Ref against an independent read (ListArchiveRules by the analyzer), every page.
    rule_listed = _own_archive_rule(aa, analyzer, rule)
    assert len(rule_listed) == 1, f"ListArchiveRules found {rule_listed!r} for rule {rule!r}"
    assert rule_listed[0]["filter"] == {"resourceType": {"eq": ["AWS::S3::Bucket"]}}, (
        f"listed filter {rule_listed[0]['filter']!r}"
    )

    got_rule = aa.get_archive_rule(analyzerName=analyzer, ruleName=rule)["archiveRule"]
    assert got_rule["ruleName"] == rule, f"GetArchiveRule ruleName {got_rule['ruleName']!r}"
    assert got_rule["filter"] == {"resourceType": {"eq": ["AWS::S3::Bucket"]}}, (
        f"GetArchiveRule filter {got_rule['filter']!r}"
    )
    created_at_iso = got_rule["createdAt"].strftime("%Y-%m-%dT%H:%M:%SZ")
    updated_at_iso = got_rule["updatedAt"].strftime("%Y-%m-%dT%H:%M:%SZ")
    assert out["ArchiveRuleCreatedAt"] == created_at_iso, (
        f"GetAtt CreatedAt {out['ArchiveRuleCreatedAt']!r} != {created_at_iso!r}"
    )
    assert out["ArchiveRuleUpdatedAt"] == updated_at_iso, (
        f"GetAtt UpdatedAt {out['ArchiveRuleUpdatedAt']!r} != {updated_at_iso!r}"
    )

    # Child before parent: an update dropping the archive rule leaves the SAME analyzer
    # (createdAt unchanged), while the rule itself answers its own exact NotFound.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(analyzer, False, tag_value=analyzer))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"rule-removing update ended {status!r}"
    rows = decisive_rows(stack_events(cf, stack_id))
    assert ("ArchiveRule", "DELETE_COMPLETE") in rows, f"no ArchiveRule DELETE_COMPLETE in {rows!r}"

    expect_error(lambda: aa.get_archive_rule(analyzerName=analyzer, ruleName=rule),
                 *_RULE_NOT_FOUND)
    after = aa.get_analyzer(analyzerName=analyzer)["analyzer"]
    assert after["createdAt"] == created_at, (
        f"after dropping the ArchiveRule the analyzer createdAt changed: "
        f"{after['createdAt']!r} != {created_at!r}"
    )

    delete_stack(cf, stack_id)
    until_raises(lambda: aa.get_analyzer(analyzerName=analyzer))
    expect_error(lambda: aa.get_analyzer(analyzerName=analyzer), *_ANALYZER_NOT_FOUND)
    expect_error(lambda: aa.get_archive_rule(analyzerName=analyzer, ruleName=rule),
                 *_ANALYZER_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
