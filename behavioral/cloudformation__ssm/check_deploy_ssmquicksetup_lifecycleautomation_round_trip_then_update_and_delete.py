"""deploy-ssmquicksetup-lifecycleautomation-round-trip-then-update-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ssmquicksetup-lifecycleautomation-round-trip-then-update-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

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

_NOT_FOUND_CODE = "AssociationDoesNotExist"


def _noop_document_content():
    return {
        "schemaVersion": "0.3",
        "description": "sim2real no-op lifecycle automation document",
        "assumeRole": "{{ AutomationAssumeRole }}",
        "parameters": {
            "AutomationAssumeRole": {"type": "String", "default": ""},
            "ExecutionMode": {"type": "String", "default": ""},
        },
        "mainSteps": [{
            "name": "NoOp",
            "action": "aws:executeScript",
            "inputs": {
                "Runtime": "python3.11",
                "Handler": "script_handler",
                "Script": "def script_handler(events, context):\n  return {'ok': True}\n",
            },
        }],
    }


def _template(role_name, doc_name, resource_key, stack, extra_tags=None):
    tags_map = {"sim2real": stack, "sim2real-lifecycle": resource_key}
    if extra_tags:
        tags_map.update(extra_tags)
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AutomationRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "ssm.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            "NoOpDoc": {
                "Type": "AWS::SSM::Document",
                "Properties": {
                    "Name": doc_name,
                    "DocumentType": "Automation",
                    "DocumentFormat": "JSON",
                    "Content": _noop_document_content(),
                },
            },
            "Lifecycle": {
                "Type": "AWS::SSMQuickSetup::LifecycleAutomation",
                "Properties": {
                    "AutomationDocument": {"Ref": "NoOpDoc"},
                    "ResourceKey": resource_key,
                    "AutomationParameters": {
                        "AutomationAssumeRole": [{"Fn::GetAtt": ["AutomationRole", "Arn"]}]
                    },
                    "Tags": tags_map,
                },
            },
        },
        "Outputs": {
            "LifecycleRef": {"Value": {"Ref": "Lifecycle"}},
            "LifecycleAssociationId": {"Value": {"Fn::GetAtt": ["Lifecycle", "AssociationId"]}},
            "DocName": {"Value": {"Ref": "NoOpDoc"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["AutomationRole", "Arn"]}},
        },
    })


def _own_tags(ssm, association_id):
    raw = ssm.list_tags_for_resource(ResourceType="Association", ResourceId=association_id)
    return {t["Key"]: t["Value"] for t in raw["TagList"] if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation SSMQuickSetup LifecycleAutomation is a real SSM Automation association:
    Ref, GetAtt and every templated property read back through SSM, an in-place update keeps the
    same server-minted association, and the stack delete removes it for good.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-ssmqs-rt-")
    role_name = ctx.unique_name("sim2real-ssmqs-rt-role-")
    doc_name = ctx.unique_name("sim2real-ssmqs-rt-doc-")
    resource_key = ctx.unique_name("ssmqsrt")[:40]

    stack_id = create_stack(ctx, cf, stack, _template(role_name, doc_name, resource_key, stack),
                             Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    association_id = out["LifecycleRef"]

    # Ref == read-only GetAtt AssociationId == the primary identifier.
    assert out["LifecycleAssociationId"] == association_id, (
        f"GetAtt AssociationId {out['LifecycleAssociationId']!r} != Ref {association_id!r}"
    )

    # Ref against an independent read (ListAssociations by the deterministic AssociationName the
    # resource mints from ResourceKey), never a read keyed by the Ref itself.
    assoc_name = f"AWS-QuickSetup-LifecycleAutomation-{resource_key}"
    listed = paginate(ssm, "list_associations", "Associations",
                      AssociationFilterList=[{"key": "AssociationName", "value": assoc_name}])
    assert [a["AssociationId"] for a in listed] == [association_id], (
        f"ListAssociations by name found {listed!r} for Ref {association_id!r}"
    )

    desc = ssm.describe_association(AssociationId=association_id)["AssociationDescription"]
    assert desc["AssociationName"] == assoc_name, f"AssociationName {desc['AssociationName']!r}"
    assert desc["Name"] == out["DocName"], f"document Name {desc['Name']!r} != {out['DocName']!r}"
    # Every templated property: the automation role we set, and the handler-injected lifecycle
    # phase; the overview proves the automation actually executed, not merely that it was declared.
    assert desc["Parameters"] == {
        "AutomationAssumeRole": [out["RoleArn"]], "ExecutionMode": ["Create"],
    }, f"Parameters {desc['Parameters']!r}"
    assert desc["Overview"]["Status"] == "Success", f"Overview {desc['Overview']!r}"
    assert _own_tags(ssm, association_id) == {
        "sim2real": stack, "sim2real-lifecycle": resource_key,
    }, f"tags {_own_tags(ssm, association_id)!r}"
    created_date = desc["Date"]
    # The automation document the stack created, with its templated type, format and content.
    doc = ssm.get_document(Name=out["DocName"], DocumentFormat="JSON")
    got_doc = (doc["Name"], doc["DocumentType"], doc["DocumentFormat"], json.loads(doc["Content"]))
    assert got_doc == (doc_name, "Automation", "JSON", _noop_document_content()), (
        f"GetDocument reads {got_doc!r}"
    )
    assert desc["AssociationVersion"] == "1", f"AssociationVersion {desc['AssociationVersion']!r}"

    # In-place update (ResourceKey unchanged, so no replacement): the same server-minted
    # AssociationId and creation Date prove it is the same resource, not a new one; the lifecycle
    # phase passed to the handler moves from Create to Update and the automation re-runs.
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(role_name, doc_name, resource_key, stack,
                               extra_tags={"sim2real-updated": "yes"}),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"update ended {status!r}"
    after = ssm.describe_association(AssociationId=association_id)["AssociationDescription"]
    assert (after["AssociationId"], after["Date"]) == (association_id, created_date), (
        f"after update: AssociationId/Date {(after['AssociationId'], after['Date'])!r}, "
        f"expected {(association_id, created_date)!r}"
    )
    assert after["AssociationVersion"] == "2", f"AssociationVersion {after['AssociationVersion']!r}"
    assert after["Parameters"]["ExecutionMode"] == ["Update"], (
        f"ExecutionMode {after['Parameters']['ExecutionMode']!r}"
    )
    assert after["Overview"]["Status"] == "Success", f"Overview {after['Overview']!r}"
    assert _own_tags(ssm, association_id) == {
        "sim2real": stack, "sim2real-lifecycle": resource_key, "sim2real-updated": "yes",
    }, f"tags after update {_own_tags(ssm, association_id)!r}"

    delete_stack(cf, stack_id)
    gone = (_NOT_FOUND_CODE, f"Association {association_id} does not exist.")
    expect_error(lambda: ssm.describe_association(AssociationId=association_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
