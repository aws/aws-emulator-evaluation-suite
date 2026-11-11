"""deploy-resiliencehubv2-policy-round-trip-then-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-resiliencehubv2-policy-round-trip-then-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "resiliencehubv2"]

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

def _template(name, description, target):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Pol": {"Type": "AWS::ResilienceHubV2::Policy", "Properties": {
                "Name": name, "Description": description,
                "AvailabilitySlo": {"Target": target},
            }},
        },
        "Outputs": {
            "PolArn": {"Value": {"Ref": "Pol"}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ResilienceHubV2 Policy reads back through ResilienceHubV2 with its
    AvailabilitySlo, an in-place update changes only its description, and the stack delete
    removes it.
    """
    cf = ctx.client("cloudformation")
    rhv2 = ctx.client("resiliencehubv2")
    stack = ctx.unique_name("sim2real-rhv2-pol-")
    name = ctx.unique_name("sim2real-rhv2-polname-")
    desc = "sim2real policy for a round-trip check"

    stack_id = create_stack(ctx, cf, stack, _template(name, desc, 99.9))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {stack_events(cf, stack_id)!r}"
    )
    out = stack_outputs(cf, stack_id)
    pol_arn = out["PolArn"]
    pol_id = pol_arn.rsplit(":", 1)[-1]

    pol = rhv2.get_policy(policyArn=pol_arn)["policy"]
    assert (pol["name"], pol["description"]) == (name, desc), (
        f"GetPolicy returned name/description {(pol['name'], pol['description'])!r}, "
        f"expected {(name, desc)!r}"
    )
    assert pol["availabilitySlo"] == {"target": 99.9}, (
        f"GetPolicy availabilitySlo {pol['availabilitySlo']!r} != {{'target': 99.9}}"
    )
    created_at = pol["createdAt"]
    pol_tags = {k: v for k, v in rhv2.list_tags_for_resource(resourceArn=pol_arn)["tags"].items()
            if not k.startswith("aws:")}
    assert pol_tags == {"sim2real": stack}, f"Policy tags {pol_tags!r}, expected the stack tag"

    policies = {p["name"]: p for p in paginate(rhv2, "list_policies", "policySummaries")}
    assert name in policies, f"ListPolicies did not include {name!r}"
    assert policies[name]["policyArn"] == pol_arn, (
        f"ListPolicies entry for {name!r} has ARN {policies[name]['policyArn']!r}, "
        f"expected {pol_arn!r}"
    )

    # In-place update: only Description (mutable) changes; Name and AvailabilitySlo are untouched,
    # and the unchanged createdAt proves the same policy rather than a replacement.
    new_desc = desc + " (updated)"
    cf.update_stack(StackName=stack_id, TemplateBody=_template(name, new_desc, 99.9))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"description update ended {status!r}"
    pol_after = rhv2.get_policy(policyArn=pol_arn)["policy"]
    assert pol_after["description"] == new_desc, (
        f"GetPolicy description {pol_after['description']!r} != {new_desc!r} after the update"
    )
    assert pol_after["createdAt"] == created_at, (
        f"Policy createdAt changed from {created_at!r} to {pol_after['createdAt']!r}; "
        f"it was replaced rather than updated in place"
    )
    assert pol_after["availabilitySlo"] == {"target": 99.9}, (
        f"AvailabilitySlo changed to {pol_after['availabilitySlo']!r} on an update that did not "
        f"touch it"
    )

    delete_stack(cf, stack_id)
    gone = ("ResourceNotFoundException", f"Policy not found: {pol_id}")
    expect_error(lambda: rhv2.get_policy(policyArn=pol_arn), *gone)
    policies_after = {p["name"] for p in paginate(rhv2, "list_policies", "policySummaries")}
    assert name not in policies_after, f"ListPolicies still lists the deleted {name!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
