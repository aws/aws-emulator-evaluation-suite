"""deploy-resiliencehubv2-system-and-userjourney-round-trip-then-child-and-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-resiliencehubv2-system-and-userjourney-round-trip-then-child-and-stack-delete"
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

def _template(sys_name, sys_desc, with_uj, uj_name=None, uj_desc=None):
    resources = {
        "Sys": {"Type": "AWS::ResilienceHubV2::System", "Properties": {
            "Name": sys_name, "Description": sys_desc,
        }},
    }
    outputs = {
        "SysArn": {"Value": {"Ref": "Sys"}},
        "SysId": {"Value": {"Fn::GetAtt": ["Sys", "SystemId"]}},
    }
    if with_uj:
        resources["UJ"] = {"Type": "AWS::ResilienceHubV2::UserJourney", "Properties": {
            "SystemIdentifier": {"Ref": "Sys"}, "Name": uj_name, "Description": uj_desc,
        }}
        outputs["UJRef"] = {"Value": {"Ref": "UJ"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ResilienceHubV2 System and child UserJourney read back through
    ResilienceHubV2; dropping the UserJourney in an update removes only it, and deleting the
    stack removes the System.
    """
    cf = ctx.client("cloudformation")
    rhv2 = ctx.client("resiliencehubv2")
    stack = ctx.unique_name("sim2real-rhv2-sysuj-")
    sys_name = ctx.unique_name("sim2real-rhv2-sys-")
    sys_desc = "sim2real system for a round-trip check"
    uj_name = ctx.unique_name("sim2real-rhv2-uj-")
    uj_desc = "sim2real user journey for a round-trip check"

    stack_id = create_stack(ctx, cf, stack, _template(sys_name, sys_desc, True, uj_name, uj_desc))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {stack_events(cf, stack_id)!r}"
    )
    out = stack_outputs(cf, stack_id)
    sys_arn, sys_id, uj_ref = out["SysArn"], out["SysId"], out["UJRef"]
    uj_sys_half, uj_id = uj_ref.split("|", 1)
    assert uj_sys_half == sys_arn, f"UserJourney Ref {uj_ref!r} does not embed {sys_arn!r}"

    sys_obj = rhv2.get_system(systemArn=sys_arn)["system"]
    assert sys_obj["systemId"] == sys_id, (
        f"GetAtt SystemId {sys_id!r} != GetSystem systemId {sys_obj['systemId']!r}"
    )
    assert (sys_obj["name"], sys_obj["description"]) == (sys_name, sys_desc), (
        f"GetSystem returned name/description {(sys_obj['name'], sys_obj['description'])!r}, "
        f"expected {(sys_name, sys_desc)!r}"
    )
    created_at = sys_obj["createdAt"]
    sys_tags = {k: v for k, v in rhv2.list_tags_for_resource(resourceArn=sys_arn)["tags"].items()
            if not k.startswith("aws:")}
    assert sys_tags == {"sim2real": stack}, f"System tags {sys_tags!r}, expected the stack tag"

    systems = {s["name"]: s for s in paginate(rhv2, "list_systems", "systemSummaries")}
    assert sys_name in systems, f"ListSystems did not include {sys_name!r}"
    assert (systems[sys_name]["systemArn"], systems[sys_name]["systemId"]) == (sys_arn, sys_id), (
        f"ListSystems entry for {sys_name!r} is {systems[sys_name]!r}, expected ARN {sys_arn!r} "
        f"and id {sys_id!r}"
    )

    uj_obj = rhv2.get_user_journey(systemArn=sys_arn, userJourneyId=uj_id)["userJourney"]
    assert uj_obj["userJourneyId"] == uj_id, (
        f"Ref id {uj_id!r} != GetUserJourney userJourneyId {uj_obj['userJourneyId']!r}"
    )
    assert (uj_obj["name"], uj_obj["description"]) == (uj_name, uj_desc), (
        f"GetUserJourney returned name/description {(uj_obj['name'], uj_obj['description'])!r}, "
        f"expected {(uj_name, uj_desc)!r}"
    )

    ujs = paginate(rhv2, "list_user_journeys", "userJourneySummaries", systemArn=sys_arn)
    assert {u["userJourneyId"] for u in ujs} == {uj_id}, (
        f"ListUserJourneys(systemArn={sys_arn!r}) returned {ujs!r}, expected only {uj_id!r}"
    )

    # Child before parent: dropping the UserJourney removes only it; the System (same createdAt)
    # survives, so the resource was updated in place rather than replaced.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(sys_name, sys_desc, False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"UserJourney-dropping update ended {status!r}"

    gone = ("ResourceNotFoundException", f"User journey not found: {uj_id}")
    expect_error(lambda: rhv2.get_user_journey(systemArn=sys_arn, userJourneyId=uj_id), *gone)
    ujs_after = paginate(rhv2, "list_user_journeys", "userJourneySummaries", systemArn=sys_arn)
    assert ujs_after == [], f"ListUserJourneys still reports {ujs_after!r} after the update"
    sys_after_update = rhv2.get_system(systemArn=sys_arn)["system"]
    assert sys_after_update["createdAt"] == created_at, (
        f"System createdAt changed from {created_at!r} to {sys_after_update['createdAt']!r}; "
        f"it was replaced rather than updated in place"
    )

    delete_stack(cf, stack_id)
    gone = ("ResourceNotFoundException", f"System not found: {sys_id}")
    expect_error(lambda: rhv2.get_system(systemArn=sys_arn), *gone)
    systems_after = {s["name"] for s in paginate(rhv2, "list_systems", "systemSummaries")}
    assert sys_name not in systems_after, f"ListSystems still lists the deleted {sys_name!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
