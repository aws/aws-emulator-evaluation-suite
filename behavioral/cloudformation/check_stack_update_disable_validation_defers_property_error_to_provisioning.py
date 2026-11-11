"""stack-update-disable-validation-defers-property-error-to-provisioning."""

from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "stack-update-disable-validation-defers-property-error-to-provisioning"
GROUP = "stack-update"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An update adding a resource with an invalid enum property stops in pre-deployment validation
    before provisioning it; with DisableValidation the resource is attempted and fails at create.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/validate-stack-deployments.html"""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-uval-")
    param = "/" + ctx.unique_name("sim2real-cfn-uval-p-")
    stack_id = _create(ctx, cfn, name, _template(None))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"

    # Validated: the update stops before Param is provisioned and the validation names it.
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(param))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"validated update ended {_stack(cfn, stack_id)!r}"
    validated = _rows(_events(cfn, stack_id)[before:])
    assert _of(validated, "Param") == [], f"validation must stop the update before Param is provisioned: {validated!r}"
    found = _validation_errors(cfn, stack_id)
    assert found == [("Param", "AWS::SSM::Parameter", "PROPERTY_VALIDATION", "FAILED", "FAIL",
                      "NotAType is not a valid enum value. Supported values: [String, StringList]",
                      "/Resources/Param/Properties/Type")], (
        f"validation errors of the update: {found!r}")

    # Validation disabled: the identical update reaches the resource handler, which refuses it.
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(param), DisableValidation=True)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"unvalidated update ended {_stack(cfn, stack_id)!r}"
    attempted = _of(_rows(_events(cfn, stack_id)[before:]), "Param")
    assert attempted == [
        ("CREATE_IN_PROGRESS", None),
        ("CREATE_FAILED", "Properties validation failed for resource Param with message:\n"
                          "#/Type: #: only 1 subschema matches out of 2\n"
                          "#/Type: failed validation constraint for keyword [enum]"),
        ("DELETE_COMPLETE", None),
    ], f"Param events with validation disabled: {attempted!r}"
    disabled_found = _validation_errors(cfn, stack_id)[len(found):]
    assert disabled_found == [], f"validation ran although disabled: {disabled_found!r}"
    kept = [r["LogicalResourceId"] for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]]
    assert kept == ["Handle"], f"resources after both rolled-back updates: {kept!r}"


def _validation_errors(cfn, stack_id: str) -> list[tuple]:
    """``(logical id, type, name, status, mode, reason, path)`` of each VALIDATION_ERROR operation event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend((e.get("LogicalResourceId"), e.get("ResourceType"), e.get("ValidationName"),
                    e.get("ValidationStatus"), e.get("ValidationFailureMode"), e.get("ValidationStatusReason"),
                    e.get("ValidationPath"))
                   for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR")
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _template(param: str | None) -> str:
    """A handle, and with ``param`` an SSM parameter whose Type is not one of its enum values."""
    res: dict = {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}
    if param:
        res["Param"] = {"Type": "AWS::SSM::Parameter",
                        "Properties": {"Name": param, "Type": "NotAType", "Value": "v"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": res})


# ===== helpers =====

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=timeout_s, what=f"stack {stack_id} settled")


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE by id; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _stack(cfn, stack_id)["StackStatus"],
                  lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}")


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _rows(events: list[dict], *keys: str) -> list[tuple]:
    """``(LogicalResourceId, ResourceStatus, ResourceStatusReason, *keys)`` per event; absent is None."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"),
             *(e.get(k) for k in keys)) for e in events]


def _of(rows: list[tuple], logical_id: str) -> list[tuple]:
    """The rows of one logical resource, without the logical id."""
    return [r[1:] for r in rows if r[0] == logical_id]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
