"""deploy-agent-registry-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-agent-registry-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["agent-registry-control", "cloudformation"]

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

_CFN_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)Z$")


def _parse_cfn_timestamp(value: str) -> datetime:
    """Normalize a CloudFormation GetAtt timestamp to microsecond precision."""
    m = _CFN_TS_RE.match(value)
    assert m, f"unexpected CloudFormation timestamp format: {value!r}"
    frac = m.group(2)[:6].ljust(6, "0")
    return datetime.strptime(f"{m.group(1)}.{frac}", "%Y-%m-%dT%H:%M:%S.%f").replace(
        tzinfo=timezone.utc
    )


def _registry_by_name(arc, name: str) -> list[dict]:
    return [r for r in paginate(arc, "list_registries", "registries") if r["name"] == name]


def _template(name: str, description: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Reg": {
                "Type": "AWS::AgentRegistry::Registry",
                "Properties": {"Name": name, "Description": description},
            },
        },
        "Outputs": {
            "RegArn": {"Value": {"Ref": "Reg"}},
            "RegId": {"Value": {"Fn::GetAtt": "Reg.RegistryId"}},
            "RegStatus": {"Value": {"Fn::GetAtt": "Reg.Status"}},
            "RegCreatedAt": {"Value": {"Fn::GetAtt": "Reg.CreatedAt"}},
            "RegUpdatedAt": {"Value": {"Fn::GetAtt": "Reg.UpdatedAt"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Agent Registry reads back through Agent Registry Control, then deletes.

    Ref is the ARN the registry is listed under, the GetAtts and templated properties match
    GetRegistry, and the stack delete makes the registry unreadable.
    """
    cfn = ctx.client("cloudformation")
    arc = ctx.client("agent-registry-control")
    stack = ctx.unique_name("sim2real-ar-reg-stack-")
    name = ctx.unique_name("sim2real-ar-reg-")
    description = "sim2real agent registry provisioning check"

    stack_id = create_stack(ctx, cfn, stack, _template(name, description))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    listed = _registry_by_name(arc, name)
    assert [r["registryArn"] for r in listed] == [out["RegArn"]], f"registries {listed!r}"
    reg_id = listed[0]["registryId"]

    got = arc.get_registry(registryId=reg_id)
    got_atts = (out["RegId"], out["RegStatus"], _parse_cfn_timestamp(out["RegCreatedAt"]),
                _parse_cfn_timestamp(out["RegUpdatedAt"]))
    want_atts = (got["registryId"], got["status"], got["createdAt"], got["updatedAt"])
    assert got_atts == want_atts, f"GetAtts {got_atts!r}, GetRegistry {want_atts!r}"
    assert (got["name"], got["description"]) == (name, description), (
        f"registry reads {(got['name'], got['description'])!r}"
    )

    delete_stack(cfn, stack_id)
    until_raises(lambda: arc.get_registry(registryId=reg_id))
    refused = ("ResourceNotFoundException", f"Registry with ARN {reg_id} not found.")
    expect_error(lambda: arc.get_registry(registryId=reg_id), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
