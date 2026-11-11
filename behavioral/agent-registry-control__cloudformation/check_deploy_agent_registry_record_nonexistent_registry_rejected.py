"""deploy-agent-registry-record-nonexistent-registry-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-agent-registry-record-nonexistent-registry-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
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
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

_BAD_REGISTRY_ID = "ZZZZZZZZZZZZ"
_REJECTED = (
    f"Registry with ID {_BAD_REGISTRY_ID} not found. (Service: Agent Registry Control; "
    "Operation: CreateRegistryRecord; Status Code: 404; Error Code: ResourceNotFoundException; "
    "Request ID: <id>)",
    "NotFound",
)
_DATA = json.dumps({"k": "sim2real-v"})


def _record_template(registry_id, record_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Rec": {
                "Type": "AWS::AgentRegistry::RegistryRecord",
                "Properties": {
                    "RegistryId": registry_id,
                    "Name": record_name,
                    "RecordType": "CUSTOM",
                    "Descriptors": {"Custom": {"Data": _DATA}},
                },
            },
        },
        "Outputs": {"RecArn": {"Value": {"Ref": "Rec"}},
                    "RecId": {"Value": {"Fn::GetAtt": "Rec.RecordId"}}},
    })


def _registry_by_name(arc, name: str) -> list[dict]:
    return [r for r in paginate(arc, "list_registries", "registries") if r["name"] == name]


def _records(arc, registry_id: str) -> list[dict]:
    return paginate(arc, "list_registry_records", "registryRecords", registryId=registry_id)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation RegistryRecord naming a nonexistent registry id fails and rolls back.

    Agent Registry Control's CreateRegistryRecord refuses it, while the same template naming a real
    registry creates a record with the templated name, type and descriptor.
    """
    cfn = ctx.client("cloudformation")
    arc = ctx.client("agent-registry-control")
    registry_name = ctx.unique_name("sim2real-ar-rec-rej-reg-")
    good_record = ctx.unique_name("sim2real-ar-rec-good-")
    bad_record = ctx.unique_name("sim2real-ar-rec-bad-")

    registry_arn = arc.create_registry(name=registry_name, tags={"sim2real": registry_name})[
        "registryArn"]
    listed = _registry_by_name(arc, registry_name)
    assert [r["registryArn"] for r in listed] == [registry_arn], f"registries {listed!r}"
    registry_id = listed[0]["registryId"]
    ctx.on_cleanup(lambda: arc.delete_registry(registryId=registry_id))

    # Positive control: the same template naming the real registry.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ar-rec-good-stack-"),
                           _record_template(registry_id, good_record))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    got = arc.get_registry_record(registryId=registry_id, recordId=out["RecId"])
    got = (got["recordArn"], got["name"], got["recordType"], got["descriptors"])
    want = (out["RecArn"], good_record, "CUSTOM", {"custom": {"data": _DATA}})
    assert got == want, f"control record reads {got!r}, expected {want!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ar-rec-bad-stack-"),
                          _record_template(_BAD_REGISTRY_ID, bad_record))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    events = stack_events(cfn, bad_id)
    got = handler_reason(failed_reason(events, "Rec"), ctx.account)
    assert got == _REJECTED, f"Rec reason {got!r}, expected {_REJECTED!r}"
    # The refused create minted no record: its CREATE_FAILED row carries no physical id.
    physical = [e.get("PhysicalResourceId", "") for e in events
                if e["LogicalResourceId"] == "Rec" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert physical == [""], f"Rec CREATE_FAILED physical ids {physical!r}, expected ['']"

    # Control read: the real registry still lists exactly the control record.
    names = sorted(r["name"] for r in _records(arc, registry_id))
    assert names == [good_record], f"records of {registry_id!r}: {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
