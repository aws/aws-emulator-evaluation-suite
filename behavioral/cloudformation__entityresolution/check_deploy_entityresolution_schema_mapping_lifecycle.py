"""deploy-entityresolution-schema-mapping-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-entityresolution-schema-mapping-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "entityresolution"]

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

def _reasons(events):
    """``(logical id, status, reason)`` of every event row with a reason, oldest first."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e["ResourceStatusReason"])
            for e in events if e.get("ResourceStatusReason")]


def _template(schema_name, id_field="CustomerId"):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Mapping": {"Type": "AWS::EntityResolution::SchemaMapping", "Properties": {
            "SchemaName": schema_name,
            "Description": f"schema mapping {schema_name}",
            "MappedInputFields": [
                {"FieldName": id_field, "Type": "UNIQUE_ID"},
                {"FieldName": "FullName", "Type": "NAME"},
            ],
            "Tags": [{"Key": "sim2real-er", "Value": schema_name}],
        }}},
        "Outputs": {
            "MappingRef": {"Value": {"Ref": "Mapping"}},
            "MappingArn": {"Value": {"Fn::GetAtt": ["Mapping", "SchemaArn"]}},
        },
    })


def _listed(er, name):
    return [s["schemaArn"] for s in paginate(er, "list_schema_mappings", "schemaList")
            if s["schemaName"] == name]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Entity Resolution schema mapping reads back with its description and fields.

    Ref and GetAtt match an independent listing, and deleting the stack removes the mapping; tags
    are not graded, as GetSchemaMapping returns none for the mapping.
    """
    cf = ctx.client("cloudformation")
    er = ctx.client("entityresolution")
    stack = ctx.unique_name("sim2real-behav-cfn-ermap-")
    name = ctx.unique_name("sim2real-behav-cfn-ermap-")

    stack_id = create_stack(ctx, cf, stack, _template(name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {_reasons(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    assert (out["MappingRef"], _listed(er, name)) == (name, [out["MappingArn"]]), (
        f"Ref {out['MappingRef']!r}, ListSchemaMappings {_listed(er, name)!r}, "
        f"GetAtt SchemaArn {out['MappingArn']!r}"
    )
    got = er.get_schema_mapping(schemaName=name)
    # Only what GetSchemaMapping returns for the type: its "tags" member reads {} here.
    have = (got["schemaArn"], got.get("description"), got["hasWorkflows"],
            [(f["fieldName"], f["type"]) for f in got["mappedInputFields"]])
    want = (out["MappingArn"], f"schema mapping {name}", False,
            [("CustomerId", "UNIQUE_ID"), ("FullName", "NAME")])
    assert have == want, f"GetSchemaMapping {have!r}, expected {want!r}"

    delete_stack(cf, stack_id)
    not_found = ("ResourceNotFoundException", "SchemaMapping does not exist")
    expect_error(lambda: er.get_schema_mapping(schemaName=name), *not_found)
    assert _listed(er, name) == [], f"the deleted mapping is listed: {_listed(er, name)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
