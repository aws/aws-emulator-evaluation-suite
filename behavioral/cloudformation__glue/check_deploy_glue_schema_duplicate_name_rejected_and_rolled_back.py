"""deploy-glue-schema-duplicate-name-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-glue-schema-duplicate-name-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue"]

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

_AVRO = json.dumps({"type": "record", "name": "User", "fields": [{"name": "id", "type": "string"}]})

_REJECTED = (
    "Resource of type 'AWS::Glue::Schema' with identifier '<name>' already exists.",
    "AlreadyExists",
)


def _schema_properties(registry_ref_logical_id: str, schema_name: str) -> dict:
    return {
        "Name": schema_name,
        "Registry": {"Arn": {"Ref": registry_ref_logical_id}},
        "DataFormat": "AVRO",
        "Compatibility": "BACKWARD",
        "SchemaDefinition": _AVRO,
    }


def _template(registry_name: str, schema_name: str, schema2_name: str) -> str:
    """A registry with two schemas; the rejected template gives both the same Name."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Registry": {"Type": "AWS::Glue::Registry", "Properties": {"Name": registry_name}},
            "Schema1": {
                "Type": "AWS::Glue::Schema",
                "Properties": _schema_properties("Registry", schema_name),
            },
            "Schema2": {
                "Type": "AWS::Glue::Schema",
                "DependsOn": "Schema1",
                "Properties": _schema_properties("Registry", schema2_name),
            },
        },
        "Outputs": {
            "Schema1Arn": {"Value": {"Ref": "Schema1"}},
            "Schema2Arn": {"Value": {"Ref": "Schema2"}},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A second AWS::Glue::Schema reusing the first one's Name in its registry fails AlreadyExists
    and the rollback deletes the registry and the first schema; the same template with a unique
    second Name deploys both schemas.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-schema.html
    """
    glue = ctx.client("glue")
    cfn = ctx.client("cloudformation")
    bad_stack = ctx.unique_name("sim2real-glueschemadupbad-")
    registry_name = ctx.unique_name("sim2real-glueschemadup-reg-")
    schema_name = ctx.unique_name("sim2real-glueschemadup-schema-")

    bad_id = create_stack(ctx, cfn, bad_stack,
                          _template(registry_name, schema_name, schema_name))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Schema2"), ctx.account,
                         schema_name)
    assert got == _REJECTED, f"expected reason {_REJECTED!r}, got {got!r}"

    resources = cfn.describe_stack_resources(StackName=bad_id)["StackResources"]
    registry_ids = [r["PhysicalResourceId"] for r in resources
                     if r["ResourceType"] == "AWS::Glue::Registry"]
    schema1_ids = [r["PhysicalResourceId"] for r in resources
                   if r["ResourceType"] == "AWS::Glue::Schema" and r["LogicalResourceId"] == "Schema1"]
    assert len(registry_ids) == 1 and len(schema1_ids) == 1, (
        f"expected exactly one registry and one Schema1, got "
        f"registries={registry_ids!r} schema1={schema1_ids!r}"
    )
    registry_arn, schema1_arn = registry_ids[0], schema1_ids[0]

    # The rollback itself removed them: read before this check deletes the stack.
    registry_gone = ("EntityNotFoundException",
                     f"Registry is not found. RegistryName: null, RegistryArn: {registry_arn}")
    expect_error(lambda: glue.get_registry(RegistryId={"RegistryArn": registry_arn}),
                 *registry_gone)
    schema_gone = ("EntityNotFoundException", f"Registry is not found. RegistryName: {registry_name}")
    expect_error(lambda: glue.get_schema(SchemaId={"SchemaArn": schema1_arn}), *schema_gone)
    delete_stack(cfn, bad_id)

    # Positive control: the same template with only Schema2's Name made unique deploys both.
    good_stack = ctx.unique_name("sim2real-glueschemadupgood-")
    good_registry_name = ctx.unique_name("sim2real-glueschemadup-reg-")
    good_schema_name = ctx.unique_name("sim2real-glueschemadup-schema-")
    good_schema2_name = ctx.unique_name("sim2real-glueschemadup-schema2-")
    good_id = create_stack(ctx, cfn, good_stack,
                           _template(good_registry_name, good_schema_name, good_schema2_name))
    good_status = wait_stack(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_outputs = stack_outputs(cfn, good_id)
    for output, name in (("Schema1Arn", good_schema_name), ("Schema2Arn", good_schema2_name)):
        control = glue.get_schema(SchemaId={"SchemaName": name, "RegistryName": good_registry_name})
        got = (control["SchemaArn"], control["SchemaName"], control["RegistryName"],
               control["DataFormat"], control["Compatibility"], control["SchemaStatus"])
        want = (good_outputs[output], name, good_registry_name, "AVRO", "BACKWARD", "AVAILABLE")
        assert got == want, f"control schema {output}: expected {want!r}, Glue reports {got!r}"
        latest = glue.get_schema_version(SchemaId={"SchemaArn": control["SchemaArn"]},
                                         SchemaVersionNumber={"LatestVersion": True})
        assert json.loads(latest["SchemaDefinition"]) == json.loads(_AVRO), (
            f"control schema {output}: expected the template's definition, Glue reports "
            f"{latest['SchemaDefinition']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
