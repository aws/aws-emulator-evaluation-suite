"""deploy-glue-registry-schema-schemaversion-and-metadata-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-glue-registry-schema-schemaversion-and-metadata-round-trip-and-delete"
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

_AVRO_V1 = json.dumps({"type": "record", "name": "User", "fields": [{"name": "id", "type": "string"}]})
_AVRO_V2 = json.dumps({
    "type": "record", "name": "User",
    "fields": [{"name": "id", "type": "string"}, {"name": "email", "type": "string", "default": ""}],
})


def _template(registry_name: str, schema_name: str, meta_key: str, meta_value: str,
              *, with_children: bool = True) -> str:
    """Registry and schema, plus (``with_children``) the second version and the metadata."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Registry": {"Type": "AWS::Glue::Registry", "Properties": {"Name": registry_name}},
            "Schema": {
                "Type": "AWS::Glue::Schema",
                "Properties": {
                    "Name": schema_name,
                    "Registry": {"Arn": {"Ref": "Registry"}},
                    "DataFormat": "AVRO",
                    "Compatibility": "BACKWARD",
                    "SchemaDefinition": _AVRO_V1,
                },
            },
            "SchemaVersion": {
                "Type": "AWS::Glue::SchemaVersion",
                "Properties": {
                    "Schema": {"SchemaArn": {"Ref": "Schema"}},
                    "SchemaDefinition": _AVRO_V2,
                },
            },
            "SchemaVersionMetadata": {
                "Type": "AWS::Glue::SchemaVersionMetadata",
                "Properties": {
                    "SchemaVersionId": {"Fn::GetAtt": ["Schema", "InitialSchemaVersionId"]},
                    "Key": meta_key,
                    "Value": meta_value,
                },
            },
        },
        "Outputs": {
            "RegistryArn": {"Value": {"Ref": "Registry"}},
            "SchemaArn": {"Value": {"Ref": "Schema"}},
            "SchemaInitialVersionId": {"Value": {"Fn::GetAtt": ["Schema", "InitialSchemaVersionId"]}},
            "SchemaVersionId": {"Value": {"Ref": "SchemaVersion"}},
        },
    }
    if not with_children:
        del template["Resources"]["SchemaVersion"]
        del template["Resources"]["SchemaVersionMetadata"]
        del template["Outputs"]["SchemaVersionId"]
    return json.dumps(template)


def _version_numbers(glue, schema_arn: str) -> list[int]:
    """Version numbers ListSchemaVersions reports for the schema, all pages, sorted."""
    out: list[int] = []
    kwargs: dict = {"SchemaId": {"SchemaArn": schema_arn}}
    while True:
        page = glue.list_schema_versions(**kwargs)
        out.extend(v["VersionNumber"] for v in page.get("Schemas", []))
        if not page.get("NextToken"):
            return sorted(out)
        kwargs["NextToken"] = page["NextToken"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation registry, schema, second schema version and version metadata read back
    through Glue with the template's values; an update removing the version and the metadata
    deletes each under a live schema, and deleting the stack removes the registry and schema.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-registry.html
    """
    glue = ctx.client("glue")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-glueschema-")
    registry_name = ctx.unique_name("sim2real-glueschema-reg-")
    schema_name = ctx.unique_name("sim2real-glueschema-schema-")
    meta_key, meta_value = "sim2real-key", "sim2real-value"

    stack_id = create_stack(ctx, cfn, stack, _template(registry_name, schema_name,
                                                       meta_key, meta_value))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    registry_arn = outputs["RegistryArn"]
    schema_arn = outputs["SchemaArn"]
    initial_version_id = outputs["SchemaInitialVersionId"]
    version_id = outputs["SchemaVersionId"]

    reg = glue.get_registry(RegistryId={"RegistryName": registry_name})
    assert reg["RegistryArn"] == registry_arn, (
        f"expected RegistryArn {registry_arn!r}, Glue reports {reg['RegistryArn']!r}"
    )
    assert reg["RegistryName"] == registry_name, (
        f"expected RegistryName {registry_name!r}, Glue reports {reg['RegistryName']!r}"
    )
    assert reg["Status"] == "AVAILABLE", f"expected registry Status 'AVAILABLE', got {reg['Status']!r}"

    sch = glue.get_schema(SchemaId={"SchemaName": schema_name, "RegistryName": registry_name})
    assert sch["SchemaArn"] == schema_arn, (
        f"expected SchemaArn {schema_arn!r}, Glue reports {sch['SchemaArn']!r}"
    )
    assert sch["SchemaName"] == schema_name, (
        f"expected SchemaName {schema_name!r}, Glue reports {sch['SchemaName']!r}"
    )
    assert sch["RegistryName"] == registry_name, (
        f"expected the schema's RegistryName {registry_name!r}, Glue reports {sch['RegistryName']!r}"
    )
    assert sch["DataFormat"] == "AVRO", f"expected DataFormat 'AVRO', got {sch['DataFormat']!r}"
    assert sch["Compatibility"] == "BACKWARD", (
        f"expected Compatibility 'BACKWARD', got {sch['Compatibility']!r}"
    )
    assert sch["LatestSchemaVersion"] == 2, (
        f"expected LatestSchemaVersion 2 after the second version, got {sch['LatestSchemaVersion']!r}"
    )

    ver = glue.get_schema_version(SchemaVersionId=version_id)
    assert ver["SchemaVersionId"] == version_id, (
        f"expected SchemaVersionId {version_id!r}, Glue reports {ver['SchemaVersionId']!r}"
    )
    assert ver["VersionNumber"] == 2, f"expected VersionNumber 2, Glue reports {ver['VersionNumber']!r}"
    assert ver["Status"] == "AVAILABLE", f"expected version Status 'AVAILABLE', got {ver['Status']!r}"
    assert json.loads(ver["SchemaDefinition"]) == json.loads(_AVRO_V2), (
        f"expected the second version's definition to equal the template's, Glue reports "
        f"{ver['SchemaDefinition']!r}"
    )
    assert ver["SchemaArn"] == schema_arn, (
        f"expected the version's SchemaArn {schema_arn!r}, Glue reports {ver['SchemaArn']!r}"
    )

    first = glue.get_schema_version(SchemaId={"SchemaArn": schema_arn},
                                    SchemaVersionNumber={"VersionNumber": 1})
    assert first["SchemaVersionId"] == initial_version_id, (
        f"GetAtt InitialSchemaVersionId: expected Glue's version 1 id {first['SchemaVersionId']!r}, "
        f"got {initial_version_id!r}"
    )
    assert json.loads(first["SchemaDefinition"]) == json.loads(_AVRO_V1), (
        f"expected the initial version's definition to equal the template's, Glue reports "
        f"{first['SchemaDefinition']!r}"
    )

    meta = glue.query_schema_version_metadata(SchemaVersionId=initial_version_id)
    assert meta["SchemaVersionId"] == initial_version_id, (
        f"expected SchemaVersionId {initial_version_id!r}, Glue reports {meta['SchemaVersionId']!r}"
    )
    assert sorted(meta["MetadataInfoMap"]) == [meta_key], (
        f"expected exactly key {meta_key!r} in the initial version's metadata, got "
        f"{sorted(meta['MetadataInfoMap'])!r}"
    )
    assert meta["MetadataInfoMap"][meta_key]["MetadataValue"] == meta_value, (
        f"expected metadata value {meta_value!r}, Glue reports "
        f"{meta['MetadataInfoMap'][meta_key]['MetadataValue']!r}"
    )

    # Each child's own delete: an update removes the second version and the metadata while the
    # schema that owns both stays.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(registry_name, schema_name, meta_key, meta_value,
                                            with_children=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack!r} update ended {status!r}, expected UPDATE_COMPLETE"
    meta = glue.query_schema_version_metadata(SchemaVersionId=initial_version_id)
    assert meta["MetadataInfoMap"] == {}, (
        f"removing SchemaVersionMetadata must delete it, Glue still reports {meta['MetadataInfoMap']!r}"
    )
    # Version deletion settles asynchronously: poll, bounded, until only version 1 is listed.
    deadline = time.monotonic() + 60.0
    versions = _version_numbers(glue, schema_arn)
    while versions != [1] and time.monotonic() < deadline:
        time.sleep(2.0)
        versions = _version_numbers(glue, schema_arn)
    assert versions == [1], f"removing SchemaVersion must leave only version 1, Glue lists {versions!r}"

    delete_stack(cfn, stack_id)

    registry_gone = ("EntityNotFoundException",
                     f"Registry is not found. RegistryName: null, RegistryArn: {registry_arn}")
    expect_error(lambda: glue.get_registry(RegistryId={"RegistryArn": registry_arn}),
                 *registry_gone)

    schema_gone = ("EntityNotFoundException", f"Registry is not found. RegistryName: {registry_name}")
    expect_error(lambda: glue.get_schema(SchemaId={"SchemaArn": schema_arn}), *schema_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
