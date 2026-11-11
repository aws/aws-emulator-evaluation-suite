"""deploy-eventschemas-registry-policy-schema-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eventschemas-registry-policy-schema-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "schemas"]

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

_CONTENT = json.dumps({
    "openapi": "3.0.0",
    "info": {"title": "sim2real-eventschemas-check", "version": "1.0.0"},
    "paths": {},
    "components": {
        "schemas": {"Event": {"type": "object", "properties": {"id": {"type": "string"}}}}
    },
})
_REGISTRY_DESCRIPTION = "sim2real registry for a CloudFormation provisioning check"
_SCHEMA_DESCRIPTION = "sim2real schema for a CloudFormation provisioning check"


def _policy(principal, resource):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowAccountRootDescribeRegistry", "Effect": "Allow",
            "Principal": {"AWS": principal}, "Action": "schemas:DescribeRegistry",
            "Resource": resource,
        }],
    }


def _template(registry_name, schema_name, with_schema=True):
    resources = {
        "Registry": {
            "Type": "AWS::EventSchemas::Registry",
            "Properties": {"RegistryName": registry_name, "Description": _REGISTRY_DESCRIPTION},
        },
        "RegistryPolicy": {
            "Type": "AWS::EventSchemas::RegistryPolicy",
            "Properties": {
                "RegistryName": {"Fn::GetAtt": ["Registry", "RegistryName"]},
                "Policy": _policy({"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"},
                                  {"Ref": "Registry"}),
            },
        },
    }
    outputs = {
        "RegistryRef": {"Value": {"Ref": "Registry"}},
        "RegistryName": {"Value": {"Fn::GetAtt": ["Registry", "RegistryName"]}},
        "RegistryArn": {"Value": {"Fn::GetAtt": ["Registry", "RegistryArn"]}},
        "RegistryPolicyRef": {"Value": {"Ref": "RegistryPolicy"}},
    }
    if with_schema:
        resources["Schema"] = {
            "Type": "AWS::EventSchemas::Schema",
            "Properties": {
                "RegistryName": {"Fn::GetAtt": ["Registry", "RegistryName"]},
                "SchemaName": schema_name, "Type": "OpenApi3",
                "Description": _SCHEMA_DESCRIPTION, "Content": _CONTENT,
            },
        }
        outputs.update({
            "SchemaRef": {"Value": {"Ref": "Schema"}},
            "SchemaName": {"Value": {"Fn::GetAtt": ["Schema", "SchemaName"]}},
            "SchemaArn": {"Value": {"Fn::GetAtt": ["Schema", "SchemaArn"]}},
            "SchemaVersion": {"Value": {"Fn::GetAtt": ["Schema", "SchemaVersion"]}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(schemas, arn):
    tags_map = schemas.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
    return {k: v for k, v in tags_map.items() if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation schema registry, its resource policy and a schema read back through Schemas.

    Ref, GetAtt, properties and tags match; an update dropping the schema empties the registry
    while it answers, and the stack delete removes the registry.
    """
    cf = ctx.client("cloudformation")
    schemas = ctx.client("schemas")
    registry_name = ctx.unique_name("sim2real-eschreg-")
    schema_name = ctx.unique_name("sim2real-eschsch-")
    stack = ctx.unique_name("sim2real-eschstack-")

    stack_id = create_stack(ctx, cf, stack, _template(registry_name, schema_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]

    # Registry: Ref and GetAtt == the ARN ListRegistries reports for the templated name.
    registries = [r for r in paginate(schemas, "list_registries", "Registries",
                                      RegistryNamePrefix=registry_name)
                  if r["RegistryName"] == registry_name]
    reg_arn = f"arn:{partition}:schemas:{ctx.region}:{ctx.account}:registry/{registry_name}"
    assert [r["RegistryArn"] for r in registries] == [reg_arn], f"ListRegistries {registries!r}"
    got = (out["RegistryRef"], out["RegistryArn"], out["RegistryName"])
    assert got == (reg_arn, reg_arn, registry_name), f"Registry Ref/GetAtt {got!r}"
    reg = schemas.describe_registry(RegistryName=registry_name)
    assert (reg["RegistryArn"], reg["Description"]) == (reg_arn, _REGISTRY_DESCRIPTION), (
        f"DescribeRegistry reads {reg!r}"
    )
    reg_tags = _own_tags(schemas, reg_arn)
    assert reg_tags == {"sim2real": stack}, f"registry tags {reg_tags!r}"

    # RegistryPolicy: Ref is the registry name it is attached to; the policy reads back exactly.
    assert out["RegistryPolicyRef"] == registry_name, f"Ref {out['RegistryPolicyRef']!r}"
    policy = json.loads(schemas.get_resource_policy(RegistryName=registry_name)["Policy"])
    want_policy = _policy(f"arn:{partition}:iam::{ctx.account}:root", reg_arn)
    assert policy == want_policy, f"registry policy {policy!r}, expected {want_policy!r}"

    # Schema: Ref and GetAtt == the ARN ListSchemas reports in the registry; properties match.
    listed = [s for s in paginate(schemas, "list_schemas", "Schemas", RegistryName=registry_name)
              if s["SchemaName"] == schema_name]
    schema_arn = f"arn:{partition}:schemas:{ctx.region}:{ctx.account}:schema/{registry_name}/{schema_name}"
    assert [s["SchemaArn"] for s in listed] == [schema_arn], f"ListSchemas found {listed!r}"
    got = (out["SchemaRef"], out["SchemaArn"], out["SchemaName"])
    assert got == (schema_arn, schema_arn, schema_name), f"Schema Ref/GetAtt {got!r}"
    schema = schemas.describe_schema(RegistryName=registry_name, SchemaName=schema_name)
    got = (schema["SchemaArn"], schema["Type"], schema["Description"], schema["SchemaVersion"],
           json.loads(schema["Content"]))
    want = (schema_arn, "OpenApi3", _SCHEMA_DESCRIPTION, out["SchemaVersion"], json.loads(_CONTENT))
    assert got == want, f"DescribeSchema reads {got!r}, expected {want!r}"
    schema_tags = _own_tags(schemas, schema_arn)
    assert schema_tags == {"sim2real": stack}, f"schema tags {schema_tags!r}"

    # Child first: an update dropping the schema empties the registry while it still answers.
    cf.update_stack(StackName=stack_id,
                    TemplateBody=_template(registry_name, schema_name, with_schema=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"schema-dropping update ended {status!r}"
    left = paginate(schemas, "list_schemas", "Schemas", RegistryName=registry_name)
    assert left == [], f"ListSchemas after the update: {left!r}"
    still = schemas.describe_registry(RegistryName=registry_name)
    assert still["RegistryArn"] == reg_arn, f"registry after the update reads {still!r}"

    delete_stack(cf, stack_id)
    gone = ("NotFoundException", f"Registry with name {registry_name} does not exist.")
    expect_error(lambda: schemas.describe_registry(RegistryName=registry_name), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
