"""deploy-glue-integration-resource-property-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-glue-integration-resource-property-round-trip-and-delete"
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

def _template(role_name: str, database_name: str, *, with_irp: bool = True) -> str:
    """The role, the database and (``with_irp``) the integration resource property on it."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "glue.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            "Database": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {"Name": database_name},
                },
            },
            "Irp": {
                "Type": "AWS::Glue::IntegrationResourceProperty",
                "Properties": {
                    "ResourceArn": {
                        "Fn::Sub": "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/${Database}"
                    },
                    "TargetProcessingProperties": {"RoleArn": {"Fn::GetAtt": ["Role", "Arn"]}},
                },
            },
        },
        "Outputs": {
            "DatabaseName": {"Value": {"Ref": "Database"}},
            "ResourceArn": {
                "Value": {
                    "Fn::Sub": "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/${Database}"
                }
            },
            "ResourcePropertyArn": {"Value": {"Fn::GetAtt": ["Irp", "ResourcePropertyArn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "IrpRef": {"Value": {"Ref": "Irp"}},
        },
    }
    if not with_irp:
        del template["Resources"]["Irp"]
        del template["Outputs"]["ResourcePropertyArn"]
        del template["Outputs"]["IrpRef"]
    return json.dumps(template)


def _properties_on(glue, resource_arn: str) -> list[dict]:
    """Every integration resource property Glue lists for ``resource_arn``, all pages."""
    out: list[dict] = []
    kwargs: dict = {}
    while True:
        page = glue.list_integration_resource_properties(**kwargs)
        out.extend(p for p in page["IntegrationResourcePropertyList"]
                   if p.get("ResourceArn") == resource_arn)
        if not page.get("Marker"):
            return out
        kwargs["Marker"] = page["Marker"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Glue::IntegrationResourceProperty on a Glue database reads back
    through Glue with the template's role; a stack update removing only it deletes it while the
    database stays, and deleting the stack removes the database.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-integrationresourceproperty.html
    """
    glue = ctx.client("glue")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-glueirp-")
    role_name = ctx.unique_name("sim2real-glueirp-role-")
    database_name = ctx.unique_name("sim2real_glueirp_db_")

    stack_id = create_stack(ctx, cfn, stack, _template(role_name, database_name),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    resource_arn = outputs["ResourceArn"]
    resource_property_arn = outputs["ResourcePropertyArn"]
    role_arn = outputs["RoleArn"]
    db = glue.get_database(CatalogId=ctx.account, Name=database_name)
    assert db["Database"]["Name"] == database_name, (
        f"expected database Name {database_name!r}, Glue reports {db['Database']['Name']!r}"
    )
    assert outputs["DatabaseName"] == db["Database"]["Name"], (
        f"Ref of the database: expected {db['Database']['Name']!r}, got {outputs['DatabaseName']!r}"
    )

    irp = glue.get_integration_resource_property(ResourceArn=resource_arn)
    assert irp["ResourceArn"] == resource_arn, (
        f"expected ResourceArn {resource_arn!r}, Glue reports {irp['ResourceArn']!r}"
    )
    assert irp["ResourcePropertyArn"] == resource_property_arn, (
        f"expected ResourcePropertyArn {resource_property_arn!r}, Glue reports "
        f"{irp['ResourcePropertyArn']!r}"
    )
    assert irp["TargetProcessingProperties"]["RoleArn"] == role_arn, (
        f"expected TargetProcessingProperties.RoleArn {role_arn!r}, Glue reports "
        f"{irp['TargetProcessingProperties']['RoleArn']!r}"
    )
    want_ref = f"{irp['ResourceArn']}|{irp['ResourcePropertyArn']}"
    assert outputs["IrpRef"] == want_ref, (
        f"Ref must join Glue's ResourceArn and ResourcePropertyArn with '|': expected "
        f"{want_ref!r}, got {outputs['IrpRef']!r}"
    )
    listed = [p["ResourcePropertyArn"] for p in _properties_on(glue, resource_arn)]
    assert listed == [resource_property_arn], (
        f"ListIntegrationResourceProperties for the database: expected "
        f"{[resource_property_arn]!r}, got {listed!r}"
    )

    # The property's own delete: an update removes only it, while its database stays.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(role_name, database_name, with_irp=False),
                     Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack!r} update ended {status!r}, expected UPDATE_COMPLETE"
    remaining = _properties_on(glue, resource_arn)
    assert remaining == [], (
        f"removing Irp from the stack must delete the property, Glue still lists {remaining!r}"
    )
    kept = glue.get_database(CatalogId=ctx.account, Name=database_name)["Database"]["Name"]
    assert kept == database_name, f"the database must survive the update, Glue reports {kept!r}"

    delete_stack(cfn, stack_id)
    db_gone = ("EntityNotFoundException", f"Database {database_name} not found.")
    expect_error(lambda: glue.get_database(CatalogId=ctx.account, Name=database_name), *db_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
