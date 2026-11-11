"""deploy-cfn-lakeformation-permissions-grant-round-trip-and-revoke."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-lakeformation-permissions-grant-round-trip-and-revoke"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue", "iam", "lakeformation"]

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

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "glue.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def _db_grants(lf, role_arn: str, db_name: str) -> list[tuple[list[str], list[str]]]:
    """(Permissions, PermissionsWithGrantOption) of every entry, all pages, for role on db."""
    kw = {"Principal": {"DataLakePrincipalIdentifier": role_arn},
          "Resource": {"Database": {"Name": db_name}}}
    out = []
    while True:
        page = lf.list_permissions(**kw)
        out += [(e["Permissions"], e.get("PermissionsWithGrantOption", []))
                for e in page["PrincipalResourcePermissions"]]
        if not page.get("NextToken"):
            return out
        kw["NextToken"] = page["NextToken"]


def _template(role_name: str, db1: str, db2: str, account: str, *, with_permissions: bool) -> str:
    resources = {
        "PrincipalRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST,
            },
        },
        "Db1": {"Type": "AWS::Glue::Database", "Properties": {
            "CatalogId": account, "DatabaseInput": {"Name": db1}}},
        "Db2": {"Type": "AWS::Glue::Database", "Properties": {
            "CatalogId": account, "DatabaseInput": {"Name": db2}}},
    }
    outputs = {"PrincipalRoleArn": {"Value": {"Fn::GetAtt": ["PrincipalRole", "Arn"]}}}
    if with_permissions:
        resources["LegacyPerm"] = {
            "Type": "AWS::LakeFormation::Permissions",
            "DependsOn": ["Db1", "PrincipalRole"],
            "Properties": {
                "DataLakePrincipal": {
                    "DataLakePrincipalIdentifier": {"Fn::GetAtt": ["PrincipalRole", "Arn"]}},
                "Resource": {"DatabaseResource": {"Name": db1}},
                "Permissions": ["DESCRIBE"],
            },
        }
        resources["NewPerm"] = {
            "Type": "AWS::LakeFormation::PrincipalPermissions",
            "DependsOn": ["Db2", "PrincipalRole"],
            "Properties": {
                "Principal": {"DataLakePrincipalIdentifier": {"Fn::GetAtt": ["PrincipalRole", "Arn"]}},
                "Resource": {"Database": {"CatalogId": account, "Name": db2}},
                "Permissions": ["DESCRIBE"],
                "PermissionsWithGrantOption": [],
            },
        }
        outputs["LegacyPermId"] = {"Value": {"Ref": "LegacyPerm"}}
        outputs["NewPermPrincipalIdentifier"] = {"Value": {"Fn::GetAtt": ["NewPerm", "PrincipalIdentifier"]}}
        outputs["NewPermResourceIdentifier"] = {"Value": {"Fn::GetAtt": ["NewPerm", "ResourceIdentifier"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation's LakeFormation Permissions and PrincipalPermissions grant exactly DESCRIBE.

    Lake Formation lists that grant beside the database's ALL; an update dropping both revokes
    DESCRIBE only, and deleting the stack removes the role and both databases from IAM and Glue.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lakeformation-permissions.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    glue = ctx.client("glue")
    lf = ctx.client("lakeformation")
    role_name = ctx.unique_name("sim2real-behav-lfperm-role-")
    db1 = ctx.unique_name("sim2real_behav_lfperm_db1_")
    db2 = ctx.unique_name("sim2real_behav_lfperm_db2_")
    account = ctx.account

    stack_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-behav-cfn-lfperm-"),
        _template(role_name, db1, db2, account, with_permissions=True),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    role = iam.get_role(RoleName=role_name)["Role"]
    role_arn = role["Arn"]
    assert outputs["PrincipalRoleArn"] == role_arn, (
        f"GetAtt PrincipalRole.Arn {outputs['PrincipalRoleArn']!r}, IAM reports {role_arn!r}"
    )
    assert role["AssumeRolePolicyDocument"] == _TRUST, (
        f"role trust policy {role['AssumeRolePolicyDocument']!r}, expected {_TRUST!r}"
    )

    # AWS::LakeFormation::Permissions: Ref is "LakeFormation-<principal>::<resource ARN>".
    db1_arn = f"arn:{partition}:glue:{ctx.region}:{account}:database/{db1}"
    expected_legacy_id = f"LakeFormation-{role_arn}::{db1_arn}"
    assert outputs["LegacyPermId"] == expected_legacy_id, (
        f"Ref(LegacyPerm) {outputs['LegacyPermId']!r}, expected {expected_legacy_id!r}"
    )

    # AWS::LakeFormation::PrincipalPermissions: the read-only GetAtts are the composite
    # identifier halves, each a JSON object naming the principal and the resource granted on.
    principal_identifier = json.loads(outputs["NewPermPrincipalIdentifier"])
    assert principal_identifier == {"DataLakePrincipalIdentifier": role_arn}, (
        f"PrincipalIdentifier {principal_identifier!r}"
    )
    resource_identifier = json.loads(outputs["NewPermResourceIdentifier"])
    expected_resource_identifier = {
        "Catalog": None,
        "Database": {"CatalogId": account, "Name": db2},
        "Table": None, "TableWithColumns": None, "DataLocation": None,
        "DataCellsFilter": None, "LFTag": None, "LFTagPolicy": None,
    }
    assert resource_identifier == expected_resource_identifier, (
        f"ResourceIdentifier {resource_identifier!r}, expected {expected_resource_identifier!r}"
    )

    # In an account on IAM access control, ListPermissions also reports the database's ALL
    # beside the granted DESCRIBE; that ALL is not the stack's, so it outlives the revoke.
    for db in (db1, db2):
        grants = _db_grants(lf, role_arn, db)
        assert grants == [(["ALL", "DESCRIBE"], [])], f"Lake Formation lists {grants!r} on {db!r}"

    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(role_name, db1, db2, account, with_permissions=False),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"permission-removing update ended {status!r}"
    for db in (db1, db2):
        grants = _db_grants(lf, role_arn, db)
        assert grants == [(["ALL"], [])], (
            f"after the update Lake Formation lists {grants!r} on {db!r}, expected only the ALL"
        )
        assert glue.get_database(Name=db)["Database"]["Name"] == db, f"database {db!r} is gone"

    delete_stack(cfn, stack_id)
    for db in (db1, db2):
        db_gone = ("EntityNotFoundException", f"Database {db} not found.")
        expect_error(lambda db=db: glue.get_database(Name=db), *db_gone)
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    until_raises(lambda: iam.get_role(RoleName=role_name))
    expect_error(lambda: iam.get_role(RoleName=role_name), *role_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
