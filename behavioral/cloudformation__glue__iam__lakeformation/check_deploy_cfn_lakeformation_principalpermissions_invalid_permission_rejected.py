"""deploy-cfn-lakeformation-principalpermissions-invalid-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-lakeformation-principalpermissions-invalid-permission-rejected"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

_REJECTED_REASON = (
    "BOGUS_PERM is not a valid enum value. Supported values: [ALL, SELECT, ALTER, DROP, "
    "DELETE, INSERT, DESCRIBE, CREATE_DATABASE, CREATE_TABLE, DATA_LOCATION_ACCESS, "
    "CREATE_LF_TAG, ASSOCIATE, GRANT_WITH_LF_TAG_EXPRESSION]"
)


def _template(role_name: str, db_name: str, account: str, permission: str) -> str:
    return json.dumps({
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
            "Db": {"Type": "AWS::Glue::Database", "Properties": {
                "CatalogId": account, "DatabaseInput": {"Name": db_name}}},
            "BadPerm": {
                "Type": "AWS::LakeFormation::PrincipalPermissions",
                "DependsOn": ["Db", "Role"],
                "Properties": {
                    "Principal": {"DataLakePrincipalIdentifier": {"Fn::GetAtt": ["Role", "Arn"]}},
                    "Resource": {"Database": {"CatalogId": account, "Name": db_name}},
                    "Permissions": [permission],
                    "PermissionsWithGrantOption": [],
                },
            },
        },
    })


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


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::LakeFormation::PrincipalPermissions naming an unknown permission fails validation.

    The stack rolls back before its role and database exist, while the same template granting
    DESCRIBE deploys a grant Lake Formation lists exactly.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lakeformation-principalpermissions.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    glue = ctx.client("glue")
    lf = ctx.client("lakeformation")
    account = ctx.account
    good_role = ctx.unique_name("sim2real-behav-lfppgood-role-")
    good_db = ctx.unique_name("sim2real_behav_lfppgood_db_")
    bad_role = ctx.unique_name("sim2real-behav-lfppbad-role-")
    bad_db = ctx.unique_name("sim2real_behav_lfppbad_db_")

    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-lfppgood-"),
                           _template(good_role, good_db, account, "DESCRIBE"),
                           Capabilities=["CAPABILITY_NAMED_IAM"])
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-lfppbad-"),
                          _template(bad_role, bad_db, account, "BOGUS_PERM"),
                          Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    want = [("BadPerm", "PROPERTY_VALIDATION", "FAILED", "FAIL", _REJECTED_REASON,
             "/Resources/BadPerm/Properties/Permissions/0")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"

    # Validation runs before any resource is created: the role and database never existed.
    resources = cfn.describe_stack_resources(StackName=bad_id)["StackResources"]
    assert resources == [], f"the rejected stack created resources: {resources!r}"
    expect_error(lambda: glue.get_database(Name=bad_db),
                 *("EntityNotFoundException", f"Database {bad_db} not found."))
    expect_error(lambda: iam.get_role(RoleName=bad_role),
                 *("NoSuchEntity", f"The role with name {bad_role} cannot be found."))

    # Positive control: same template, the one property given a VALID value.
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    role_arn = iam.get_role(RoleName=good_role)["Role"]["Arn"]
    grants = _db_grants(lf, role_arn, good_db)
    # In an account on IAM access control, ListPermissions also reports the database's ALL
    # beside the granted DESCRIBE.
    assert grants == [(["ALL", "DESCRIBE"], [])], f"Lake Formation lists {grants!r} for the control"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
