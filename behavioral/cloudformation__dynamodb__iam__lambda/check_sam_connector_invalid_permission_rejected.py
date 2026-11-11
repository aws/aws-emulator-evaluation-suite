"""sam-connector-invalid-permission-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-connector-invalid-permission-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "iam", "lambda"]

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


def create_stack_via_change_set(ctx, cf, name, template, capabilities, timeout_s=300.0):
    """Deploy a Transform (SAM) template as `sam deploy` does: CREATE change set, execute, wait.

    Returns ``(stack_id, change_set, stack_status)``; a FAILED change set is not executed
    (status None), so the check grades ``change_set["StatusReason"]``. Cleanup is registered first.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    resp = cf.create_change_set(
        StackName=name, ChangeSetName="sim2real-create", ChangeSetType="CREATE",
        TemplateBody=template, Capabilities=list(capabilities),
        Tags=[{"Key": "sim2real", "Value": name}],
    )
    stack_id, change_set_id = resp["StackId"], resp["Id"]
    created["StackId"] = stack_id
    deadline = time.monotonic() + timeout_s
    while True:
        change_set = cf.describe_change_set(ChangeSetName=change_set_id)
        if change_set["Status"] in ("CREATE_COMPLETE", "FAILED"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"change set {change_set_id} still {change_set['Status']!r}")
        time.sleep(2)
    if change_set["Status"] == "FAILED":
        return stack_id, change_set, None
    cf.execute_change_set(ChangeSetName=change_set_id)
    return stack_id, change_set, wait_stack(cf, stack_id, timeout_s=timeout_s)


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

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_READ_ACTIONS = {
    "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
    "dynamodb:ConditionCheckItem", "dynamodb:PartiQLSelect",
}
_TRANSFORM_REASON = (
    "Transform AWS::Serverless-2016-10-31 failed with: Invalid Serverless Application "
    "Specification document. Number of errors found: 1. Resource with id [Connector] is "
    "invalid. Unsupported 'Permissions' provided for connector from AWS::Lambda::Function "
    "to AWS::DynamoDB::Table; valid values are: Read, Write."
)
_DEADLINE_S = 600.0

# The table and function names and the permission are filled in per run (str.format), as
# `sam deploy` would pass them; the skeleton's change-set deploy takes no Parameters.
_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  Table:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: {table_name}
      PrimaryKey:
        Name: pk
        Type: String
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: {function_name}
      Handler: index.handler
      Runtime: python3.13
      InlineCode: |
        def handler(event, context):
            return {{"ok": True}}
  Connector:
    Type: AWS::Serverless::Connector
    Properties:
      Source:
        Id: Fn
      Destination:
        Id: Table
      Permissions:
        - {permission}
"""


@tags("axis:rejection", "cap:c2", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Connector with a Permissions value other than Read or Write fails the SAM transform in
    its change set and creates nothing; the same template with Read deploys and grants exactly
    the Read actions on the table to the function's role."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")

    bad_table_name = ctx.unique_name("sim2real-sam-connneg-bad-tbl-")
    bad_function_name = ctx.unique_name("sim2real-sam-connneg-bad-fn-")
    bad_stack = ctx.unique_name("sim2real-sam-connneg-bad-")
    bad_stack_id, bad_change_set, _ = create_stack_via_change_set(
        ctx, cfn, bad_stack,
        _TEMPLATE.format(table_name=bad_table_name, function_name=bad_function_name,
                         permission="Delete"),
        _CAPS, timeout_s=_DEADLINE_S,
    )
    assert (bad_change_set["Status"], bad_change_set.get("StatusReason")) == (
        "FAILED", _TRANSFORM_REASON
    ), (
        f"a Connector with Permissions: [Delete] must fail the transform with "
        f"{_TRANSFORM_REASON!r}; got {(bad_change_set['Status'], bad_change_set.get('StatusReason'))!r}"
    )
    bad_resources = paginate(cfn, "list_stack_resources", "StackResourceSummaries",
                             StackName=bad_stack_id)
    assert bad_resources == [], f"the refused stack must create nothing; got {bad_resources!r}"
    bad_table_gone = (
        "ResourceNotFoundException", f"Requested resource not found: Table: {bad_table_name} not found"
    )
    expect_error(lambda: ddb.describe_table(TableName=bad_table_name), *bad_table_gone)

    # Positive control: the same template with Permissions: [Read].
    good_table_name = ctx.unique_name("sim2real-sam-connneg-good-tbl-")
    good_function_name = ctx.unique_name("sim2real-sam-connneg-good-fn-")
    ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{good_function_name}"))
    good_stack = ctx.unique_name("sim2real-sam-connneg-good-")
    good_stack_id, good_change_set, status = create_stack_via_change_set(
        ctx, cfn, good_stack,
        _TEMPLATE.format(table_name=good_table_name, function_name=good_function_name,
                         permission="Read"),
        _CAPS, timeout_s=_DEADLINE_S,
    )
    assert good_change_set["Status"] == "CREATE_COMPLETE", (
        f"the positive control's change set ended {good_change_set['Status']}: "
        f"{good_change_set.get('StatusReason')!r}"
    )
    assert status == "CREATE_COMPLETE", (
        f"the positive control (same template, Permissions: [Read]) must deploy clean; got "
        f"{status}: {decisive_rows(stack_events(cfn, good_stack_id))!r}"
    )

    def physical(logical_id: str) -> str:
        return cfn.describe_stack_resource(
            StackName=good_stack_id, LogicalResourceId=logical_id
        )["StackResourceDetail"]["PhysicalResourceId"]

    role_name, policy_arn = physical("FnRole"), physical("ConnectorPolicy")
    table_arn = ddb.describe_table(TableName=good_table_name)["Table"]["TableArn"]
    function_role = lam.get_function_configuration(FunctionName=good_function_name)["Role"]
    assert function_role == iam.get_role(RoleName=role_name)["Role"]["Arn"], (
        "the control function must run under the FnRole the template expands"
    )
    attached = [
        p["PolicyArn"]
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name)
        for p in page["AttachedPolicies"]
    ]
    assert policy_arn in attached, (
        f"the ConnectorPolicy is not attached to the function's role; attached: {attached!r}"
    )
    version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    statements = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)[
        "PolicyVersion"]["Document"]["Statement"]
    assert len(statements) == 1, f"expected one Read statement, got {statements!r}"
    actions = statements[0]["Action"]
    actions = actions if isinstance(actions, list) else [actions]
    assert set(actions) == _READ_ACTIONS and len(actions) == len(_READ_ACTIONS), (
        f"a Read connector must grant exactly the Read action set; got {sorted(actions)!r}"
    )
    assert statements[0]["Resource"] == [table_arn, f"{table_arn}/index/*"], (
        f"expected Resource [<table ARN>, <table ARN>/index/*], got {statements[0]['Resource']!r}"
    )


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
