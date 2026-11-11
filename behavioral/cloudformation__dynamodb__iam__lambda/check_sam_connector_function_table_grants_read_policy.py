"""sam-connector-function-table-grants-read-policy."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-connector-function-table-grants-read-policy"
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

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_READ_ACTIONS = {
    "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
    "dynamodb:ConditionCheckItem", "dynamodb:PartiQLSelect",
}
_DEADLINE_S = 600.0

# The table and function names are filled in per run (str.format), as `sam deploy` would pass
# them; the skeleton's change-set deploy takes no Parameters.
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
        - Read
Outputs:
  FunctionRoleName:
    Value: !Ref FnRole
  TableArn:
    Value: !GetAtt Table.Arn
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A Serverless::Connector expands into a real IAM managed policy attached to the source
    function's role, granting exactly the Read dynamodb actions on the destination table, and
    stack delete removes the policy, the function and the table."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")
    stack = ctx.unique_name("sim2real-sam-conn-")
    table_name = ctx.unique_name("sim2real-sam-conn-tbl-")
    function_name = ctx.unique_name("sim2real-sam-conn-fn-")

    ctx.on_cleanup(
        lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{function_name}")
    )

    stack_id, change_set, status = create_stack_via_change_set(
        ctx, cfn, stack, _TEMPLATE.format(table_name=table_name, function_name=function_name),
        _CAPS, timeout_s=_DEADLINE_S,
    )
    assert change_set["Status"] == "CREATE_COMPLETE", (
        f"change set for {stack} ended {change_set['Status']}: {change_set.get('StatusReason')!r}"
    )
    assert status == "CREATE_COMPLETE", (
        f"stack {stack} ended {status}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    outputs = stack_outputs(cfn, stack_id)
    role_name, table_arn = outputs["FunctionRoleName"], outputs["TableArn"]

    table = ddb.describe_table(TableName=table_name)["Table"]
    assert table["TableArn"] == table_arn, (
        f"GetAtt Table.Arn {table_arn!r} differs from DescribeTable's {table['TableArn']!r}"
    )
    assert table["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}], (
        f"expected SimpleTable PrimaryKey pk as the HASH key, got {table['KeySchema']!r}"
    )
    assert table["AttributeDefinitions"] == [{"AttributeName": "pk", "AttributeType": "S"}], (
        f"expected attribute pk of type S, got {table['AttributeDefinitions']!r}"
    )

    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    function = lam.get_function_configuration(FunctionName=function_name)
    got_fn = (function["FunctionName"], function["Handler"], function["Runtime"], function["Role"])
    want_fn = (function_name, "index.handler", "python3.13", role_arn)
    assert got_fn == want_fn, (
        f"expected function (name, handler, runtime, role == Ref FnRole's ARN) {want_fn!r}, "
        f"got {got_fn!r}"
    )

    # The connector's expanded AWS::IAM::ManagedPolicy, by its logical id; its physical id is the ARN.
    policy_arn = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="ConnectorPolicy"
    )["StackResourceDetail"]["PhysicalResourceId"]
    attached = [
        p["PolicyArn"]
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name)
        for p in page["AttachedPolicies"]
    ]
    assert policy_arn in attached, (
        f"the ConnectorPolicy is not attached to the function's role; attached: {attached!r}"
    )
    version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    document = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)[
        "PolicyVersion"]["Document"]
    statements = document["Statement"]
    assert len(statements) == 1, f"expected one Read statement, got {statements!r}"
    statement = statements[0]
    assert statement["Effect"] == "Allow", f"expected Effect Allow, got {statement['Effect']!r}"
    actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
    assert set(actions) == _READ_ACTIONS and len(actions) == len(_READ_ACTIONS), (
        f"a Read connector must grant exactly the Read action set; got {sorted(actions)!r}"
    )
    assert statement["Resource"] == [table_arn, f"{table_arn}/index/*"], (
        f"expected Resource [<table ARN>, <table ARN>/index/*], got {statement['Resource']!r}"
    )

    delete_stack(cfn, stack_id)
    policy_gone = ("NoSuchEntity", f"Policy {policy_arn} was not found.")
    expect_error(lambda: iam.get_policy(PolicyArn=policy_arn), *policy_gone)
    table_gone = (
        "ResourceNotFoundException", f"Requested resource not found: Table: {table_name} not found"
    )
    expect_error(lambda: ddb.describe_table(TableName=table_name), *table_gone)
    function_gone = (
        "ResourceNotFoundException",
        f"Function not found: arn:{partition}:lambda:{ctx.region}:{ctx.account}:function:"
        f"{function_name}",
    )
    expect_error(lambda: lam.get_function(FunctionName=function_name), *function_gone)


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
