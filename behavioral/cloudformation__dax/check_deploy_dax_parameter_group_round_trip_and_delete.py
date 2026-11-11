"""deploy-dax-parameter-group-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dax-parameter-group-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "dax"]

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


_DESCRIPTION = "sim2real dax parameter group"
_RECORD_TTL = "70000"
_QUERY_TTL = "80000"


def _template(name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ParamGroup": {
                "Type": "AWS::DAX::ParameterGroup",
                "Properties": {
                    "ParameterGroupName": name,
                    "Description": _DESCRIPTION,
                    "ParameterNameValues": {
                        "record-ttl-millis": _RECORD_TTL,
                        "query-ttl-millis": _QUERY_TTL,
                    },
                },
            },
        },
        "Outputs": {
            "ParamGroupRef": {"Value": {"Ref": "ParamGroup"}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::DAX::ParameterGroup's Ref is the group's own name, and its
    ParameterNameValues read back through DAX DescribeParameters as "user"-sourced
    values; deleting the stack removes the group (ParameterGroupNotFoundFault).

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dax-parametergroup.html
    """
    dax = ctx.client("dax")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-daxpgstack-")
    name = ctx.unique_name("sim2real-daxpg-")

    stack_id = create_stack(ctx, cfn, stack, _template(name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    ref = outputs["ParamGroupRef"]
    assert ref == name, (
        f"expected Ref to be the declared ParameterGroupName {name!r}, CloudFormation output "
        f"{ref!r}"
    )

    # Ref against an independent read: the account's parameter groups, every page.
    groups = [g for g in paginate(dax, "describe_parameter_groups", "ParameterGroups")
              if g["ParameterGroupName"] == name]
    assert len(groups) == 1, f"DescribeParameterGroups lists {groups!r} for {name!r}"
    group = groups[0]
    assert group["ParameterGroupName"] == ref, (
        f"expected DescribeParameterGroups to echo back {ref!r}, got {group['ParameterGroupName']!r}"
    )
    assert group["Description"] == _DESCRIPTION, (
        f"expected Description {_DESCRIPTION!r}, DAX reports {group['Description']!r}"
    )

    params = {p["ParameterName"]: p for p in paginate(
        dax, "describe_parameters", "Parameters", ParameterGroupName=ref)}
    record_param = params["record-ttl-millis"]
    query_param = params["query-ttl-millis"]
    assert record_param["ParameterValue"] == _RECORD_TTL, (
        f"expected record-ttl-millis {_RECORD_TTL!r} as declared in ParameterNameValues, DAX "
        f"reports {record_param['ParameterValue']!r}"
    )
    assert record_param["Source"] == "user", (
        f"expected record-ttl-millis Source 'user' once CloudFormation applies "
        f"ParameterNameValues, DAX reports {record_param['Source']!r}"
    )
    assert query_param["ParameterValue"] == _QUERY_TTL, (
        f"expected query-ttl-millis {_QUERY_TTL!r} as declared in ParameterNameValues, DAX "
        f"reports {query_param['ParameterValue']!r}"
    )
    assert query_param["Source"] == "user", (
        f"expected query-ttl-millis Source 'user' once CloudFormation applies "
        f"ParameterNameValues, DAX reports {query_param['Source']!r}"
    )

    delete_stack(cfn, stack_id)
    parameter_groups_gone = ("ParameterGroupNotFoundFault", "Parameter Group not found.")
    expect_error(lambda: dax.describe_parameter_groups(ParameterGroupNames=[ref]),
                 *parameter_groups_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
