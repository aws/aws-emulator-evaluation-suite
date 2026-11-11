"""deploy-cfn-codestarconnections-connection-resource-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-codestarconnections-connection-resource-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "codestar-connections"]

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

_CONNECTION_GONE = ("ResourceNotFoundException", "No connection exists with the ARN")


def _template(connection_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Conn": {
                    "Type": "AWS::CodeStarConnections::Connection",
                    "Properties": {
                        "ConnectionName": connection_name,
                        "ProviderType": "GitHub",
                    },
                },
            },
            "Outputs": {
                "ConnRef": {"Value": {"Ref": "Conn"}},
                "ConnArnAtt": {"Value": {"Fn::GetAtt": ["Conn", "ConnectionArn"]}},
                "ConnStatus": {"Value": {"Fn::GetAtt": ["Conn", "ConnectionStatus"]}},
                "ConnOwnerAccountId": {"Value": {"Fn::GetAtt": ["Conn", "OwnerAccountId"]}},
            },
        }
    )


@tags(
    "axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::CodeStarConnections::Connection reaches CREATE_COMPLETE, Ref and
    every Fn::GetAtt attribute match GetConnection, and deleting the stack removes the
    connection (GetConnection on its ARN then fails with ResourceNotFoundException)."""
    cf = ctx.client("cloudformation")
    codestar = ctx.client("codestar-connections")

    connection_name = ctx.unique_name("sim2real-cfnconn-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    stack_id = create_stack(ctx, cf, stack_name, _template(connection_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended in {status!r}, not CREATE_COMPLETE"

    outputs = stack_outputs(cf, stack_id)
    connection_arn = outputs["ConnRef"]
    assert outputs["ConnArnAtt"] == connection_arn, (
        f"expected Fn::GetAtt ConnectionArn to equal Ref {connection_arn!r}, got {outputs['ConnArnAtt']!r}"
    )

    listed = [c for c in _connections(codestar) if c["ConnectionName"] == connection_name]
    assert len(listed) == 1, f"expected one listed connection named {connection_name!r}, got {len(listed)}"
    assert listed[0]["ConnectionArn"] == connection_arn, (
        f"Ref should be the listed connection's ARN {listed[0]['ConnectionArn']!r}, got {connection_arn!r}"
    )

    conn = codestar.get_connection(ConnectionArn=connection_arn)["Connection"]
    assert conn["ConnectionArn"] == connection_arn, (
        f"GetConnection ConnectionArn is {conn['ConnectionArn']!r}, expected Ref {connection_arn!r}"
    )
    assert conn["ConnectionName"] == connection_name, (
        f"expected ConnectionName {connection_name!r}, got {conn['ConnectionName']!r}"
    )
    assert conn["ProviderType"] == "GitHub", f"expected ProviderType GitHub, got {conn['ProviderType']!r}"
    assert conn["ConnectionStatus"] == outputs["ConnStatus"], (
        f"expected Fn::GetAtt ConnectionStatus to equal GetConnection's {conn['ConnectionStatus']!r}, "
        f"got {outputs['ConnStatus']!r}"
    )
    assert conn["ConnectionStatus"] == "PENDING", (
        f"expected a fresh connection to be PENDING, got {conn['ConnectionStatus']!r}"
    )
    assert conn["OwnerAccountId"] == outputs["ConnOwnerAccountId"], (
        f"expected Fn::GetAtt OwnerAccountId to equal GetConnection's {conn['OwnerAccountId']!r}, "
        f"got {outputs['ConnOwnerAccountId']!r}"
    )
    assert conn["OwnerAccountId"] == ctx.account, (
        f"expected OwnerAccountId to be the creating account {ctx.account!r}, got {conn['OwnerAccountId']!r}"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: codestar.get_connection(ConnectionArn=connection_arn), *_CONNECTION_GONE)


def _connections(codestar) -> list[dict]:
    """Every connection ListConnections returns; it has no paginator, so every page is read."""
    out: list[dict] = []
    kwargs: dict = {}
    while True:
        page = codestar.list_connections(**kwargs)
        out.extend(page["Connections"])
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
