"""deploy-cfn-events-connection-and-api-destination-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-events-connection-and-api-destination-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "events"]

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


_ENDPOINT = "https://example.com/sim2real-endpoint"


def _destination_not_found(name: str) -> tuple[str, str]:
    return ("ResourceNotFoundException",
            f"Failed to describe the api-destination(s). An api-destination '{name}' does not exist.")


def _connection_not_found(name: str) -> tuple[str, str]:
    return ("ResourceNotFoundException",
            f"Failed to describe the connection(s). Connection '{name}' does not exist.")


def _template(connection_name: str, destination_name: str) -> str:
    """The API key arrives as a NoEcho parameter, so it never appears in the template text."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"ApiKey": {"Type": "String", "NoEcho": True}},
            "Resources": {
                "Connection": {
                    "Type": "AWS::Events::Connection",
                    "Properties": {
                        "Name": connection_name,
                        "Description": "sim2real cfn connection",
                        "AuthorizationType": "API_KEY",
                        "AuthParameters": {
                            "ApiKeyAuthParameters": {
                                "ApiKeyName": "sim2real-auth-header",
                                "ApiKeyValue": {"Ref": "ApiKey"},
                            }
                        },
                    },
                },
                "Destination": {
                    "Type": "AWS::Events::ApiDestination",
                    "Properties": {
                        "Name": destination_name,
                        "Description": "sim2real cfn api destination",
                        "ConnectionArn": {"Fn::GetAtt": ["Connection", "Arn"]},
                        "InvocationEndpoint": _ENDPOINT,
                        "HttpMethod": "POST",
                        "InvocationRateLimitPerSecond": 5,
                    },
                },
            },
            "Outputs": {
                "ConnectionRef": {"Value": {"Ref": "Connection"}},
                "ConnectionArn": {"Value": {"Fn::GetAtt": ["Connection", "Arn"]}},
                "ConnectionSecretArn": {"Value": {"Fn::GetAtt": ["Connection", "SecretArn"]}},
                "DestinationRef": {"Value": {"Ref": "Destination"}},
                "DestinationArn": {"Value": {"Fn::GetAtt": ["Destination", "Arn"]}},
            },
        }
    )


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A stack-provisioned AWS::Events::Connection and AWS::Events::ApiDestination that
    references it have Ref equal to their name and DescribeConnection/DescribeApiDestination
    matching the stack's properties and Fn::GetAtt outputs; deleting the stack removes both.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")

    connection_name = ctx.unique_name("sim2real-behav-evconn-")
    destination_name = ctx.unique_name("sim2real-behav-evdest-")
    stack_name = ctx.unique_name("sim2real-behav-evconn-stack-")

    stack_id = create_stack(
        ctx, cfn, stack_name,
        _template(connection_name, destination_name),
        Parameters=[{"ParameterKey": "ApiKey",
                     "ParameterValue": ctx.unique_name("sim2real-api-key-")}],
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack create ended in {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    assert outputs["ConnectionRef"] == connection_name, (
        f"Ref on the Connection should be its name, got {outputs['ConnectionRef']!r}"
    )
    assert outputs["DestinationRef"] == destination_name, (
        f"Ref on the ApiDestination should be its name, got {outputs['DestinationRef']!r}"
    )

    connection = events.describe_connection(Name=connection_name)
    assert connection["Name"] == outputs["ConnectionRef"], f"connection Name {connection['Name']!r}"
    assert connection["ConnectionArn"] == outputs["ConnectionArn"], (
        f"GetAtt Connection.Arn {outputs['ConnectionArn']!r} must match DescribeConnection's "
        f"{connection['ConnectionArn']!r}"
    )
    assert connection["SecretArn"] == outputs["ConnectionSecretArn"], (
        f"GetAtt Connection.SecretArn {outputs['ConnectionSecretArn']!r} must match "
        f"DescribeConnection's {connection['SecretArn']!r}"
    )
    assert connection["AuthorizationType"] == "API_KEY", (
        f"expected AuthorizationType API_KEY, got {connection['AuthorizationType']!r}"
    )
    assert connection["Description"] == "sim2real cfn connection", (
        f"expected the template's Description, got {connection['Description']!r}"
    )
    assert (
        connection["AuthParameters"]["ApiKeyAuthParameters"]["ApiKeyName"] == "sim2real-auth-header"
    ), (
        "expected ApiKeyName sim2real-auth-header, got "
        f"{connection['AuthParameters']['ApiKeyAuthParameters']!r}"
    )
    state = _wait_connection_state(events, connection_name)
    assert state == "AUTHORIZED", f"expected the settled ConnectionState AUTHORIZED, got {state!r}"

    destination = events.describe_api_destination(Name=destination_name)
    assert destination["Name"] == outputs["DestinationRef"], f"destination Name {destination['Name']!r}"
    assert destination["ApiDestinationArn"] == outputs["DestinationArn"], (
        f"GetAtt Destination.Arn {outputs['DestinationArn']!r} must match "
        f"DescribeApiDestination's {destination['ApiDestinationArn']!r}"
    )
    assert destination["ConnectionArn"] == outputs["ConnectionArn"], (
        f"the destination's ConnectionArn should be the connection's own Arn "
        f"{outputs['ConnectionArn']!r}, got {destination['ConnectionArn']!r}"
    )
    assert destination["InvocationEndpoint"] == _ENDPOINT, (
        f"expected InvocationEndpoint {_ENDPOINT!r}, got {destination['InvocationEndpoint']!r}"
    )
    assert destination["HttpMethod"] == "POST", (
        f"expected HttpMethod POST, got {destination['HttpMethod']!r}"
    )
    assert destination["InvocationRateLimitPerSecond"] == 5, (
        f"expected InvocationRateLimitPerSecond 5, got {destination['InvocationRateLimitPerSecond']!r}"
    )
    assert destination["Description"] == "sim2real cfn api destination", (
        f"expected the template's Description, got {destination['Description']!r}"
    )
    assert destination["ApiDestinationState"] == "ACTIVE", (
        f"expected ApiDestinationState ACTIVE, got {destination['ApiDestinationState']!r}"
    )

    delete_stack(cfn, stack_id)
    destination_gone = _destination_not_found(destination_name)
    connection_gone = _connection_not_found(connection_name)
    expect_error(lambda: events.describe_api_destination(Name=destination_name), *destination_gone)
    expect_error(lambda: events.describe_connection(Name=connection_name), *connection_gone)


_CONNECTION_TERMINAL = {"AUTHORIZED", "DEAUTHORIZED", "FAILED_CONNECTIVITY"}


def _wait_connection_state(events, name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    """Poll DescribeConnection to a terminal ConnectionState (never assert a transitional one)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = events.describe_connection(Name=name)["ConnectionState"]
        if last in _CONNECTION_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"connection {name} did not settle within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
