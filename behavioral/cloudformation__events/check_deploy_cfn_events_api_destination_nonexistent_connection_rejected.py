"""deploy-cfn-events-api-destination-nonexistent-connection-rejected."""
from __future__ import annotations

import json
import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-events-api-destination-nonexistent-connection-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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


def _api_key_parameter(api_key: str) -> list[dict]:
    return [{"ParameterKey": "ApiKey", "ParameterValue": api_key}]


def _template(connection_name: str, destination_name: str, connection_arn=None) -> str:
    """A Connection and an ApiDestination; ``connection_arn`` (when given) is the one change.

    The API key arrives as a NoEcho parameter, so it never appears in the template text.
    """
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"ApiKey": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "Connection": {"Type": "AWS::Events::Connection", "Properties": {
                "Name": connection_name,
                "AuthorizationType": "API_KEY",
                "AuthParameters": {"ApiKeyAuthParameters": {
                    "ApiKeyName": "sim2real-auth-header", "ApiKeyValue": {"Ref": "ApiKey"}}},
            }},
            "Destination": {"Type": "AWS::Events::ApiDestination", "Properties": {
                "Name": destination_name,
                "ConnectionArn": connection_arn or {"Fn::GetAtt": ["Connection", "Arn"]},
                "InvocationEndpoint": _ENDPOINT,
                "HttpMethod": "POST",
            }},
        },
        "Outputs": {"DestinationRef": {"Value": {"Ref": "Destination"}},
                    "ConnectionArn": {"Value": {"Fn::GetAtt": ["Connection", "Arn"]}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ApiDestination whose ConnectionArn names a missing connection is refused.

    The handler relays EventBridge's exact reason and no api destination of that name exists,
    while the same template naming its own Connection deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    api_key = ctx.unique_name("sim2real-api-key-")

    # The negative: the same template, with only ConnectionArn naming a connection never created.
    missing_name = ctx.unique_name("sim2real-behav-evconn-missing-")
    missing_uuid = str(uuid.uuid4())
    missing_arn = {"Fn::Sub": "arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}"
                              f":connection/{missing_name}/{missing_uuid}"}
    bad_connection = ctx.unique_name("sim2real-behav-evconn-bad-")
    bad_destination = ctx.unique_name("sim2real-behav-evdest-bad-")
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-evdest-bad-stack-"),
                          _template(bad_connection, bad_destination, missing_arn),
                          Parameters=_api_key_parameter(api_key))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"the missing-connection stack ended {status!r}"
    partition = bad_id.split(":")[1]
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Destination"), ctx.account,
                         bad_destination)
    want = (
        "Failed to create the api-destination(s). Connection "
        f"'arn:{partition}:events:{ctx.region}:<account>:connection/{missing_name}/{missing_uuid}' "
        "does not exist. (Service: EventBridge, Status Code: 400, Request ID: <id>) "
        "(SDK Attempt Count: <n>)",
        "NotFound",
    )
    assert got == want, f"handler reason {got!r}, expected {want!r}"
    # Rollback absence through EventBridge, by the would-be name, before this check's delete.
    destination_gone = _destination_not_found(bad_destination)
    expect_error(lambda: events.describe_api_destination(Name=bad_destination), *destination_gone)
    delete_stack(cfn, bad_id)

    # Positive control: the same template with ConnectionArn naming its own Connection.
    connection = ctx.unique_name("sim2real-behav-evconn-ctl-")
    destination = ctx.unique_name("sim2real-behav-evdest-ctl-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-evdest-ctl-stack-"),
                           _template(connection, destination),
                           Parameters=_api_key_parameter(api_key))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"the control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    assert out["DestinationRef"] == destination, f"Ref {out['DestinationRef']!r}"
    read = events.describe_api_destination(Name=destination)
    got = (read["Name"], read["ConnectionArn"], read["InvocationEndpoint"], read["HttpMethod"])
    assert got == (destination, out["ConnectionArn"], _ENDPOINT, "POST"), (
        f"the control api destination reads {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
