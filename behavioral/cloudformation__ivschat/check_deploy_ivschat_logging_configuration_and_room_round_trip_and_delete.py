"""deploy-ivschat-logging-configuration-and-room-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ivschat-logging-configuration-and-room-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ivschat"]

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

def _template(log_cfg_name: str, room_name: str, max_len: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {"Type": "AWS::Logs::LogGroup"},
            "LoggingConfig": {
                "Type": "AWS::IVSChat::LoggingConfiguration",
                "Properties": {
                    "Name": log_cfg_name,
                    "DestinationConfiguration": {
                        "CloudWatchLogs": {"LogGroupName": {"Ref": "LogGroup"}},
                    },
                },
            },
            "Room": {
                "Type": "AWS::IVSChat::Room",
                "Properties": {
                    "Name": room_name,
                    "MaximumMessageLength": max_len,
                    "LoggingConfigurationIdentifiers": [{"Ref": "LoggingConfig"}],
                },
            },
        },
        "Outputs": {
            "LogGroupName": {"Value": {"Ref": "LogGroup"}},
            "LoggingConfigArn": {"Value": {"Ref": "LoggingConfig"}},
            "LoggingConfigId": {"Value": {"Fn::GetAtt": ["LoggingConfig", "Id"]}},
            "RoomArn": {"Value": {"Ref": "Room"}},
            "RoomId": {"Value": {"Fn::GetAtt": ["Room", "Id"]}},
        },
    })


def _all(fn, key: str, **kw) -> list[dict]:
    """Every item under ``key`` across the pages of an IVSChat list (it has no paginators)."""
    out = []
    while True:
        page = fn(**kw)
        out += page[key]
        if not page.get("nextToken"):
            return out
        kw["nextToken"] = page["nextToken"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation IVSChat LoggingConfiguration and attached Room read back exactly.

    Refs and GetAtts match IVSChat's listings, the configuration is ACTIVE on the declared log
    group and the room carries its properties and the configuration; the stack delete removes both.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ivschat-loggingconfiguration.html
    """
    ivschat = ctx.client("ivschat")
    cfn = ctx.client("cloudformation")
    log_cfg_name = ctx.unique_name("sim2real-ivschatcfn-logcfg")
    room_name = ctx.unique_name("sim2real-ivschatcfn-room")
    max_len = 200

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ivschatcfn-"),
                            _template(log_cfg_name, room_name, max_len))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Refs and GetAtt Ids against independent reads: the IVSChat list entries by name.
    configs = [(c["arn"], c["id"]) for c in _all(
        ivschat.list_logging_configurations, "loggingConfigurations") if c["name"] == log_cfg_name]
    assert configs == [(out["LoggingConfigArn"], out["LoggingConfigId"])], (
        f"IVSChat lists logging configurations {configs!r}; outputs {out!r}"
    )
    rooms = [(r["arn"], r["id"]) for r in _all(ivschat.list_rooms, "rooms", name=room_name)]
    assert rooms == [(out["RoomArn"], out["RoomId"])], f"IVSChat lists rooms {rooms!r}"

    # The configuration settles to ACTIVE shortly after the handler returns.
    deadline = time.monotonic() + 60.0
    while True:
        log_cfg = ivschat.get_logging_configuration(identifier=configs[0][0])
        if log_cfg["state"] != "CREATING" or time.monotonic() > deadline:
            break
        time.sleep(2)
    got = (log_cfg["state"], log_cfg["name"], log_cfg["destinationConfiguration"])
    want = ("ACTIVE", log_cfg_name, {"cloudWatchLogs": {"logGroupName": out["LogGroupName"]}})
    assert got == want, f"logging configuration reads {got!r}, expected {want!r}"
    room = ivschat.get_room(identifier=rooms[0][0])
    got = (room["name"], room["maximumMessageLength"], room["loggingConfigurationIdentifiers"])
    assert got == (room_name, max_len, [configs[0][0]]), f"room reads {got!r}"

    delete_stack(cfn, stack_id)
    for arn, getter in ((configs[0][0], ivschat.get_logging_configuration),
                        (rooms[0][0], ivschat.get_room)):
        expect_error(lambda arn=arn, getter=getter: getter(identifier=arn),
                     *("ResourceNotFoundException", f"Resource: {arn} not found"))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
