"""cfn-iot-logging-and-resource-specific-logging-read-back-then-disabled-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iot-logging-and-resource-specific-logging-read-back-then-disabled-after-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot"]

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


# ---- Check-specific: the template, then run(). ----

_NOT_CONFIGURED = (
    "NotConfiguredException",
    "SetV2LoggingOptions was not previously called. No logging options have been set.",
)


def _prior_logging_options(iot) -> dict | None:
    """The account's v2 logging options, or None when SetV2LoggingOptions was never called."""
    try:
        return iot.get_v2_logging_options()
    except ClientError as exc:
        err = exc.response["Error"]
        if (err["Code"], err.get("Message")) != _NOT_CONFIGURED:
            raise
        return None


def _log_target_names(iot, target_type: str) -> dict[str, str]:
    """targetName -> logLevel of every ``target_type`` level, following nextToken to the end."""
    found: dict[str, str] = {}
    kwargs: dict = {"targetType": target_type}
    while True:
        page = iot.list_v2_logging_levels(**kwargs)
        for c in page.get("logTargetConfigurations", []):
            found[c["logTarget"]["targetName"]] = c["logLevel"]
        if not page.get("nextToken"):
            return found
        kwargs["nextToken"] = page["nextToken"]


def _wait_log_level_absent(iot, target_type: str, target_name: str, *,
                            timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    """Poll list_v2_logging_levels until ``target_name`` no longer appears for ``target_type``."""
    deadline = time.monotonic() + timeout_s
    names = set()
    while time.monotonic() < deadline:
        names = set(_log_target_names(iot, target_type))
        if target_name not in names:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"{target_name!r} still present in list_v2_logging_levels after {timeout_s}s: {names!r}"
    )


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control",
      "resource:account-singleton:iot-logging")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::IoT::Logging and its dependent
    AWS::IoT::ResourceSpecificLogging are real at IoT: Ref and the role and log levels match
    IoT's own v2 logging options, and deleting the stack disables logging and drops the level."""
    cfn = ctx.client("cloudformation")
    iot = ctx.client("iot")

    # AWS::IoT::Logging owns the account's one v2 logging configuration and its delete disables
    # all logs, so the check runs only where logging is unset or already disabled.
    prior = _prior_logging_options(iot)
    assert prior is None or prior.get("disableAllLogs") is True, (
        "precondition: IoT v2 logging must be unset or disabled in this account and region before "
        f"the stack takes it over; it is enabled at defaultLogLevel {prior.get('defaultLogLevel')!r}"
    )

    stack_name = ctx.unique_name("sim2real-behav-cfn-v2log-")
    thing_group_name = ctx.unique_name("sim2real-behav-tg-")

    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "iot.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ThingGroup": {
                "Type": "AWS::IoT::ThingGroup",
                "Properties": {"ThingGroupName": thing_group_name},
            },
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "ManagedPolicyArns": [
                        {"Fn::Sub":
                         "arn:${AWS::Partition}:iam::aws:policy/service-role/AWSIoTLogging"},
                    ],
                },
            },
            "Logging": {
                "Type": "AWS::IoT::Logging",
                "Properties": {
                    "AccountId": ctx.account,
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "DefaultLogLevel": "ERROR",
                },
            },
            "ResourceSpecificLogging": {
                "Type": "AWS::IoT::ResourceSpecificLogging",
                "DependsOn": "Logging",
                "Properties": {
                    "TargetType": "THING_GROUP",
                    "TargetName": thing_group_name,
                    "LogLevel": "DEBUG",
                },
            },
        },
        "Outputs": {
            "LoggingRef": {"Value": {"Ref": "Logging"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "RslRef": {"Value": {"Ref": "ResourceSpecificLogging"}},
            "RslTargetId": {"Value": {"Fn::GetAtt": ["ResourceSpecificLogging", "TargetId"]}},
        },
    })

    stack_id = create_stack(ctx, cfn, stack_name, template, Capabilities=["CAPABILITY_IAM"])
    created = wait_stack(cfn, stack_id, timeout_s=240.0)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    assert outputs["LoggingRef"] == ctx.account, (
        f"Ref Logging was {outputs['LoggingRef']!r}, expected the primary identifier "
        f"(the account id) {ctx.account!r}"
    )
    expected_target_id = f"THING_GROUP:{thing_group_name}"
    assert outputs["RslRef"] == expected_target_id, (
        f"Ref ResourceSpecificLogging was {outputs['RslRef']!r}, expected {expected_target_id!r}"
    )
    assert outputs["RslTargetId"] == expected_target_id, (
        f"GetAtt ResourceSpecificLogging.TargetId was {outputs['RslTargetId']!r}, "
        f"expected {expected_target_id!r}"
    )

    group = iot.describe_thing_group(thingGroupName=thing_group_name)
    assert group["thingGroupName"] == thing_group_name, (
        f"expected IoT to hold thing group {thing_group_name!r}, got {group['thingGroupName']!r}"
    )

    # Independent read at the destination: IoT's own v2 logging options and per-target
    # levels must carry the properties the template declared.
    options = iot.get_v2_logging_options()
    assert options["roleArn"] == outputs["RoleArn"], (
        f"expected v2 logging roleArn {outputs['RoleArn']!r}, got {options['roleArn']!r}"
    )
    assert options["defaultLogLevel"] == "ERROR", (
        f"expected defaultLogLevel 'ERROR', got {options['defaultLogLevel']!r}"
    )
    assert options["disableAllLogs"] is False, (
        f"expected disableAllLogs False while the stack is up, got {options['disableAllLogs']!r}"
    )

    by_name = _log_target_names(iot, "THING_GROUP")
    assert by_name.get(thing_group_name) == "DEBUG", (
        f"expected {thing_group_name!r} logged at 'DEBUG', got {by_name.get(thing_group_name)!r} "
        f"in {by_name!r}"
    )

    delete_stack(cfn, stack_id)

    _wait_log_level_absent(iot, "THING_GROUP", thing_group_name)

    after = iot.get_v2_logging_options()
    assert after["disableAllLogs"] is True, (
        f"expected disableAllLogs True (the documented disabled state) after stack delete, "
        f"got {after['disableAllLogs']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
