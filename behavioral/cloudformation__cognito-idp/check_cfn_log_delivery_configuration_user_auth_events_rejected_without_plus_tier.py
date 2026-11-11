"""cfn-log-delivery-configuration-user-auth-events-rejected-without-plus-tier."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "cfn-log-delivery-configuration-user-auth-events-rejected-without-plus-tier"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]

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


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "The following feature is not available for the ESSENTIALS pricing tier configured: Log "
    "Streaming (Service: CognitoIdentityProvider, Status Code: 400, Request ID: <id>) (SDK Attempt "
    "Count: <n>)",
    "GeneralServiceException",
)


def _template(pool_name: str, log_group_name: str, event_source: str) -> str:
    """The pool declares the ESSENTIALS tier the refusal depends on; EventSource is the varied value."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Pool": {"Type": "AWS::Cognito::UserPool", "Properties": {
                "UserPoolName": pool_name, "UserPoolTier": "ESSENTIALS"}},
            "LogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": {
                "LogGroupName": log_group_name, "RetentionInDays": 1}},
            "LogDelivery": {"Type": "AWS::Cognito::LogDeliveryConfiguration",
                            "DependsOn": "LogGroup", "Properties": {
                                "UserPoolId": {"Ref": "Pool"},
                                "LogConfigurations": [{
                                    "EventSource": event_source,
                                    "LogLevel": "ERROR",
                                    "CloudWatchLogsConfiguration": {"LogGroupArn": {
                                        "Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:"
                                                   f"${{AWS::AccountId}}:log-group:{log_group_name}"}},
                                }],
                            }},
        },
        "Outputs": {"PoolRef": {"Value": {"Ref": "Pool"}}},
    })


def _pool_names(cognito):
    return [p["Name"] for p in paginate(cognito, "list_user_pools", "UserPools", MaxResults=60)]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation LogDeliveryConfiguration for userAuthEvents on an ESSENTIALS pool is refused.

    Cognito's exact tier refusal rolls the stack back and its pool is gone, while the same template
    with userNotification deploys and reads back its tier and configuration.
    """
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    good_pool = ctx.unique_name("sim2real-behav-cogauthlogpoolok-")
    bad_pool = ctx.unique_name("sim2real-behav-cogauthlogpool-")
    good_group = "/" + ctx.unique_name("sim2real-behav-cogauthloggrpctrl-")
    bad_group = "/" + ctx.unique_name("sim2real-behav-cogauthloggrp-")

    # Positive control: the same template, EventSource given a tier-unrestricted value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cogauthloggoodstack-"),
                           _template(good_pool, good_group, "userNotification"))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    pool_id = stack_outputs(cfn, good_id)["PoolRef"]
    tier = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]["UserPoolTier"]
    assert tier == "ESSENTIALS", f"control pool tier {tier!r}"
    config = cognito.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    partition = good_id.split(":")[1]
    want = [{"EventSource": "userNotification", "LogLevel": "ERROR", "CloudWatchLogsConfiguration": {
        "LogGroupArn": f"arn:{partition}:logs:{ctx.region}:{ctx.account}:log-group:{good_group}"}}]
    assert config["LogConfigurations"] == want, f"control log configuration {config!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cogauthlogbadstack-"),
                          _template(bad_pool, bad_group, "userAuthEvents"))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"userAuthEvents stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "LogDelivery"), ctx.account,
                         bad_pool, bad_group)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Cognito, by the pool's name, before any delete.
    names = _pool_names(cognito)
    assert good_pool in names and bad_pool not in names, (
        f"ListUserPools: control listed {good_pool in names}, rolled-back listed {bad_pool in names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
