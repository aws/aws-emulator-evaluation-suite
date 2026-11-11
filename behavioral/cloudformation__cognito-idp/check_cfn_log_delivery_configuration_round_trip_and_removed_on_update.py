"""cfn-log-delivery-configuration-round-trip-and-removed-on-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-log-delivery-configuration-round-trip-and-removed-on-update"
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

def _template(*, with_log_delivery: bool, pool_name: str, log_group_name: str) -> str:
    resources = {
        "Pool": {"Type": "AWS::Cognito::UserPool", "Properties": {"UserPoolName": pool_name}},
        "LogGroup": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {"LogGroupName": log_group_name, "RetentionInDays": 1},
        },
    }
    if with_log_delivery:
        resources["LogDelivery"] = {
            "Type": "AWS::Cognito::LogDeliveryConfiguration",
            "DependsOn": "LogGroup",
            "Properties": {
                "UserPoolId": {"Ref": "Pool"},
                "LogConfigurations": [
                    {
                        "EventSource": "userNotification",
                        "LogLevel": "ERROR",
                        "CloudWatchLogsConfiguration": {
                            "LogGroupArn": {
                                "Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:"
                                f"log-group:{log_group_name}"
                            }
                        },
                    }
                ],
            },
        }
    outputs = {"PoolRef": {"Value": {"Ref": "Pool"}}}
    if with_log_delivery:
        outputs["LogDeliveryRef"] = {"Value": {"Ref": "LogDelivery"}}
        outputs["LogDeliveryId"] = {"Value": {"Fn::GetAtt": ["LogDelivery", "Id"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


def _pools_named(cognito, name):
    """Every user pool named ``name``, across all ListUserPools pages."""
    return [p for p in paginate(cognito, "list_user_pools", "UserPools", MaxResults=60)
            if p["Name"] == name]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Cognito LogDeliveryConfiguration reads back, then an update removes it.

    Its Ref and Id GetAtt equal the pool's listed Id and GetLogDeliveryConfiguration reports the
    template's entry; after the update the same pool reports no configurations.
    """
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-coglogdelpool-")
    log_group_name = "/" + ctx.unique_name("sim2real-behav-coglogdelgrp-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-coglogdelstack-"),
                            _template(with_log_delivery=True, pool_name=pool_name,
                                      log_group_name=log_group_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    expected_arn = f"arn:{partition}:logs:{ctx.region}:{ctx.account}:log-group:{log_group_name}"

    pools = [p["Id"] for p in _pools_named(cognito, pool_name)]
    assert pools == [out["PoolRef"]], f"user pools named {pool_name!r}: {pools!r}"
    pool_id = pools[0]
    assert (out["LogDeliveryRef"], out["LogDeliveryId"]) == (pool_id, pool_id), (
        f"LogDeliveryConfiguration Ref {out['LogDeliveryRef']!r}, GetAtt Id "
        f"{out['LogDeliveryId']!r}, expected the listed pool Id {pool_id!r}"
    )
    config = cognito.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    want = {"UserPoolId": pool_id, "LogConfigurations": [{
        "EventSource": "userNotification", "LogLevel": "ERROR",
        "CloudWatchLogsConfiguration": {"LogGroupArn": expected_arn}}]}
    assert config == want, f"GetLogDeliveryConfiguration {config!r}, expected {want!r}"

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(
        with_log_delivery=False, pool_name=pool_name, log_group_name=log_group_name))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"LogDelivery-dropping update ended {status!r}"
    after = cognito.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert after == {"UserPoolId": pool_id, "LogConfigurations": []}, (
        f"GetLogDeliveryConfiguration after the update {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
