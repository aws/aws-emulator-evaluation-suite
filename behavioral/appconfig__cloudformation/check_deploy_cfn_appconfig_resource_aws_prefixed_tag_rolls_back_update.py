"""deploy-cfn-appconfig-resource-aws-prefixed-tag-rolls-back-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-appconfig-resource-aws-prefixed-tag-rolls-back-update"
GROUP = "deploy"
SERVICES = ["appconfig", "cloudformation"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
})


def _wait_stack(cf, stack_id: str, *, timeout_s: float = 300.0) -> str:
    """Poll DescribeStacks every 2 s until a terminal StackStatus; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _template(app_name: str, tag_map: dict) -> str:
    """One AWS::AppConfig::Application carrying ``tag_map`` as its Tags property."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "App": {
                "Type": "AWS::AppConfig::Application",
                "Properties": {
                    "Name": app_name,
                    "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()],
                },
            },
        },
    })


def _own_tags(appconfig, arn: str) -> dict:
    """ListTagsForResource on ``arn``, excluding CloudFormation's own aws:cloudformation:* tags."""
    got = appconfig.list_tags_for_resource(ResourceArn=arn)["Tags"]
    return {k: v for k, v in got.items() if not k.startswith("aws:cloudformation:")}


def _physical_id(cf, stack_id: str, logical_id: str) -> str:
    return cf.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _resource_status_reason(cf, stack_id: str, logical_id: str, status: str) -> str:
    """The ResourceStatusReason of ``logical_id``'s single event at ``status``."""
    events = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    reasons = [
        e.get("ResourceStatusReason", "")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(reasons) == 1, f"expected one {status} event for {logical_id}, got {reasons!r}"
    return reasons[0]


def _delete_stack(cf, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; any other outcome raises."""
    cf.delete_stack(StackName=stack_id)
    cf.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack update adding an aws:-prefixed tag key to an AWS::AppConfig::Application's Tags
    rolls back to UPDATE_ROLLBACK_COMPLETE with an exact UPDATE_FAILED reason, the physical id
    and prior tags unchanged, and a later legal-tag update still reaches UPDATE_COMPLETE.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html
    """
    cf = ctx.client("cloudformation")
    appconfig = ctx.client("appconfig")

    stack_name = ctx.unique_name("sim2real-behav-cfnawstag-")
    app_name = ctx.unique_name("sim2real-behav-cfnawsapp-")
    tags_v1 = {"sim2real-stage": "beta"}
    tags_bad = {"sim2real-stage": "beta", "aws:reserved": "blocked"}
    tags_v2 = {"sim2real-stage": "prod"}

    stack_id = cf.create_stack(
        StackName=stack_name, TemplateBody=_template(app_name, tags_v1),
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))

    status = _wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    app_id = _physical_id(cf, stack_id, "App")
    partition = stack_id.split(":")[1]
    app_arn = f"arn:{partition}:appconfig:{ctx.region}:{ctx.account}:application/{app_id}"
    got_initial = _own_tags(appconfig, app_arn)
    assert got_initial == tags_v1, f"expected tags {tags_v1!r} after create, got {got_initial!r}"

    cf.update_stack(StackName=stack_id, TemplateBody=_template(app_name, tags_bad))
    status = _wait_stack(cf, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"expected the aws:-prefixed-tag update to roll back to UPDATE_ROLLBACK_COMPLETE, "
        f"got {status!r}"
    )

    reason = _resource_status_reason(cf, stack_id, "App", "UPDATE_FAILED")
    want_reason = "aws: prefixed tag key names are not allowed for external use."
    assert reason == want_reason, f"expected UPDATE_FAILED reason {want_reason!r}, got {reason!r}"

    app_id_after_rollback = _physical_id(cf, stack_id, "App")
    assert app_id_after_rollback == app_id, (
        f"the rolled-back update changed the application's physical id: "
        f"{app_id_after_rollback!r}, expected {app_id!r}"
    )
    got_after_rollback = _own_tags(appconfig, app_arn)
    assert got_after_rollback == tags_v1, (
        f"expected prior tags {tags_v1!r} kept after rollback, got {got_after_rollback!r}"
    )

    cf.update_stack(StackName=stack_id, TemplateBody=_template(app_name, tags_v2))
    status = _wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"expected a later update with a legal tag key to reach UPDATE_COMPLETE, got {status!r}"
    )

    app_id_final = _physical_id(cf, stack_id, "App")
    assert app_id_final == app_id, (
        f"the legal update changed the application's physical id: {app_id_final!r}, "
        f"expected {app_id!r}"
    )
    got_final = _own_tags(appconfig, app_arn)
    assert got_final == tags_v2, f"expected tags {tags_v2!r} after the legal update, got {got_final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
