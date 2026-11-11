"""change-set-disable-rollback-execute-leaves-create-failed-and-is-updatable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-disable-rollback-execute-leaves-create-failed-and-is-updatable"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs", "ssm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """ExecuteChangeSet(DisableRollback) parks a failed create in CREATE_FAILED with its good
    resources live, and an UPDATE change set then fixes only the failed one, re-creating nothing.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stack-failure-options.html
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-cfn-norb-")
    queue = ctx.unique_name("sim2real-cfn-norb-")
    keep = "/" + ctx.unique_name("sim2real-cfn-norb-keep-")
    fixed = f"{keep}-fixed"

    for name in (keep, fixed):
        ctx.on_cleanup(_teardown(lambda n=name: ssm.delete_parameter(Name=n), "ParameterNotFound"))
    ctx.on_cleanup(_teardown(lambda: _delete_queue(sqs, queue),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    created = cfn.create_change_set(
        StackName=stack, ChangeSetName="create", ChangeSetType="CREATE",
        TemplateBody=_template(queue, keep, broken=True),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_id = created["StackId"]
    _wait_change_set(cfn, stack_id, "create")
    cfn.execute_change_set(StackName=stack_id, ChangeSetName="create", DisableRollback=True)

    parked = _settle(cfn, stack_id)
    assert parked["StackStatus"] == "CREATE_FAILED", (
        f"a failed create executed with DisableRollback=True ended {parked['StackStatus']!r}, "
        f"expected CREATE_FAILED (reason {parked.get('StackStatusReason')!r})"
    )
    assert parked["DisableRollback"] is True, (
        f"DescribeStacks.DisableRollback is {parked.get('DisableRollback')!r}, expected True"
    )
    reason = parked.get("StackStatusReason")
    assert reason == "The following resource(s) failed to create: [Bad]. ", (
        f"StackStatusReason is {reason!r}"
    )
    bad = _last_event(cfn, stack_id, "Bad")
    assert (bad["ResourceStatus"], bad.get("ResourceStatusReason")) == (
        "CREATE_FAILED",
        f"{keep} already exists in stack {stack_id}",
    ), f"the colliding parameter's last event is {bad!r}"

    url = sqs.get_queue_url(QueueName=queue)["QueueUrl"]
    born = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["CreatedTimestamp"])[
        "Attributes"]["CreatedTimestamp"]
    kept = ssm.get_parameter(Name=keep)["Parameter"]
    assert (kept["Value"], kept["Version"]) == ("keep", 1), (
        f"the good parameter in the parked stack is {kept!r}, expected value 'keep' at version 1"
    )

    cfn.create_change_set(
        StackName=stack_id, ChangeSetName="fix", ChangeSetType="UPDATE",
        TemplateBody=_template(queue, keep, broken=False),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    described = _wait_change_set(cfn, stack_id, "fix")
    by_id = {c["ResourceChange"]["LogicalResourceId"]: c["ResourceChange"] for c in described["Changes"]}
    assert sorted(by_id) == ["Bad", "Keep", "Queue"], f"the fixing change set's entries: {by_id!r}"
    bad = by_id.pop("Bad")
    assert bad["Replacement"] == "True", (
        f"the fixing change set's entry for the failed resource is {bad!r}, expected a replacement"
    )
    # The stack's own Tags make CloudFormation list every other taggable resource too, each as a
    # tags-only, no-recreation entry; only Bad carries a property change.
    tags_only = {lid: (rc["Replacement"], rc["Scope"]) for lid, rc in by_id.items()}
    assert tags_only == {"Queue": ("False", ["Tags"]), "Keep": ("False", ["Tags"])}, (
        f"the fixing change set's entries besides the failed resource are {by_id!r}"
    )
    cfn.execute_change_set(StackName=stack_id, ChangeSetName="fix", DisableRollback=True)

    final = _settle(cfn, stack_id)
    assert final["StackStatus"] == "UPDATE_COMPLETE", (
        f"the fixing update ended {final['StackStatus']!r} ({final.get('StackStatusReason')!r})"
    )
    physical = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }
    assert physical == {"Queue": url, "Keep": keep, "Bad": fixed}, (
        f"physical ids after the fix are {physical!r}"
    )
    again = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["CreatedTimestamp"])[
        "Attributes"]["CreatedTimestamp"]
    assert again == born, f"the queue was re-created: CreatedTimestamp {born!r} -> {again!r}"
    kept = ssm.get_parameter(Name=keep)["Parameter"]
    assert (kept["Value"], kept["Version"]) == ("keep", 1), (
        f"the good parameter was rewritten by the fix: {kept!r}"
    )
    value = ssm.get_parameter(Name=fixed)["Parameter"]["Value"]
    assert value == "bad", f"the fixed parameter {fixed!r} holds {value!r}, expected 'bad'"


def _template(queue: str, keep: str, *, broken: bool) -> str:
    """A queue and a parameter that succeed, and a parameter whose name collides when broken."""
    bad_name = {"Ref": "Keep"} if broken else f"{keep}-fixed"
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue}},
            "Keep": {"Type": "AWS::SSM::Parameter",
                     "Properties": {"Name": keep, "Type": "String", "Value": "keep"}},
            "Bad": {"Type": "AWS::SSM::Parameter", "DependsOn": "Keep",
                    "Properties": {"Name": bad_name, "Type": "String", "Value": "bad"}},
        },
    })


def _wait_change_set(cfn, stack_id: str, name: str, *, timeout_s: float = 120.0) -> dict:
    """DescribeChangeSet once it is CREATE_COMPLETE; raises on FAILED or timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        described = cfn.describe_change_set(StackName=stack_id, ChangeSetName=name)
        if described["Status"] == "CREATE_COMPLETE":
            return described
        if described["Status"] == "FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"change set {name!r} is {described['Status']!r}: {described.get('StatusReason')!r}"
            )
        time.sleep(2.0)


def _settle(cfn, stack_id: str, *, timeout_s: float = 300.0) -> dict:
    """The stack once no operation is in progress on it; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3.0)


def _last_event(cfn, stack_id: str, logical_id: str) -> dict:
    """The newest stack event for one logical id."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for event in page["StackEvents"]:
            if event["LogicalResourceId"] == logical_id:
                return event
    raise AssertionError(f"no stack event names {logical_id!r}")


def _delete_queue(sqs, name: str) -> None:
    sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=name)["QueueUrl"])


def _delete_stack(cfn, name: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE; a stack never created is a no-op."""
    try:
        stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    stack_id = stack["StackId"]
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {name} teardown ended {status!r}")
        time.sleep(5.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
