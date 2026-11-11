"""deploy-deadline-farm-queue-storageprofile-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-deadline-farm-queue-storageprofile-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "deadline"]

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



def _template(tag_value: str, *, children: bool = True) -> str:
    """The farm, plus its queue and storage profile unless ``children`` is False."""
    tags = [{"Key": "sim2real-check", "Value": tag_value}]
    resources = {"Farm": {"Type": "AWS::Deadline::Farm",
                          "Properties": {"DisplayName": tag_value, "Tags": tags}}}
    outputs = {
        "FarmId": {"Value": {"Fn::GetAtt": ["Farm", "FarmId"]}},
        "FarmArn": {"Value": {"Ref": "Farm"}},
    }
    if children:
        resources["Queue"] = {"Type": "AWS::Deadline::Queue", "Properties": {
            "FarmId": {"Fn::GetAtt": ["Farm", "FarmId"]}, "DisplayName": tag_value, "Tags": tags,
        }}
        resources["StorageProfile"] = {"Type": "AWS::Deadline::StorageProfile", "Properties": {
            "FarmId": {"Fn::GetAtt": ["Farm", "FarmId"]}, "DisplayName": tag_value,
            "OsFamily": "LINUX",
        }}
        outputs.update({
            "QueueId": {"Value": {"Fn::GetAtt": ["Queue", "QueueId"]}},
            "QueueArn": {"Value": {"Ref": "Queue"}},
            "StorageProfileId": {"Value": {"Fn::GetAtt": ["StorageProfile", "StorageProfileId"]}},
            "StorageProfileRef": {"Value": {"Ref": "StorageProfile"}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation farm, queue and storage profile read back through Deadline with the
    declared properties and tags; an update dropping the queue and storage profile deletes both
    while the farm stays, and the stack delete removes the farm.
    """
    cfn = ctx.client("cloudformation")
    dl = ctx.client("deadline")
    tag_value = ctx.unique_name("sim2real-dlfqs-")
    stack = ctx.unique_name("sim2real-dlfqs-stk-")

    stack_id = create_stack(ctx, cfn, stack, _template(tag_value))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, stack ended in {status!r}"

    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    farm_id, queue_id, sp_id = outputs["FarmId"], outputs["QueueId"], outputs["StorageProfileId"]

    # Ref and GetAtt FarmId against an independent read: ListFarms by the declared DisplayName.
    listed = [f["farmId"] for f in paginate(dl, "list_farms", "farms")
              if f["displayName"] == tag_value]
    assert listed == [farm_id], f"ListFarms lists {listed!r}, GetAtt FarmId is {farm_id!r}"
    farm = dl.get_farm(farmId=farm_id)
    assert farm["displayName"] == tag_value, (
        f"expected farm displayName {tag_value!r}, GetFarm reports {farm['displayName']!r}")
    farm_arn = (
        f"arn:{partition}:deadline:{ctx.region}:{ctx.account}:farm/{farm_id}")
    assert outputs["FarmArn"] == farm_arn, (
        f"Ref of the farm is {outputs['FarmArn']!r}, expected {farm_arn!r}")
    # The template tag, exactly; the stack's own sim2real tag is not asserted here.
    farm_tags = dl.list_tags_for_resource(resourceArn=farm_arn)["tags"]
    got = {k: v for k, v in farm_tags.items() if k != "sim2real" and not k.startswith("aws:")}
    assert got == {"sim2real-check": tag_value}, f"the farm's tags are {farm_tags!r}"

    listed = [q["queueId"] for q in paginate(dl, "list_queues", "queues", farmId=farm_id)
              if q["displayName"] == tag_value]
    assert listed == [queue_id], f"ListQueues lists {listed!r}, GetAtt QueueId is {queue_id!r}"
    queue = dl.get_queue(farmId=farm_id, queueId=queue_id)
    assert queue["displayName"] == tag_value, (
        f"expected queue displayName {tag_value!r}, GetQueue reports {queue['displayName']!r}")
    queue_arn = f"{farm_arn}/queue/{queue_id}"
    assert outputs["QueueArn"] == queue_arn, (
        f"Ref of the queue is {outputs['QueueArn']!r}, expected {queue_arn!r}")
    queue_tags = dl.list_tags_for_resource(resourceArn=queue_arn)["tags"]
    got = {k: v for k, v in queue_tags.items() if k != "sim2real" and not k.startswith("aws:")}
    assert got == {"sim2real-check": tag_value}, f"the queue's tags are {queue_tags!r}"

    sp = dl.get_storage_profile(farmId=farm_id, storageProfileId=sp_id)
    assert sp["displayName"] == tag_value, (
        f"expected storage profile displayName {tag_value!r}, GetStorageProfile reports "
        f"{sp['displayName']!r}")
    assert sp["osFamily"] == "LINUX", (
        f"expected storage profile OsFamily 'LINUX', GetStorageProfile reports {sp['osFamily']!r}")
    assert sp["storageProfileId"] == sp_id, (
        f"expected GetStorageProfile storageProfileId {sp_id!r}, got {sp['storageProfileId']!r}")
    assert outputs["StorageProfileRef"] == f"{farm['farmId']}|{sp['storageProfileId']}", (
        f"Ref of the storage profile is {outputs['StorageProfileRef']!r}, expected its "
        f"FarmId|StorageProfileId primary identifier")

    # Each child's own delete: an update that drops both deletes them while the farm still exists.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(tag_value, children=False))
    updated = wait_stack(cfn, stack_id)
    assert updated == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, stack ended in {updated!r}"
    assert dl.get_farm(farmId=farm_id)["displayName"] == tag_value, "the farm should survive the update"
    queue_gone = (
        "ResourceNotFoundException", f"Resource of type queue with id {queue_id} does not exist."
    )
    expect_error(lambda: dl.get_queue(farmId=farm_id, queueId=queue_id), *queue_gone)
    sp_gone = (
        "ResourceNotFoundException",
        f"Resource of type storage-profile with id {sp_id} does not exist.",
    )
    expect_error(lambda: dl.get_storage_profile(farmId=farm_id, storageProfileId=sp_id), *sp_gone)

    delete_stack(cfn, stack_id)
    farm_gone = (
        "ResourceNotFoundException", f"Resource of type farm with id {farm_id} does not exist."
    )
    expect_error(lambda: dl.get_farm(farmId=farm_id), *farm_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
