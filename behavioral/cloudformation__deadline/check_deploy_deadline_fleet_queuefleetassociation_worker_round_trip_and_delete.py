"""deploy-deadline-fleet-queuefleetassociation-worker-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-deadline-fleet-queuefleetassociation-worker-round-trip-and-delete"
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

_HOST_NAME = "sim2real-deadline-host"


def _template(tag_value: str, account: str, *, children: bool = True) -> str:
    """Farm, queue, role and fleet, plus the queue-fleet association and worker unless
    ``children`` is False."""
    tags = [{"Key": "sim2real-check", "Value": tag_value}]
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Farm": {"Type": "AWS::Deadline::Farm",
                     "Properties": {"DisplayName": tag_value, "Tags": tags}},
            "Queue": {"Type": "AWS::Deadline::Queue", "Properties": {
                "FarmId": {"Fn::GetAtt": ["Farm", "FarmId"]}, "DisplayName": tag_value,
                "JobRunAsUser": {"RunAs": "WORKER_AGENT_USER"}, "Tags": tags,
            }},
            "FleetRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "credentials.deadline.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": account},
                            "ArnEquals": {"aws:SourceArn": {"Fn::GetAtt": ["Farm", "Arn"]}},
                        },
                    }],
                },
                "ManagedPolicyArns": [
                    {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AWSDeadlineCloud-FleetWorker"}
                ],
                "Tags": tags,
            }},
            "Fleet": {"Type": "AWS::Deadline::Fleet", "Properties": {
                "FarmId": {"Fn::GetAtt": ["Farm", "FarmId"]},
                "DisplayName": tag_value,
                "RoleArn": {"Fn::GetAtt": ["FleetRole", "Arn"]},
                "MaxWorkerCount": 1,
                "MinWorkerCount": 0,
                "Configuration": {"CustomerManaged": {
                    "Mode": "NO_SCALING",
                    "WorkerCapabilities": {
                        "VCpuCount": {"Min": 1}, "MemoryMiB": {"Min": 512},
                        "OsFamily": "LINUX", "CpuArchitectureType": "x86_64",
                    },
                }},
                "Tags": tags,
            }},
            "QFA": {"Type": "AWS::Deadline::QueueFleetAssociation", "Properties": {
                "FarmId": {"Fn::GetAtt": ["Farm", "FarmId"]},
                "QueueId": {"Fn::GetAtt": ["Queue", "QueueId"]},
                "FleetId": {"Fn::GetAtt": ["Fleet", "FleetId"]},
            }},
            "Worker": {"Type": "AWS::Deadline::Worker", "Properties": {
                "FarmId": {"Fn::GetAtt": ["Farm", "FarmId"]},
                "FleetId": {"Fn::GetAtt": ["Fleet", "FleetId"]},
                "HostProperties": {"HostName": _HOST_NAME},
                "Tags": tags,
            }},
        },
        "Outputs": {
            "FarmId": {"Value": {"Fn::GetAtt": ["Farm", "FarmId"]}},
            "QueueId": {"Value": {"Fn::GetAtt": ["Queue", "QueueId"]}},
            "QueueArn": {"Value": {"Ref": "Queue"}},
            "FleetId": {"Value": {"Fn::GetAtt": ["Fleet", "FleetId"]}},
            "FleetArn": {"Value": {"Ref": "Fleet"}},
            "FleetArnAttr": {"Value": {"Fn::GetAtt": ["Fleet", "Arn"]}},
            "FleetStatus": {"Value": {"Fn::GetAtt": ["Fleet", "Status"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["FleetRole", "Arn"]}},
            "WorkerId": {"Value": {"Fn::GetAtt": ["Worker", "WorkerId"]}},
            "WorkerRef": {"Value": {"Ref": "Worker"}},
            "WorkerArnAttr": {"Value": {"Fn::GetAtt": ["Worker", "Arn"]}},
            "WorkerStatus": {"Value": {"Fn::GetAtt": ["Worker", "Status"]}},
            "QfaRef": {"Value": {"Ref": "QFA"}},
        },
    }
    if not children:
        for logical in ("QFA", "Worker"):
            del template["Resources"][logical]
        for key in ("WorkerId", "WorkerRef", "WorkerArnAttr", "WorkerStatus", "QfaRef"):
            del template["Outputs"][key]
    return json.dumps(template)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation customer-managed fleet, queue-fleet association and worker read back
    through Deadline with the declared properties and tags; an update dropping the association
    and worker deletes both while the fleet stays, and the stack delete removes the rest.
    """
    cfn = ctx.client("cloudformation")
    dl = ctx.client("deadline")
    tag_value = ctx.unique_name("sim2real-dlfqw-")
    stack = ctx.unique_name("sim2real-dlfqw-stk-")

    stack_id = create_stack(ctx, cfn, stack, _template(tag_value, ctx.account),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, stack ended in {status!r}"

    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    farm_id, queue_id, fleet_id, worker_id = (
        outputs["FarmId"], outputs["QueueId"], outputs["FleetId"], outputs["WorkerId"])

    # Each Ref and GetAtt id against an independent read: the farm's list, by declared name.
    listed = [f["fleetId"] for f in paginate(dl, "list_fleets", "fleets", farmId=farm_id)
              if f["displayName"] == tag_value]
    assert listed == [fleet_id], f"ListFleets lists {listed!r}, GetAtt FleetId is {fleet_id!r}"
    listed = [q["queueId"] for q in paginate(dl, "list_queues", "queues", farmId=farm_id)
              if q["displayName"] == tag_value]
    assert listed == [queue_id], f"ListQueues lists {listed!r}, GetAtt QueueId is {queue_id!r}"
    listed = [w["workerId"]
              for w in paginate(dl, "list_workers", "workers", farmId=farm_id, fleetId=fleet_id)
              if w["hostProperties"].get("hostName") == _HOST_NAME]
    assert listed == [worker_id], f"ListWorkers lists {listed!r}, GetAtt WorkerId is {worker_id!r}"
    fleet = dl.get_fleet(farmId=farm_id, fleetId=fleet_id)
    assert fleet["status"] == "ACTIVE", (
        f"expected the fleet to be ACTIVE once CREATE_COMPLETE, GetFleet reports "
        f"{fleet['status']!r}")
    assert fleet["maxWorkerCount"] == 1, (
        f"expected MaxWorkerCount 1, GetFleet reports {fleet['maxWorkerCount']!r}")
    got_fleet = (fleet["displayName"], fleet["roleArn"], fleet["minWorkerCount"])
    assert got_fleet == (tag_value, outputs["RoleArn"], 0), (
        f"expected (displayName, roleArn, minWorkerCount) {(tag_value, outputs['RoleArn'], 0)!r}, "
        f"GetFleet reports {got_fleet!r}")
    managed = fleet["configuration"]["customerManaged"]
    caps = managed["workerCapabilities"]
    got_caps = (managed["mode"], caps["vCpuCount"], caps["memoryMiB"], caps["osFamily"],
                caps["cpuArchitectureType"])
    want_caps = ("NO_SCALING", {"min": 1}, {"min": 512}, "LINUX", "x86_64")
    assert got_caps == want_caps, (
        f"expected customerManaged (mode, vCpuCount, memoryMiB, osFamily, cpuArchitectureType) "
        f"{want_caps!r}, GetFleet reports {got_caps!r}")
    fleet_arn = f"arn:{partition}:deadline:{ctx.region}:{ctx.account}:farm/{farm_id}/fleet/{fleet_id}"
    assert outputs["FleetArn"] == outputs["FleetArnAttr"] == fleet_arn, (
        f"Ref and GetAtt Arn of the fleet are {outputs['FleetArn']!r} and "
        f"{outputs['FleetArnAttr']!r}, expected {fleet_arn!r}")
    assert outputs["FleetStatus"] == fleet["status"], (
        f"GetAtt Status of the fleet is {outputs['FleetStatus']!r}, GetFleet reports {fleet['status']!r}")

    queue = dl.get_queue(farmId=farm_id, queueId=queue_id)
    got_queue = (queue["displayName"], queue["jobRunAsUser"])
    assert got_queue == (tag_value, {"runAs": "WORKER_AGENT_USER"}), (
        f"expected queue (displayName, jobRunAsUser) {(tag_value, {'runAs': 'WORKER_AGENT_USER'})!r}, "
        f"GetQueue reports {got_queue!r}")
    queue_arn = f"arn:{partition}:deadline:{ctx.region}:{ctx.account}:farm/{farm_id}/queue/{queue_id}"
    assert outputs["QueueArn"] == queue_arn, (
        f"Ref of the queue is {outputs['QueueArn']!r}, expected {queue_arn!r}")

    qfa = dl.get_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id)
    assert qfa["status"] == "ACTIVE", (
        f"expected the queue-fleet association to be ACTIVE, GetQueueFleetAssociation reports "
        f"{qfa['status']!r}")
    assert (qfa["queueId"], qfa["fleetId"]) == (queue_id, fleet_id), (
        f"expected the association of queue {queue_id!r} and fleet {fleet_id!r}, got "
        f"{(qfa['queueId'], qfa['fleetId'])!r}")
    assert outputs["QfaRef"] == f"{farm_id}|{qfa['fleetId']}|{qfa['queueId']}", (
        f"Ref of the queue-fleet association is {outputs['QfaRef']!r}, expected its "
        f"FarmId|FleetId|QueueId primary identifier")

    worker = dl.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id)
    assert worker["status"] == "CREATED", (
        f"expected an un-started worker to be CREATED, GetWorker reports {worker['status']!r}")
    assert outputs["WorkerStatus"] == worker["status"], (
        f"GetAtt Status of the worker is {outputs['WorkerStatus']!r}, GetWorker reports "
        f"{worker['status']!r}")
    assert worker["hostProperties"]["hostName"] == _HOST_NAME, (
        f"expected HostProperties.HostName {_HOST_NAME!r}, GetWorker reports "
        f"{worker['hostProperties'].get('hostName')!r}")
    worker_arn = f"{fleet_arn}/worker/{worker['workerId']}"
    assert outputs["WorkerRef"] == outputs["WorkerArnAttr"] == worker_arn, (
        f"Ref and GetAtt Arn of the worker are {outputs['WorkerRef']!r} and "
        f"{outputs['WorkerArnAttr']!r}, expected {worker_arn!r}")

    for label, arn in (("farm", f"arn:{partition}:deadline:{ctx.region}:{ctx.account}:farm/{farm_id}"),
                       ("queue", queue_arn), ("fleet", fleet_arn), ("worker", worker_arn)):
        # The template tag, exactly; the stack's own sim2real tag is not asserted here.
        got_tags = dl.list_tags_for_resource(resourceArn=arn)["tags"]
        got = {k: v for k, v in got_tags.items() if k != "sim2real" and not k.startswith("aws:")}
        assert got == {"sim2real-check": tag_value}, f"the {label}'s tags are {got_tags!r}"

    # Each child's own delete: an update that drops the association and the worker deletes both
    # while the farm, queue and fleet still exist.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(tag_value, ctx.account, children=False),
                     Capabilities=["CAPABILITY_IAM"])
    updated = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert updated == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, stack ended in {updated!r}"
    assert dl.get_fleet(farmId=farm_id, fleetId=fleet_id)["fleetId"] == fleet_id, (
        "the fleet should survive the update")
    qfa_gone = (
        "ResourceNotFoundException",
        f"Resource of type queue-fleet-association with id {farm_id}, {queue_id} and {fleet_id} "
        f"does not exist.",
    )
    expect_error(lambda: dl.get_queue_fleet_association(
        farmId=farm_id, queueId=queue_id, fleetId=fleet_id), *qfa_gone)
    worker_gone = (
        "ResourceNotFoundException", f"Resource of type worker with id {worker_id} does not exist."
    )
    expect_error(lambda: dl.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id),
                 *worker_gone)

    delete_stack(cfn, stack_id)
    farm_gone = (
        "ResourceNotFoundException", f"Resource of type farm with id {farm_id} does not exist."
    )
    expect_error(lambda: dl.get_farm(farmId=farm_id), *farm_gone)
    expect_error(lambda: dl.get_fleet(farmId=farm_id, fleetId=fleet_id), *farm_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
