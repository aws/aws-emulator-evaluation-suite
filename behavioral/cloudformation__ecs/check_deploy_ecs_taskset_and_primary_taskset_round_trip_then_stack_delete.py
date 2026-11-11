"""deploy-ecs-taskset-and-primary-taskset-round-trip-then-stack-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ecs-taskset-and-primary-taskset-round-trip-then-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecs"]

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

CONTAINER_IMAGE = "public.ecr.aws/docker/library/busybox:latest"


def _template(cluster_name, service_name, subnet_id, sg_id, with_task_sets=True):
    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {"ClusterName": cluster_name}},
            "TaskDef": {"Type": "AWS::ECS::TaskDefinition", "Properties": {
                "RequiresCompatibilities": ["FARGATE"],
                "NetworkMode": "awsvpc",
                "Cpu": "256",
                "Memory": "512",
                "ContainerDefinitions": [{
                    "Name": "app", "Image": CONTAINER_IMAGE, "Essential": True,
                }],
            }},
            "Service": {"Type": "AWS::ECS::Service", "DependsOn": ["TaskDef"], "Properties": {
                "Cluster": {"Ref": "Cluster"},
                "ServiceName": service_name,
                "SchedulingStrategy": "REPLICA",
                "DeploymentController": {"Type": "EXTERNAL"},
            }},
            "TaskSet": {"Type": "AWS::ECS::TaskSet", "Properties": {
                "Cluster": {"Ref": "Cluster"},
                "Service": {"Fn::GetAtt": ["Service", "Name"]},
                "TaskDefinition": {"Ref": "TaskDef"},
                "LaunchType": "FARGATE",
                "NetworkConfiguration": {"AwsvpcConfiguration": {
                    "Subnets": [subnet_id],
                    "SecurityGroups": [sg_id],
                    "AssignPublicIp": "DISABLED",
                }},
                "Scale": {"Unit": "PERCENT", "Value": 0},
                "Tags": [{"Key": "sim2real-taskset", "Value": service_name}],
            }},
            "PrimaryTaskSet": {"Type": "AWS::ECS::PrimaryTaskSet", "Properties": {
                "Cluster": {"Ref": "Cluster"},
                "Service": {"Fn::GetAtt": ["Service", "Name"]},
                "TaskSetId": {"Fn::GetAtt": ["TaskSet", "Id"]},
            }},
        },
        "Outputs": {
            "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
            "TaskDefArn": {"Value": {"Fn::GetAtt": ["TaskDef", "TaskDefinitionArn"]}},
            "ServiceArn": {"Value": {"Fn::GetAtt": ["Service", "ServiceArn"]}},
            "ServiceNameOut": {"Value": {"Fn::GetAtt": ["Service", "Name"]}},
            "TaskSetId": {"Value": {"Fn::GetAtt": ["TaskSet", "Id"]}},
            "TaskSetRefOut": {"Value": {"Ref": "TaskSet"}},
            "PrimaryTaskSetRefOut": {"Value": {"Ref": "PrimaryTaskSet"}},
        },
    }
    if not with_task_sets:
        for key in ("TaskSet", "PrimaryTaskSet"):
            del doc["Resources"][key]
        for key in ("TaskSetId", "TaskSetRefOut", "PrimaryTaskSetRefOut"):
            del doc["Outputs"][key]
    return json.dumps(doc)


def _retire_task_definition(cfn, stack_id, ecs, task_definition_arn):
    """After the stack's delete, delete the revision it leaves INACTIVE; a second call is a no-op."""
    delete_stack(cfn, stack_id)
    status = ecs.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"][
        "status"]
    if status == "DELETE_IN_PROGRESS":
        return
    assert status == "INACTIVE", f"task definition {task_definition_arn} is {status!r}"
    failures = ecs.delete_task_definitions(taskDefinitions=[task_definition_arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {task_definition_arn} teardown failed: {failures}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ECS task set and its primary designation read back on an EXTERNAL service.

    An update dropping both removes the task set from the still-ACTIVE service; the stack delete
    leaves the service in ECS's INACTIVE tombstone and the task definition INACTIVE.
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    net = ctx.network()
    subnet_id = net.subnet_ids[0]
    sg_id = net.security_group_id

    stack = ctx.unique_name("sim2real-cfnecs-ts-")
    cluster_name = ctx.unique_name("sim2real-cfnecs-ts-cl-")
    service_name = ctx.unique_name("sim2real-cfnecs-ts-s-")

    stack_id = create_stack(
        ctx, cfn, stack, _template(cluster_name, service_name, subnet_id, sg_id)
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    cluster_arn = out["ClusterArn"]
    task_def_arn = out["TaskDefArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(cfn, stack_id, ecs, task_def_arn))
    service_arn = out["ServiceArn"]
    taskset_id = out["TaskSetId"]
    # TaskSet's primary identifier is composite (Cluster|Service|Id); PrimaryTaskSet's is
    # (Cluster|Service). Ref joins the identifying properties with "|", in template order.
    assert out["TaskSetRefOut"] == f"{cluster_name}|{service_name}|{taskset_id}", (
        f"Ref TaskSet {out['TaskSetRefOut']!r} != Cluster|Service|Id "
        f"{cluster_name}|{service_name}|{taskset_id}"
    )
    assert out["PrimaryTaskSetRefOut"] == f"{cluster_name}|{service_name}", (
        f"Ref PrimaryTaskSet {out['PrimaryTaskSetRefOut']!r} != Cluster|Service "
        f"{cluster_name}|{service_name}"
    )

    svc = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"][0]
    got_svc = (svc["serviceName"], svc["schedulingStrategy"], svc["deploymentController"],
               svc["status"])
    assert got_svc == (service_name, "REPLICA", {"type": "EXTERNAL"}, "ACTIVE"), (
        f"service reads {got_svc!r}"
    )

    # TaskSet's Id against an independent read: every task set DescribeServices lists for the
    # service the check owns. DescribeTaskSets refuses an empty taskSets list ("TaskSets cannot
    # be empty."), so it is called with the id that listing gave.
    listed_ids = [t["id"] for t in svc["taskSets"]]
    assert listed_ids == [taskset_id], (
        f"DescribeServices({service_arn!r}) lists task sets {listed_ids!r}, Id {taskset_id!r}"
    )
    task_sets = ecs.describe_task_sets(
        cluster=cluster_arn, service=service_arn, taskSets=listed_ids, include=["TAGS"]
    )["taskSets"]
    assert [t["id"] for t in task_sets] == [taskset_id], (
        f"DescribeTaskSets({listed_ids!r}) returned ids {[t['id'] for t in task_sets]!r}"
    )
    ts = task_sets[0]
    assert ts["clusterArn"] == cluster_arn, f"taskSet clusterArn {ts['clusterArn']!r}"
    # DescribeTaskSets reports the service's short-form ARN (no cluster name segment), while
    # DescribeServices/GetAtt report the long form; both name the same service.
    partition = cluster_arn.split(":")[1]
    short_service_arn = f"arn:{partition}:ecs:{ctx.region}:{ctx.account}:service/{service_name}"
    assert ts["serviceArn"] == short_service_arn, (
        f"taskSet serviceArn {ts['serviceArn']!r} != {short_service_arn!r}"
    )
    assert ts["taskDefinition"] == task_def_arn, f"taskSet taskDefinition {ts['taskDefinition']!r}"
    assert ts["launchType"] == "FARGATE", f"taskSet launchType {ts['launchType']!r}"
    net_cfg = ts["networkConfiguration"]["awsvpcConfiguration"]
    assert net_cfg["subnets"] == [subnet_id], f"taskSet subnets {net_cfg['subnets']!r}"
    assert net_cfg["securityGroups"] == [sg_id], f"taskSet securityGroups {net_cfg['securityGroups']!r}"
    assert ts["scale"] == {"value": 0.0, "unit": "PERCENT"}, f"taskSet scale {ts['scale']!r}"
    assert ts["status"] == "PRIMARY", (
        f"taskSet status {ts['status']!r}, expected 'PRIMARY' (the PrimaryTaskSet designation)"
    )
    ts_tags = {t["key"]: t["value"] for t in ts.get("tags", []) if not t["key"].startswith("aws:")}
    assert ts_tags == {"sim2real": stack, "sim2real-taskset": service_name}, f"taskSet tags {ts_tags!r}"

    # PrimaryTaskSet's own claim, through the service: its taskSets[].status == PRIMARY.
    svc = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"][0]
    primary_ids = [t["id"] for t in svc["taskSets"] if t["status"] == "PRIMARY"]
    assert primary_ids == [taskset_id], (
        f"service's PRIMARY taskSets are {primary_ids!r}, expected only {taskset_id!r}"
    )

    # The children alone: an update dropping both leaves the service ACTIVE with no task set.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(
        cluster_name, service_name, subnet_id, sg_id, with_task_sets=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"task-set-removing update ended {status!r}"
    kept = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"]
    assert [(s["status"], s["taskSets"]) for s in kept] == [("ACTIVE", [])], (
        f"service after the update reads {kept!r}"
    )

    delete_stack(cfn, stack_id)
    after = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"]
    assert [s["status"] for s in after] == ["INACTIVE"], (
        f"DescribeServices({service_arn!r}) after the stack delete returned {after!r}"
    )
    retired = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]["status"]
    assert retired == "INACTIVE", f"the stack's task definition is {retired!r} after its delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
