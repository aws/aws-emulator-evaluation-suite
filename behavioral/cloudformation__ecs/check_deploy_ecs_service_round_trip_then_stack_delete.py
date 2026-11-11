"""deploy-ecs-service-round-trip-then-stack-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ecs-service-round-trip-then-stack-delete"
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


def _template(cluster_name, service_name, subnet_id, sg_id, service_tag_value):
    return json.dumps({
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
                "TaskDefinition": {"Ref": "TaskDef"},
                "DesiredCount": 0,
                "LaunchType": "FARGATE",
                "NetworkConfiguration": {"AwsvpcConfiguration": {
                    "Subnets": [subnet_id],
                    "SecurityGroups": [sg_id],
                    "AssignPublicIp": "DISABLED",
                }},
                "Tags": [{"Key": "sim2real-service", "Value": service_tag_value}],
            }},
        },
        "Outputs": {
            "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
            "TaskDefArn": {"Value": {"Fn::GetAtt": ["TaskDef", "TaskDefinitionArn"]}},
            "ServiceArn": {"Value": {"Fn::GetAtt": ["Service", "ServiceArn"]}},
            "ServiceNameOut": {"Value": {"Fn::GetAtt": ["Service", "Name"]}},
            "ServiceRefOut": {"Value": {"Ref": "Service"}},
        },
    })


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
    """A CloudFormation ECS service, its cluster and task definition read back through ECS.

    The stack delete leaves the service in ECS's INACTIVE tombstone and deregisters the revision.
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    net = ctx.network()
    subnet_id = net.subnet_ids[0]
    sg_id = net.security_group_id

    stack = ctx.unique_name("sim2real-cfnecs-svc-")
    cluster_name = ctx.unique_name("sim2real-cfnecs-svc-cl-")
    service_name = ctx.unique_name("sim2real-cfnecs-svc-s-")

    stack_id = create_stack(
        ctx, cfn, stack, _template(cluster_name, service_name, subnet_id, sg_id, service_name)
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
    assert out["ServiceRefOut"] == service_arn, (
        f"Ref Service {out['ServiceRefOut']!r} != its own ServiceArn GetAtt {service_arn!r}"
    )
    assert out["ServiceNameOut"] == service_name, (
        f"GetAtt Service.Name {out['ServiceNameOut']!r} != template ServiceName {service_name!r}"
    )

    # ServiceArn (the primary identifier) against an independent read: ListServices on the
    # cluster the check owns, paginated, never a read keyed by the Ref/GetAtt alone.
    listed = paginate(ecs, "list_services", "serviceArns", cluster=cluster_arn, maxResults=100)
    assert listed == [service_arn], f"ListServices(cluster={cluster_arn!r}) returned {listed!r}"

    described = ecs.describe_services(
        cluster=cluster_arn, services=[service_arn], include=["TAGS"]
    )["services"]
    assert len(described) == 1, f"DescribeServices({service_arn!r}) returned {described!r}"
    svc = described[0]
    assert svc["serviceArn"] == service_arn, f"serviceArn {svc['serviceArn']!r} != {service_arn!r}"
    assert svc["serviceName"] == service_name, f"serviceName {svc['serviceName']!r} != {service_name!r}"
    assert svc["clusterArn"] == cluster_arn, f"clusterArn {svc['clusterArn']!r} != {cluster_arn!r}"
    assert svc["status"] == "ACTIVE", f"freshly-created service status {svc['status']!r}"
    assert svc["desiredCount"] == 0, f"desiredCount {svc['desiredCount']!r}, expected 0"
    assert svc["launchType"] == "FARGATE", f"launchType {svc['launchType']!r}"
    assert svc["taskDefinition"] == task_def_arn, (
        f"taskDefinition {svc['taskDefinition']!r} != the stack's own {task_def_arn!r}"
    )
    net_cfg = svc["networkConfiguration"]["awsvpcConfiguration"]
    assert net_cfg["subnets"] == [subnet_id], f"subnets {net_cfg['subnets']!r} != {[subnet_id]!r}"
    assert net_cfg["securityGroups"] == [sg_id], f"securityGroups {net_cfg['securityGroups']!r}"
    assert net_cfg["assignPublicIp"] == "DISABLED", f"assignPublicIp {net_cfg['assignPublicIp']!r}"

    clusters = ecs.describe_clusters(clusters=[svc["clusterArn"]])["clusters"]
    assert [(c["clusterName"], c["status"]) for c in clusters] == [(cluster_name, "ACTIVE")], (
        f"cluster {clusters!r}"
    )
    td = ecs.describe_task_definition(taskDefinition=svc["taskDefinition"])["taskDefinition"]
    got_td = (td["requiresCompatibilities"], td["networkMode"], td["cpu"], td["memory"],
              [(c["name"], c["image"], c["essential"]) for c in td["containerDefinitions"]])
    assert got_td == (["FARGATE"], "awsvpc", "256", "512", [("app", CONTAINER_IMAGE, True)]), (
        f"task definition {got_td!r}"
    )

    service_tags = {t["key"]: t["value"] for t in svc.get("tags", [])
                    if not t["key"].startswith("aws:")}
    assert service_tags == {"sim2real": stack, "sim2real-service": service_name}, (
        f"service tags {service_tags!r}"
    )

    delete_stack(cfn, stack_id)

    # Gone, through ECS's own documented tombstone: DescribeServices still answers (never a
    # ServiceNotFoundException for a service that existed) but reports status INACTIVE, and
    # ListServices on the same cluster no longer lists it.
    after = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"]
    assert len(after) == 1, f"DescribeServices({service_arn!r}) after delete returned {after!r}"
    assert after[0]["status"] == "INACTIVE", (
        f"deleted service status {after[0]['status']!r}, expected the documented 'INACTIVE'"
    )
    listed_after = paginate(ecs, "list_services", "serviceArns", cluster=cluster_arn, maxResults=100)
    assert service_arn not in listed_after, f"ListServices still lists deleted {service_arn!r}"
    retired = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]["status"]
    assert retired == "INACTIVE", f"the stack's task definition is {retired!r} after its delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
