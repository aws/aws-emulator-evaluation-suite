"""service-revisions-tracking."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-revisions-tracking"
GROUP = 'service-lifecycle'
SERVICES = ['ecs']

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = [
        s["SubnetId"]
        for s in ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        ).get("Subnets", [])
    ]
    if not subnets:
        raise AssertionError("no network subnets available in this account/region")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError("no default security group available in this account/region")
    return subnets, sgs[0]["GroupId"]


def _register_fargate_td(ctx, ecs):
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))
    return td


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each UpdateService that changes the task definition mints a distinct ServiceRevision whose
    DescribeServiceRevisions record keeps the task definition of that point in time.
    """
    ecs = ctx.client("ecs")
    # Creating an awsvpc/FARGATE service needs the ECS service-linked role.
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:  # already-exists (InvalidInput) is success
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise
    subnets, sg = _default_network(ctx)
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real-check", "value": CHECK}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    td1 = _register_fargate_td(ctx, ecs)
    td2 = _register_fargate_td(ctx, ecs)

    svc_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=name,
        serviceName=svc_name,
        taskDefinition=td1["taskDefinitionArn"],
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=name, service=svc_name, force=True))

    def _current_revision_arn():
        # DescribeServices is eventually consistent right after CreateService —
        # the service can be briefly absent, so tolerate an empty list instead
        # of indexing [0] and let the poll retry.
        svcs = ecs.describe_services(cluster=name, services=[svc_name])["services"]
        if not svcs:
            return None
        desc = svcs[0]
        return (
            desc.get("currentServiceRevisions", [{}])[0].get("arn")
            if desc.get("currentServiceRevisions")
            else None
        )

    rev1_arn = _poll_until(
        _current_revision_arn,
        lambda arn: arn is not None,
        timeout_s=60,
        interval_s=3,
        description="the initial CreateService produces a discoverable currentServiceRevision",
    )

    ecs.update_service(cluster=name, service=svc_name, taskDefinition=td2["taskDefinitionArn"])

    rev2_arn = _poll_until(
        _current_revision_arn,
        lambda arn: arn is not None and arn != rev1_arn,
        timeout_s=60,
        interval_s=3,
        description="UpdateService produces a NEW, distinct currentServiceRevision",
    )
    assert rev2_arn != rev1_arn, "expected a distinct service revision after UpdateService"

    revisions = ecs.describe_service_revisions(serviceRevisionArns=[rev1_arn, rev2_arn])[
        "serviceRevisions"
    ]
    assert not ecs.describe_service_revisions(serviceRevisionArns=[rev1_arn, rev2_arn]).get(
        "failures"
    ), "unexpected failures describing known service revisions"
    by_arn = {r["serviceRevisionArn"]: r for r in revisions}
    assert by_arn[rev1_arn]["taskDefinition"] == td1["taskDefinitionArn"], (
        f"expected the FIRST revision to still resolve to td1, got {by_arn[rev1_arn]['taskDefinition']}"
    )
    assert by_arn[rev2_arn]["taskDefinition"] == td2["taskDefinitionArn"], (
        f"expected the SECOND revision to resolve to td2, got {by_arn[rev2_arn]['taskDefinition']}"
    )



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                    "ServiceNotActiveException",
                ):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
