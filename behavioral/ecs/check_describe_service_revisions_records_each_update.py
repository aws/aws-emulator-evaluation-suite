"""describe-service-revisions-records-each-update."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-service-revisions-records-each-update"
GROUP = "ordering"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each UpdateService that changes the task definition yields a distinct revision;
    DescribeServiceRevisions returns one entry per revision with matching taskDefinition
    and createdAt, in chronological order."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_networking(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-svcrev-cl-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecs-svcrev-td-")

    def _register(sleep_seconds):
        ecs.register_task_definition(
            family=family,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            cpu="256",
            memory="512",
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "public.ecr.aws/docker/library/busybox:1.36",
                    "essential": True,
                    "command": ["sleep", sleep_seconds],
                }
            ],
            tags=[{"key": "sim2real", "value": "true"}],
        )

    _register("100")
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, f"{family}:1"))

    service_name = ctx.unique_name("sim2real-ecs-svcrev-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=f"{family}:1",
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet_id],
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))

    def _list_deployments():
        return ecs.list_service_deployments(cluster=cluster_name, service=service_name).get(
            "serviceDeployments", []
        )

    # ECS can supersede a still-running deployment instead of recording a separate revision,
    # so each update waits for its deployment to reach a terminal status first.
    _TERMINAL_STATUSES = {"SUCCESSFUL", "STOPPED", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED"}

    def _terminal_snapshot(min_count):
        def _probe():
            ds = _list_deployments()
            if len(ds) < min_count:
                return None
            ds_sorted = sorted(ds, key=lambda d: d["createdAt"])
            latest = ds_sorted[-1]
            if latest.get("status") in _TERMINAL_STATUSES:
                return ds_sorted
            return None

        return _poll_until(_probe, lambda r: r is not None, timeout_s=180.0, interval_s=5.0)

    # wait for the deployment created by create_service itself to settle
    _terminal_snapshot(1)

    _register("200")
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, f"{family}:2"))
    ecs.update_service(cluster=cluster_name, service=service_name, taskDefinition=f"{family}:2")
    _terminal_snapshot(2)

    _register("300")
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, f"{family}:3"))
    ecs.update_service(cluster=cluster_name, service=service_name, taskDefinition=f"{family}:3")
    deployments = _terminal_snapshot(3)
    deployments_sorted = deployments[:3]
    revision_arns = [d["targetServiceRevisionArn"] for d in deployments_sorted]
    assert len(set(revision_arns)) == 3, f"expected 3 distinct service revision ARNs, got {revision_arns}"

    desc = ecs.describe_service_revisions(serviceRevisionArns=revision_arns)
    assert not desc.get("failures"), f"unexpected failures: {desc.get('failures')}"
    revisions = desc["serviceRevisions"]
    assert len(revisions) == 3, f"expected 3 service revisions described, got {len(revisions)}"

    by_arn = {r["serviceRevisionArn"]: r for r in revisions}
    ordered = [by_arn[a] for a in revision_arns]

    expected_taskdefs = [f"{family}:1", f"{family}:2", f"{family}:3"]
    got_taskdefs = [r["taskDefinition"].rsplit("/", 1)[-1] for r in ordered]
    assert got_taskdefs == expected_taskdefs, (
        f"expected chronological taskDefinition progression {expected_taskdefs}, got {got_taskdefs}"
    )

    created_ats = [r["createdAt"] for r in ordered]
    assert created_ats == sorted(created_ats), "expected service revisions in chronological order"
    assert len(set(created_ats)) == 3, "expected a distinct createdAt per service revision"




def _default_networking(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for Fargate networking")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _poll_until(probe, predicate, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services or tasks remain, and a running task's ENI blocks
    deleting the network.
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
                if exc.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
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


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
