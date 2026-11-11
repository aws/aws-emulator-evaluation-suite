"""update-task-protection-standalone-task-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-task-protection-standalone-task-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "plane:control")
def run(ctx) -> None:
    """UpdateTaskProtection on a standalone task (launched via RunTask, not managed by an
    ECS service) is rejected via a TASK_NOT_VALID failure entry -- only service-managed
    tasks can be protected."""
    ecs = ctx.client("ecs")
    cluster_arn = _create_cluster(ctx)
    net = _default_network(ctx)
    td = _register_sleep_task_def(ctx)

    task_arn, task = _run_task_and_wait_running(ecs, cluster_arn, td["taskDefinitionArn"], net)
    ctx.on_cleanup(lambda: _stop_task_ignore(ecs, cluster_arn, task_arn))
    assert task["lastStatus"] == "RUNNING"

    resp = ecs.update_task_protection(cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True)
    assert not resp.get("protectedTasks"), f"expected no protected tasks, got {resp.get('protectedTasks')}"
    failures = resp.get("failures", [])
    assert failures, "expected a failure entry for a standalone (non-service) task"
    assert failures[0]["reason"] == "TASK_NOT_VALID", f"expected TASK_NOT_VALID, got {failures[0]['reason']}"
    # Compare by the task's unique ID rather than requiring byte-identical ARNs: ECS may
    # echo back the failure's arn in a different ARN "shape" (e.g. with/without the
    # cluster-name path segment) than the one RunTask handed us, depending on the
    # account's ARN-format settings -- the identifying task ID must still match.
    assert _task_id(failures[0]["arn"]) == _task_id(task_arn), (
        f"failure arn {failures[0]['arn']!r} does not identify the requested task {task_arn!r}"
    )

    # Independent read at the destination: GetTaskProtection (a different operation than
    # the UpdateTaskProtection call under test) must also report the task as unprotected
    # and refuse it with the same failure reason, rather than relying solely on the
    # mutating call's own response.
    get_resp = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])
    assert not get_resp.get("protectedTasks"), (
        f"GetTaskProtection shows the standalone task as protected: {get_resp.get('protectedTasks')}"
    )
    get_failures = get_resp.get("failures", [])
    assert get_failures, "expected GetTaskProtection to also report a failure for the standalone task"
    assert get_failures[0]["reason"] == "TASK_NOT_VALID", (
        f"expected TASK_NOT_VALID from GetTaskProtection, got {get_failures[0]['reason']!r}"
    )
    assert _task_id(get_failures[0]["arn"]) == _task_id(task_arn), (
        f"GetTaskProtection failure arn {get_failures[0]['arn']!r} does not identify {task_arn!r}"
    )


def _task_id(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets in shared network")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group in shared network")
    return {"subnet_id": subnets[0]["SubnetId"], "sg_id": sgs[0]["GroupId"]}


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-cluster-")
    arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, arn))
    return arn


def _safe_delete_cluster(ecs, arn: str) -> None:
    _drain_and_delete_ecs_cluster(ecs, arn)


def _register_sleep_task_def(ctx, family_prefix="sim2real-behav-sleep"):
    ecs = ctx.client("ecs")
    family = ctx.unique_name(f"{family_prefix}-")
    td = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "900"],
                "essential": True,
            }
        ],
    )["taskDefinition"]

    def _cleanup():
        try:
            ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"])
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
        ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]])

    ctx.on_cleanup(_cleanup)
    return td


def _run_task_and_wait_running(ecs, cluster_arn, task_def_arn, net, **kwargs):
    resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType=kwargs.pop("launchType", "FARGATE"),
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [net["subnet_id"]],
                "securityGroups": [net["sg_id"]],
                "assignPublicIp": "ENABLED",
            }
        },
        **kwargs,
    )
    if resp.get("failures"):
        raise AssertionError(f"RunTask failures: {resp['failures']}")
    task_arn = resp["tasks"][0]["taskArn"]
    task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=240.0,
        interval_s=6.0,
    )
    return task_arn, task


def _stop_task_ignore(ecs, cluster_arn: str, task_arn: str) -> None:
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-behav-cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise



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
            except ClientError:
                pass
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
