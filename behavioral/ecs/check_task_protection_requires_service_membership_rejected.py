"""task-protection-requires-service-membership-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "task-protection-requires-service-membership-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "plane:control")
def run(ctx) -> None:
    """UpdateTaskProtection/GetTaskProtection protect a service-managed task, but reject a
    standalone (non-service) task with a TASK_NOT_VALID failure entry instead of silently
    protecting it."""
    ecs = ctx.client("ecs")
    net = _default_network(ctx)

    cluster_arn = _create_cluster(ctx, ecs)
    task_def_arn = _register_sleep_task_def(ctx, ecs)

    # ---- positive control: the same call succeeds on a service-managed task ----
    service_task_arn = _create_service_and_wait_running(ctx, ecs, cluster_arn, task_def_arn, net)

    enabled = ecs.update_task_protection(
        cluster=cluster_arn, tasks=[service_task_arn], protectionEnabled=True
    )
    assert not enabled.get("failures"), (
        f"UpdateTaskProtection on a service-managed task unexpectedly failed: {enabled['failures']}"
    )
    assert enabled["protectedTasks"] and enabled["protectedTasks"][0]["protectionEnabled"] is True, (
        f"expected the service-managed task to become protected, got {enabled}"
    )
    control_get = ecs.get_task_protection(cluster=cluster_arn, tasks=[service_task_arn])
    assert control_get["protectedTasks"][0]["protectionEnabled"] is True, (
        f"GetTaskProtection does not reflect the enabled protection on the service-managed task: "
        f"{control_get}"
    )

    # ---- break exactly one thing: the identical call against a standalone task ----
    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": [net["subnet_id"]], "assignPublicIp": "ENABLED"}
        },
    )
    if run_resp.get("failures"):
        raise AssertionError(
            f"unable to launch a standalone Fargate task in this account: {run_resp['failures']}"
        )
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_task_quiet(ecs, cluster_arn, task_arn))

    resp = ecs.update_task_protection(cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True)
    assert not resp["protectedTasks"], f"standalone task unexpectedly became protected: {resp}"
    assert resp["failures"], "expected a failure entry for a standalone (non-service) task"
    failure = resp["failures"][0]
    assert _task_id(failure["arn"]) == _task_id(task_arn), (
        f"expected failure entry to identify the same task as {task_arn!r}, got {failure['arn']!r}"
    )
    assert failure["reason"] == "TASK_NOT_VALID", f"expected TASK_NOT_VALID, got {failure['reason']!r}"

    get_resp = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])
    assert not get_resp["protectedTasks"], f"standalone task shows as protected: {get_resp}"
    assert get_resp["failures"], "expected a failure entry from GetTaskProtection too"
    assert get_resp["failures"][0]["reason"] == "TASK_NOT_VALID", (
        f"expected TASK_NOT_VALID from GetTaskProtection, got {get_resp['failures'][0]['reason']!r}"
    )


def _task_id(task_arn):
    # ECS task ARNs may be returned in either the long form
    # (arn:aws:ecs:region:account:task/cluster-name/task-id) or the legacy short form
    # (arn:aws:ecs:region:account:task/task-id) depending on the API and the account's
    # ARN-format opt-in settings. The trailing path segment (the task id/GUID) uniquely
    # identifies the task regardless of which form is used, so compare on that.
    return task_arn.rsplit("/", 1)[-1]


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("unreachable: account has no shared network VPC to place a Fargate task in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:
        raise AssertionError("unreachable: shared network has no network subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("unreachable: shared network has no default security group")
    return {"subnet_id": subnets[0]["SubnetId"], "sg_id": sgs[0]["GroupId"]}


def _create_cluster(ctx, ecs):
    name = ctx.unique_name("sim2real-ecs-tpn-")
    arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_retry(ecs, arn))
    return arn


def _register_sleep_task_def(ctx, ecs):
    family = ctx.unique_name("sim2real-ecs-td-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "c",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "600"],
            }
        ],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _create_service_and_wait_running(ctx, ecs, cluster_arn, task_def_arn, net):
    service_name = ctx.unique_name("sim2real-ecs-tpn-svc-")
    service_arn = ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [net["subnet_id"]],
                "securityGroups": [net["sg_id"]],
                "assignPublicIp": "ENABLED",
            }
        },
    )["service"]["serviceArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_service(ecs, cluster_arn, service_arn))

    def _service_task_arn():
        arns = ecs.list_tasks(cluster=cluster_arn, serviceName=service_arn)["taskArns"]
        return arns[0] if arns else None

    task_arn = _poll_until(_service_task_arn, lambda a: a is not None, timeout_s=120.0, interval_s=3.0)
    _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]["lastStatus"],
        lambda status: status == "RUNNING",
        timeout_s=240.0,
        interval_s=5.0,
    )
    return task_arn


def _drain_and_delete_service(ecs, cluster_arn, service_arn) -> None:
    _safe(lambda: ecs.update_service(cluster=cluster_arn, service=service_arn, desiredCount=0))
    ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "NamespaceNotFoundException",
            "ServiceNotActiveException",
            "ServiceNotFoundException",
        ):
            raise


def _stop_task_quiet(ecs, cluster_arn, task_arn) -> None:
    _safe(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-cleanup"))


def _delete_cluster_retry(ecs, cluster_arn) -> None:
    _drain_and_delete_ecs_cluster(ecs, cluster_arn)



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
