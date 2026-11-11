"""concurrent-update-task-protection-conflicting-expiry."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-update-task-protection-conflicting-expiry"
GROUP = "concurrency"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateTaskProtection calls with different expiry values on the
    same task resolve to a single, deterministic last-writer-wins outcome -- never a
    blended/corrupted expiration, and the read-back is stable afterwards."""
    ecs = ctx.client("ecs")
    net = _default_networking(ctx)
    cluster = _create_cluster(ctx)
    task_def_arn = _register_sleep_task_def(ctx)

    service_name = ctx.unique_name("sim2real-ecs-conc-svc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": net},
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: _stop_service_and_wait(ctx, cluster, service_name))

    task_arn = _wait_for_running_task(ctx, cluster, service_name)

    def _call(expires_in_minutes: int):
        return ecs.update_task_protection(
            cluster=cluster,
            tasks=[task_arn],
            protectionEnabled=True,
            expiresInMinutes=expires_in_minutes,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_call, 5)
        fut_b = pool.submit(_call, 50)
        resp_a = fut_a.result()
        resp_b = fut_b.result()

    assert resp_a["failures"] == [], resp_a["failures"]
    assert resp_b["failures"] == [], resp_b["failures"]
    expiry_a = resp_a["protectedTasks"][0]["expirationDate"]
    expiry_b = resp_b["protectedTasks"][0]["expirationDate"]
    # The two racers requested wildly different durations (5min vs 50min), so their
    # own resulting expirations must differ enough to be distinguishable.
    delta_ab = abs((expiry_b - expiry_a).total_seconds())
    assert delta_ab > 600, (
        f"expected the 5min and 50min racers' own expirationDate to differ by >600s, "
        f"got delta={delta_ab:.1f}s (a={expiry_a}, b={expiry_b})"
    )

    got = ecs.get_task_protection(cluster=cluster, tasks=[task_arn])
    assert got["failures"] == [], got["failures"]
    final = got["protectedTasks"][0]
    assert final["protectionEnabled"] is True, (
        f"expected protectionEnabled True after the concurrent UpdateTaskProtection "
        f"calls, got {final['protectionEnabled']!r}"
    )
    final_expiry = final["expirationDate"]

    matches_a = abs((final_expiry - expiry_a).total_seconds()) < 3
    matches_b = abs((final_expiry - expiry_b).total_seconds()) < 3
    assert matches_a or matches_b, (
        f"final expiration {final_expiry} matches neither racer's own response "
        f"(a={expiry_a}, b={expiry_b}) -- indicates blended/corrupted state"
    )
    assert not (matches_a and matches_b), "racer expirations were not distinguishable; test setup invalid"

    # A repeated read must be stable, not flapping between the two candidate values.
    got2 = ecs.get_task_protection(cluster=cluster, tasks=[task_arn])
    final_expiry2 = got2["protectedTasks"][0]["expirationDate"]
    assert final_expiry2 == final_expiry, "GetTaskProtection is not stable across repeated reads"


def _default_networking(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch a Fargate task")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch a Fargate task in")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {
        "subnets": [subnets[0]["SubnetId"]],
        "securityGroups": [sgs[0]["GroupId"]] if sgs else [],
        "assignPublicIp": "ENABLED",
    }


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-conc-cluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _try_delete_cluster(ctx, name))
    return name


def _try_delete_cluster(ctx, cluster: str) -> None:
    ecs = ctx.client("ecs")
    _drain_and_delete_ecs_cluster(ecs, cluster)


def _register_sleep_task_def(ctx) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-conc-taskdef-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "3600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _wait_for_running_task(ctx, cluster: str, service_name: str, timeout_s: float = 240.0) -> str:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        arns = ecs.list_tasks(cluster=cluster, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
        if arns:
            tasks = ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]
            running = [t for t in tasks if t["lastStatus"] == "RUNNING"]
            if running:
                return running[0]["taskArn"]
        time.sleep(5)
    raise AssertionError(f"no task in service {service_name} reached RUNNING within {timeout_s}s")


def _stop_service_and_wait(ctx, cluster: str, service_name: str, timeout_s: float = 180.0) -> None:
    ecs = ctx.client("ecs")
    try:
        task_arns = ecs.list_tasks(cluster=cluster, serviceName=service_name)["taskArns"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ClusterNotFoundException", "ServiceNotFoundException"):
            raise
        return
    if task_arns:
        # A scale-in protected task survives the service's scale-down; drop the protection first.
        ecs.update_task_protection(cluster=cluster, tasks=task_arns, protectionEnabled=False)
    try:
        ecs.delete_service(cluster=cluster, service=service_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise
    if not task_arns:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            tasks = ecs.describe_tasks(cluster=cluster, tasks=task_arns)["tasks"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return
        if all(t["lastStatus"] == "STOPPED" for t in tasks):
            return
        time.sleep(2)
    raise AssertionError(f"tasks of service {service_name} not STOPPED within {timeout_s:.0f}s")



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=780.0, interval_s=2.0):
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
