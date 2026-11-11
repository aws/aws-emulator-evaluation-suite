"""update-task-protection-reapply-extends-expiration."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-task-protection-reapply-extends-expiration"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-invoking UpdateTaskProtection on an already-protected task with a larger
    expiresInMinutes extends the expiration timestamp instead of erroring."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    cluster_name = _create_cluster(ctx)
    taskdef_arn = _register_fargate_taskdef(ctx)
    task_arn = _run_service_task_until_running(ctx, cluster_name, taskdef_arn, subnet_id, sg_id)

    t0 = time.time()
    resp1 = ecs.update_task_protection(
        cluster=cluster_name, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=10,
    )
    assert not resp1["failures"], f"unexpected UpdateTaskProtection failures: {resp1['failures']}"
    protected1 = resp1["protectedTasks"][0]
    assert protected1["protectionEnabled"] is True, f"expected protectionEnabled=True, got {protected1}"
    expiration1 = protected1["expirationDate"]

    # re-apply with a longer TTL -- must extend, not error
    t1 = time.time()
    resp2 = ecs.update_task_protection(
        cluster=cluster_name, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=20,
    )
    assert not resp2["failures"], f"unexpected UpdateTaskProtection failures: {resp2['failures']}"
    protected2 = resp2["protectedTasks"][0]
    assert protected2["protectionEnabled"] is True, f"expected protectionEnabled=True, got {protected2}"
    expiration2 = protected2["expirationDate"]

    # The shift must track measured wall-clock time between the two calls plus the
    # 10-minute increase in expiresInMinutes (10 -> 20) -- not just "greater than",
    # which a backend anchoring to the original grant time would also satisfy.
    observed_delta = (expiration2 - expiration1).total_seconds()
    expected_delta = (t1 - t0) + (20 - 10) * 60
    assert abs(observed_delta - expected_delta) < 90, (
        f"expected re-applying with expiresInMinutes=20 (was 10) to move expiration "
        f"forward by ~{expected_delta:.0f}s (elapsed time between calls plus the "
        f"10-minute increase), got a shift of {observed_delta:.0f}s "
        f"(first={expiration1}, second={expiration2})"
    )

    # positive control: GetTaskProtection reflects the extended expiration
    gtp = ecs.get_task_protection(cluster=cluster_name, tasks=[task_arn])
    assert not gtp["failures"], f"unexpected GetTaskProtection failures: {gtp['failures']}"
    protected_now = gtp["protectedTasks"][0]
    assert protected_now["protectionEnabled"] is True, f"expected protectionEnabled=True, got {protected_now}"
    # GetTaskProtection can truncate sub-second precision relative to the
    # UpdateTaskProtection response (observed on real AWS), so compare with a
    # few seconds of slack rather than bit-for-bit datetime equality.
    read_back_delta = abs((protected_now["expirationDate"] - expiration2).total_seconds())
    assert read_back_delta < 5, (
        f"GetTaskProtection expirationDate {protected_now['expirationDate']} does not match "
        f"the just-updated expirationDate {expiration2} (delta {read_back_delta:.3f}s)"
    )


# ===== helpers =====

def _default_subnet_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision a Fargate task network interface")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to provision a Fargate task network interface")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return subnets[0]["SubnetId"], sg_id


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-tp-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    return name


def _register_fargate_taskdef(ctx):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-taskdef-")
    arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[{
            "name": "app",
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "essential": True,
            "command": ["sleep", "3600"],
        }],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _run_service_task_until_running(ctx, cluster_name, taskdef_arn, subnet_id, sg_id, timeout_s=420.0):
    ecs = ctx.client("ecs")
    service_name = ctx.unique_name("sim2real-ecs-svc-")
    net_cfg = {"awsvpcConfiguration": {"subnets": [subnet_id], "assignPublicIp": "ENABLED"}}
    if sg_id:
        net_cfg["awsvpcConfiguration"]["securityGroups"] = [sg_id]
    ecs.create_service(
        cluster=cluster_name, serviceName=service_name, taskDefinition=taskdef_arn,
        desiredCount=1, launchType="FARGATE", networkConfiguration=net_cfg,
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        arns = ecs.list_tasks(cluster=cluster_name, serviceName=service_name).get("taskArns", [])
        if arns:
            for t in ecs.describe_tasks(cluster=cluster_name, tasks=arns)["tasks"]:
                if t["lastStatus"] == "RUNNING":
                    return t["taskArn"]
        time.sleep(5)
    raise AssertionError(f"no task in service {service_name} reached RUNNING within {timeout_s}s")


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
