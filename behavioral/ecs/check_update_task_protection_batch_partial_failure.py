"""update-task-protection-batch-partial-failure."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-task-protection-batch-partial-failure"
GROUP = "data-plane"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTaskProtection called with a mix of one valid task ID and one nonexistent
    task ID must return per-task success/failure entries (protectedTasks +
    failures[reason=MISSING]) rather than failing the whole batch call with an error.
    """
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_vpc_subnet_and_sg(ctx)
    cluster = _create_cluster(ctx)
    task_def_arn = _register_sleeper_task_def(ctx)
    service_name = _create_service(ctx, cluster, task_def_arn, subnet_id, sg_id, 1)
    task_arns = _wait_for_running_tasks(ctx, cluster, service_name, 1)
    valid_task_arn = task_arns[0]

    # Well-formed but nonexistent task ARN in the same cluster/partition/region/account.
    fake_task_id = uuid.uuid4().hex
    arn_prefix = valid_task_arn.rsplit("/", 1)[0]
    nonexistent_task_arn = f"{arn_prefix}/{fake_task_id}"

    resp = ecs.update_task_protection(
        cluster=cluster,
        tasks=[valid_task_arn, nonexistent_task_arn],
        protectionEnabled=True,
        expiresInMinutes=10,
    )

    protected = {p["taskArn"].rsplit("/", 1)[-1]: p for p in resp["protectedTasks"]}
    failed = {f["arn"].rsplit("/", 1)[-1]: f for f in resp["failures"]}
    valid_task_id = valid_task_arn.rsplit("/", 1)[-1]

    # NOTE: UpdateTaskProtection/GetTaskProtection echo taskArn/arn in the *short*
    # task-ARN form (no cluster-name path segment) even when the request supplied the
    # long-form ARN (as returned by DescribeTasks/ListTasks) -- match by trailing task
    # ID, not full-ARN string equality, to avoid a false negative on this format quirk.
    assert valid_task_id in protected, f"expected {valid_task_id} in protectedTasks, got {resp['protectedTasks']}"
    assert protected[valid_task_id]["protectionEnabled"] is True, (
        f"expected protectionEnabled=True for {valid_task_id}, got {protected[valid_task_id]}"
    )

    assert fake_task_id in failed, f"expected {fake_task_id} in failures, got {resp['failures']}"
    assert failed[fake_task_id]["reason"] == "MISSING", (
        f"expected reason=MISSING for {fake_task_id}, got {failed[fake_task_id]}"
    )

    assert valid_task_id not in failed, f"valid task {valid_task_id} unexpectedly present in failures: {failed}"
    assert fake_task_id not in protected, (
        f"nonexistent task {fake_task_id} unexpectedly present in protectedTasks: {protected}"
    )

    # Confirm the valid task's protection actually took effect (side effect, not just echo).
    gtp = ecs.get_task_protection(cluster=cluster, tasks=[valid_task_arn])
    assert not gtp["failures"], f"expected no failures reading back protection state, got {gtp['failures']}"
    assert gtp["protectedTasks"][0]["protectionEnabled"] is True, (
        f"expected protectionEnabled=True on independent read, got {gtp['protectedTasks'][0]}"
    )

    # Overly-permissive boundary: expiresInMinutes is documented to accept 1..2880
    # (48h) only. A backend that silently accepts an out-of-range value instead of
    # rejecting the whole call is overly permissive on a distinct (range/quota) axis
    # from the per-task MISSING partial-failure semantics asserted above.
    code, message = _error(
        lambda: ecs.update_task_protection(
            cluster=cluster,
            tasks=[valid_task_arn],
            protectionEnabled=True,
            expiresInMinutes=2881,
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for expiresInMinutes=2881 (> 2880 max), got {code}"
    )
    expected_message = "expiresInMinutes must be at most 2880"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejection must not have mutated the task's existing (valid) protection state.
    gtp_after = ecs.get_task_protection(cluster=cluster, tasks=[valid_task_arn])
    assert not gtp_after["failures"], f"expected no failures reading back protection state, got {gtp_after['failures']}"
    assert gtp_after["protectedTasks"][0]["protectionEnabled"] is True, (
        f"expected protectionEnabled to remain True after rejected call, got {gtp_after['protectedTasks'][0]}"
    )
    assert gtp_after["protectedTasks"][0]["expirationDate"] == gtp["protectedTasks"][0]["expirationDate"], (
        "the rejected out-of-range call must not have altered the task's expirationDate"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _default_vpc_subnet_and_sg(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch a Fargate task")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch a Fargate task into")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-tp-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, name))
    return name


def _safe_delete_cluster(ecs, name: str) -> None:
    _drain_and_delete_ecs_cluster(ecs, name)


def _register_sleeper_task_def(ctx) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-tp-")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "sleeper",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "3600"],
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _create_service(ctx, cluster: str, task_def_arn: str, subnet_id: str, sg_id: str, desired_count: int) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-tp-svc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
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
    ctx.on_cleanup(lambda: _safe_delete_service(ctx, cluster, name))
    return name


def _safe_delete_service(ctx, cluster: str, name: str) -> None:
    ecs = ctx.client("ecs")
    try:
        ecs.update_service(cluster=cluster, service=name, desiredCount=0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "NamespaceNotFoundException",
            "ServiceNotActiveException",
            "ServiceNotFoundException",
        ):
            raise
    try:
        ecs.delete_service(cluster=cluster, service=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            arns = ecs.list_tasks(cluster=cluster, serviceName=name)["taskArns"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "ServiceNotFoundException",
            ):
                raise
            break
        if not arns:
            break
        time.sleep(5)


def _wait_for_running_tasks(ctx, cluster: str, service_name: str, count: int, timeout_s: float = 420.0) -> list[str]:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        arns = ecs.list_tasks(cluster=cluster, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
        if arns:
            tasks = ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]
            running = [t["taskArn"] for t in tasks if t["lastStatus"] == "RUNNING"]
            if len(running) >= count:
                return running
        time.sleep(2)
    raise AssertionError(f"expected {count} RUNNING task(s) in service {service_name} within {timeout_s}s")



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
