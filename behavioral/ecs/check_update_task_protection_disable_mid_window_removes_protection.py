"""update-task-protection-disable-mid-window-removes-protection."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-task-protection-disable-mid-window-removes-protection"
GROUP = "data-plane"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Calling UpdateTaskProtection with protectionEnabled=false well before the
    original expiry immediately clears protection state visible via GetTaskProtection,
    rather than leaving it protected until the original window elapses."""
    ecs = ctx.client("ecs")
    net = _default_network(ctx)
    cluster_arn, cluster_name = _create_cluster(ctx)
    task_def_arn = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-td-"), ["sleep", "3600"])
    service_arn, service_name = _create_service_with_running_task(ctx, cluster_arn, task_def_arn, net)
    task_arns = _wait_for_running_tasks(ctx, cluster_arn, service_name, count=1)
    task_arn = task_arns[0]

    # Protect for a long (60 minute) window -- if disabling were ignored or
    # deferred until expiry, the task would still show protected far into the future.
    enable_resp = ecs.update_task_protection(
        cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=60
    )
    enable_protected = enable_resp["protectedTasks"][0]["protectionEnabled"]
    assert enable_protected is True, f"expected protectionEnabled=True after enabling, got {enable_protected!r}"

    get_after_enable = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])
    after_enable_protected = get_after_enable["protectedTasks"][0]["protectionEnabled"]
    assert after_enable_protected is True, (
        f"expected GetTaskProtection to report protectionEnabled=True after enabling, got {after_enable_protected!r}"
    )

    disable_resp = ecs.update_task_protection(cluster=cluster_arn, tasks=[task_arn], protectionEnabled=False)
    # UpdateTaskProtection echoes taskArn in the short (no cluster-name-segment)
    # ARN form regardless of the long-ARN form passed in -- compare by task ID.
    disable_task_id = _task_id(disable_resp["protectedTasks"][0]["taskArn"])
    assert disable_task_id == _task_id(task_arn), (
        f"expected UpdateTaskProtection response to echo task id {_task_id(task_arn)!r}, got {disable_task_id!r}"
    )
    disable_protected = disable_resp["protectedTasks"][0]["protectionEnabled"]
    assert disable_protected is False, f"expected protectionEnabled=False after disabling, got {disable_protected!r}"

    get_after_disable = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])
    matching = [p for p in get_after_disable["protectedTasks"] if _task_id(p["taskArn"]) == _task_id(task_arn)]
    assert matching, "expected a protection status entry for the task"
    assert matching[0]["protectionEnabled"] is False, (
        "task still reports as protected immediately after disabling protection, "
        "well before its 60-minute window would have expired"
    )


def _default_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch Fargate tasks")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch Fargate tasks into")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {
        "subnets": [s["SubnetId"] for s in subnets[:2]],
        "security_groups": [sgs[0]["GroupId"]] if sgs else [],
    }


def _create_cluster(ctx) -> tuple[str, str]:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-")
    arn = ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])["cluster"]["clusterArn"]

    def _cleanup() -> None:
        try:
            ecs.delete_cluster(cluster=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn, name


def _register_fargate_task_def(ctx, family: str, command: list[str]) -> str:
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": command,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _create_service_with_running_task(ctx, cluster_arn: str, task_def_arn: str, net: dict, desired_count: int = 1):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-svc-")
    resp = ecs.create_service(
        cluster=cluster_arn,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnets"],
                "securityGroups": net["security_groups"],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )
    service_arn = resp["service"]["serviceArn"]
    ctx.on_cleanup(
        lambda: _try(lambda: ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True))
    )
    return service_arn, name


def _wait_for_running_tasks(ctx, cluster_arn: str, service_name: str, count: int = 1, timeout_s: float = 300.0):
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        arns = ecs.list_tasks(cluster=cluster_arn, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
        if len(arns) >= count:
            return arns
        time.sleep(2)
    raise AssertionError(f"service {service_name} did not reach {count} RUNNING task(s) within {timeout_s}s")


def _try(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _task_id(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


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
