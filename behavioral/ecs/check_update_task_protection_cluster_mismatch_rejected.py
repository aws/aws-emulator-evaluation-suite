"""update-task-protection-cluster-mismatch-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-task-protection-cluster-mismatch-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTaskProtection with a task ARN from another cluster fails with InvalidParameterException and its
    exact message and protects nothing, while the call scoped to the task's own cluster protects it.
    """
    ecs = ctx.client("ecs")
    net = _default_network(ctx)

    cluster_a_arn, _ = _create_cluster(ctx)
    cluster_b_arn, _ = _create_cluster(ctx)

    task_def_arn = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-td-"), ["sleep", "3600"])

    _svc_a_arn, svc_a_name = _create_service_with_running_task(ctx, cluster_a_arn, task_def_arn, net)
    task_a_arn = _wait_for_running_tasks(ctx, cluster_a_arn, svc_a_name, count=1)[0]

    _svc_b_arn, svc_b_name = _create_service_with_running_task(ctx, cluster_b_arn, task_def_arn, net)
    task_b_arn = _wait_for_running_tasks(ctx, cluster_b_arn, svc_b_name, count=1)[0]

    # Break exactly one thing: ask cluster A to protect a task that lives in cluster B.
    # Real ECS rejects this outright with InvalidParameterException (a top-level
    # call failure), not a per-task MISSING failure entry.
    code, message = _error(
        lambda: ecs.update_task_protection(
            cluster=cluster_a_arn, tasks=[task_b_arn], protectionEnabled=True, expiresInMinutes=10
        )
    )
    assert code == "InvalidParameterException", f"unexpected error code: {code}"
    expected_message = "Invalid identifier: cluster identifiers mismatch"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: querying from the task's real (home) cluster shows it was never protected.
    get_resp = ecs.get_task_protection(cluster=cluster_b_arn, tasks=[task_b_arn])
    matching = [p for p in get_resp["protectedTasks"] if _task_id(p["taskArn"]) == _task_id(task_b_arn)]
    assert matching, "expected a protection status entry for the task in its own cluster"
    assert matching[0]["protectionEnabled"] is False, (
        "task shows as protected even though the protecting call targeted the wrong cluster"
    )

    # Positive control: the identical call, scoped to the task's real cluster, succeeds.
    control_resp = ecs.update_task_protection(
        cluster=cluster_b_arn, tasks=[task_b_arn], protectionEnabled=True, expiresInMinutes=10
    )
    assert control_resp["failures"] == []
    assert _task_id(control_resp["protectedTasks"][0]["taskArn"]) == _task_id(task_b_arn)
    assert control_resp["protectedTasks"][0]["protectionEnabled"] is True

    # Terminal read: independent of the mutating call above, and confirms task A
    # (in the other cluster, never targeted by any protecting call) is unaffected.
    confirm_resp = ecs.get_task_protection(cluster=cluster_b_arn, tasks=[task_b_arn])
    confirm_matching = [
        p for p in confirm_resp["protectedTasks"] if _task_id(p["taskArn"]) == _task_id(task_b_arn)
    ]
    assert confirm_matching, "expected the positive-control protection to be visible on an independent read"
    assert confirm_matching[0]["protectionEnabled"] is True, (
        "independent read does not reflect the positive control's protectionEnabled=True"
    )

    a_resp = ecs.get_task_protection(cluster=cluster_a_arn, tasks=[task_a_arn])
    a_matching = [p for p in a_resp["protectedTasks"] if _task_id(p["taskArn"]) == _task_id(task_a_arn)]
    assert a_matching, "expected a protection status entry for task A in its own cluster"
    assert a_matching[0]["protectionEnabled"] is False, (
        "task A shows as protected, but no call in this check ever targeted it"
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
    arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]

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


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected UpdateTaskProtection to reject a cross-cluster task ARN, but it SUCCEEDED and returned {result!r}")


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
