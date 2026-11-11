"""run-task-launch-type-and-capacity-provider-conflict-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "run-task-launch-type-and-capacity-provider-conflict-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask with both launchType and capacityProviderStrategy is rejected: the API requires
    launchType to be omitted when a capacity provider strategy is given."""
    ecs = ctx.client("ecs")

    cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-cluster-"),
        capacityProviders=["FARGATE", "FARGATE_SPOT"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
        tags=[
            {"key": "sim2real:managed", "value": "true"},
            {"key": "sim2real:prefix", "value": "sim2real-behav"},
        ],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    subnet_id, sg_id = _get_default_subnet_and_sg(ctx)

    task_def = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-taskdef-"),
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "300"],
            }
        ],
        tags=[
            {"key": "sim2real:managed", "value": "true"},
            {"key": "sim2real:prefix", "value": "sim2real-behav"},
        ],
    )["taskDefinition"]
    task_def_arn = task_def["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    network_config: dict[str, Any] = {
        "awsvpcConfiguration": {"subnets": [subnet_id], "assignPublicIp": "ENABLED"}
    }
    if sg_id:
        network_config["awsvpcConfiguration"]["securityGroups"] = [sg_id]

    # Positive control: capacityProviderStrategy alone (no launchType) is a valid
    # combination and actually starts a real Fargate task.
    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        capacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
        networkConfiguration=network_config,
        count=1,
    )
    assert not run_resp.get("failures"), f"positive control RunTask failed: {run_resp['failures']}"
    tasks = run_resp["tasks"]
    assert len(tasks) == 1, f"expected exactly 1 task from the positive control, got {len(tasks)}"
    task_arn = tasks[0]["taskArn"]

    def _stop_and_wait() -> None:
        try:
            ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-behav cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        _poll_until(
            lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0][
                "lastStatus"
            ],
            lambda status: status == "STOPPED",
            timeout_s=120.0,
            interval_s=3.0,
        )

    ctx.on_cleanup(_stop_and_wait)

    tasks_before = set(ecs.list_tasks(cluster=cluster_arn)["taskArns"])

    # Negative: specify BOTH launchType and capacityProviderStrategy in the same request.
    code, message = _refusal(
        lambda: ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=task_def_arn,
            launchType="FARGATE",
            capacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
            networkConfiguration=network_config,
            count=1,
        )
    )
    assert code == "InvalidParameterException", (
        f"RunTask with both launchType and capacityProviderStrategy must be rejected with "
        f"InvalidParameterException, got {code!r}"
    )
    assert message == "You may choose a capacity provider or a launch type but not both.", f"refusal message {message!r}"

    tasks_after = set(ecs.list_tasks(cluster=cluster_arn)["taskArns"])
    assert tasks_after == tasks_before, "conflicting RunTask call must not start a new task"


# ===== helpers =====
def _refusal(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because a target accepting what AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _get_default_subnet_and_sg(ctx) -> tuple[str, str | None]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available to build a networkConfiguration for the Fargate "
            "RunTask positive control; provision a shared network VPC (or add explicit VPC "
            "discovery) to close this gap"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for RunTask networkConfiguration")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return subnet_id, sg_id



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
