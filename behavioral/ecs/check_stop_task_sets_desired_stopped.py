"""stop-task-sets-desired-stopped."""

from __future__ import annotations

import time


from behavioral_harness import tags

CHECK = "stop-task-sets-desired-stopped"
GROUP = "task-execution"
SERVICES = ["ecs"]

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": ["sh", "-c", "sleep 3600"],
    }
]

# Prefix of the failure message when StopTask does not set desiredStatus STOPPED: StopTask
# needs a container runtime that actually runs the task it stops.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data"
)
def run(ctx) -> None:
    """StopTask sets desiredStatus to STOPPED and eventually the task
    reaches lastStatus STOPPED."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    _vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get(
        "Vpcs", []
    )
    if not _vpcs:
        raise AssertionError("no shared network VPC available for Fargate tasks")
    subnets = [
        s["SubnetId"]
        for s in ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [_vpcs[0]["VpcId"]]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        ).get("Subnets", [])
    ]
    if not subnets:
        raise AssertionError("shared network has no network subnets")
    cluster = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"),
        tags=[{"key": "sim2real", "value": "true"}],
    )["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(
        lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(
            taskDefinitions=[a]
        )
    )
    ctx.on_cleanup(
        lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(
            taskDefinition=a
        )
    )
    resp = ecs.run_task(
        cluster=cluster["clusterName"],
        taskDefinition=td["taskDefinitionArn"],
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnets, "assignPublicIp": "ENABLED"}
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )
    for _t in resp.get("tasks", []):
        ctx.on_cleanup(
            lambda cl=cluster["clusterName"], ta=_t["taskArn"]: ecs.stop_task(
                cluster=cl, task=ta
            )
        )
    task_arn = resp["tasks"][0]["taskArn"]

    # Stopping a task that was never really placed cannot exercise the transition this check
    # is named for, so wait for the task to reach RUNNING (or fail on its own first) before
    # calling StopTask.
    _run_deadline = time.monotonic() + 300
    _last = None
    while True:
        _tasks = ecs.describe_tasks(cluster=cluster["clusterName"], tasks=[task_arn])[
            "tasks"
        ]
        _last = _tasks[0] if _tasks else _last
        if _last is not None and _last["lastStatus"] in ("RUNNING", "STOPPED"):
            break
        if time.monotonic() >= _run_deadline:
            raise AssertionError(
                f"task never reached RUNNING within 300s; last lastStatus="
                f"{_last['lastStatus'] if _last else None!r}"
            )
        time.sleep(5)
    assert _last["lastStatus"] == "RUNNING", (
        f"task reached STOPPED on its own (stoppedReason={_last.get('stoppedReason')!r}) "
        "before StopTask could be exercised"
    )

    stop_reason = "sim2real-behavioral-stop-task-sets-desired-stopped"
    stopped = ecs.stop_task(
        cluster=cluster["clusterName"], task=task_arn, reason=stop_reason
    )["task"]
    assert stopped["desiredStatus"] == "STOPPED", (
        f"{DATAPLANE_MARKER}: "
        f"expected desiredStatus STOPPED, got {stopped['desiredStatus']}"
    )

    # A Fargate task that is still PROVISIONING can take a couple of minutes
    # to fully reach STOPPED, so allow a generous bound here.
    _deadline = time.monotonic() + 300
    while True:
        # DescribeTasks is eventually consistent right after RunTask/StopTask —
        # the task ARN can be briefly absent, so tolerate an empty list instead
        # of indexing [0] and poll until it appears + reaches STOPPED.
        _tasks = ecs.describe_tasks(cluster=cluster["clusterName"], tasks=[task_arn])[
            "tasks"
        ]
        t = _tasks[0] if _tasks else None
        if t is not None and t["lastStatus"] == "STOPPED":
            break
        if time.monotonic() >= _deadline:
            raise AssertionError("condition not met within 300s")
        time.sleep(5)

    assert t["stopCode"] == "UserInitiated", (
        f"expected stopCode UserInitiated, got {t.get('stopCode')!r}"
    )
    assert t.get("stoppedReason") == stop_reason, (
        f"expected stoppedReason {stop_reason!r}, got {t.get('stoppedReason')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
