"""task-state-change-ordering-enforced-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-state-change-ordering-enforced-rejected"
GROUP = "ordering"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitTaskStateChange from a non-agent caller for a STOPPED Fargate task fails with
    AccessDeniedException "Fargate task state changes from the agent must have the instance verified",
    and the task stays STOPPED.
    """
    ecs = ctx.client("ecs")
    subnet_id = _default_subnet(ctx)

    cluster_arn = _create_cluster(ctx, ecs)
    task_def_arn = _register_sleep_task_def(ctx, ecs)

    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": [subnet_id], "assignPublicIp": "ENABLED"}
        },
    )
    if run_resp.get("failures"):
        raise AssertionError(f"unable to launch a Fargate task in this account: {run_resp['failures']}")
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_task_quiet(ecs, cluster_arn, task_arn))

    ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-behavioral-stop")

    stopped_task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=180,
        interval_s=5.0,
    )
    assert stopped_task["lastStatus"] == "STOPPED", (
        f"positive control failed: task never reached STOPPED, last={stopped_task['lastStatus']!r}"
    )

    # Attempt an out-of-order (backward) transition: tell ECS the task is RUNNING again after
    # it has already reached the terminal STOPPED state. Real AWS denies SubmitTaskStateChange
    # outright to a non-agent caller -- assert that specific, deterministic refusal rather than
    # discarding it.
    code, message = _error_code(
        lambda: ecs.submit_task_state_change(cluster=cluster_arn, task=task_arn, status="RUNNING")
    )
    assert code == "AccessDeniedException", (
        "expected SubmitTaskStateChange to be denied to a non-agent caller with "
        f"AccessDeniedException, got code={code!r} message={message!r}"
    )
    assert message == "Fargate task state changes from the agent must have the instance verified", (
        f"expected the agent-instance-verification denial, got message={message!r}"
    )

    after = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    assert after["lastStatus"] == "STOPPED", (
        "backward SubmitTaskStateChange corrupted terminal task state: "
        f"lastStatus={after['lastStatus']!r}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected SubmitTaskStateChange to raise for a non-agent caller, it succeeded")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _default_subnet(ctx):
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
    return subnets[0]["SubnetId"]


def _create_cluster(ctx, ecs):
    name = ctx.unique_name("sim2real-ecs-tsc-")
    arn = ecs.create_cluster(
        clusterName=name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
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
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_task_definitions(taskDefinitions=[arn])))
    ctx.on_cleanup(lambda: _safe(lambda: ecs.deregister_task_definition(taskDefinition=arn)))
    return arn


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "ClusterNotFoundException"
            and not (err["Code"] == "ClientException" and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted")))
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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
