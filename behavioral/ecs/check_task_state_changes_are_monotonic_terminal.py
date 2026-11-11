"""task-state-changes-are-monotonic-terminal."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-state-changes-are-monotonic-terminal"
GROUP = "ordering"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SubmitTaskStateChange on a stopped Fargate task is refused with AccessDeniedException for
    any caller but the verified Fargate agent, after a StopTask positive control, and DescribeTasks
    shows the task's terminal status untouched, which keeps that state monotonic."""

    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a task for this check")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to launch a task for this check")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available to launch a task for this check")
    sg_id = sgs[0]["GroupId"]

    cluster_name = ctx.unique_name("sim2real-ecs-mono-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecs-mono-td-")
    td = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "c",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "3600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))

    try:
        run_resp = ecs.run_task(
            cluster=cluster_name,
            taskDefinition=td["taskDefinitionArn"],
            launchType="FARGATE",
            count=1,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [subnet_id],
                    "securityGroups": [sg_id],
                    "assignPublicIp": "ENABLED",
                }
            },
        )
    except ClientError as e:
        raise AssertionError(f"RunTask rejected in this environment: {_code(e)}")

    if not run_resp.get("tasks"):
        raise AssertionError(f"RunTask returned no task: {run_resp.get('failures')}")
    task_arn = run_resp["tasks"][0]["taskArn"]

    def _cleanup_task():
        try:
            ecs.stop_task(cluster=cluster_name, task=task_arn, reason="behavioral-check-cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_task)

    # Positive control: StopTask is a client-facing op (not agent-only) and must have a
    # real, observable effect on this same task -- otherwise the later denial would be
    # indistinguishable from "nothing about this principal or task works at all".
    ecs.stop_task(cluster=cluster_name, task=task_arn, reason="behavioral-check-positive-control")
    stopped = _poll_task_status(ecs, cluster_name, task_arn, {"STOPPED"}, timeout_s=120.0)
    assert stopped["lastStatus"] == "STOPPED", (
        f"positive control StopTask never reached STOPPED: {stopped['lastStatus']}"
    )

    # The negative: SubmitTaskStateChange is the ECS agent's own API. Against a Fargate
    # task it is rejected for any caller that is not the verified Fargate agent,
    # regardless of the caller's IAM permissions -- assert that specific, deterministic
    # refusal rather than assuming the call silently no-ops or succeeds.
    code = None
    message = ""
    try:
        ecs.submit_task_state_change(cluster=cluster_name, task=task_arn, status="RUNNING", reason="stale-agent-report")
    except ClientError as e:
        code = _code(e)
        message = e.response.get("Error", {}).get("Message", "")
    assert code == "AccessDeniedException", (
        f"expected SubmitTaskStateChange against a Fargate task from a non-agent caller "
        f"to be rejected with AccessDeniedException; got {code!r} instead -- "
        f"SubmitTaskStateChange may now be reachable from a non-agent caller"
    )
    assert message == "Fargate task state changes from the agent must have the instance verified", (
        f"AccessDeniedException must name agent/instance verification as the reason, got {message!r}"
    )

    # The rejected call must have had zero effect, not just at this instant but held
    # over a bounded window, in case the denial were only reflected in DescribeTasks
    # after a delay.
    _poll_confirms_stable(ecs, cluster_name, task_arn, "STOPPED", duration_s=15.0, interval_s=3.0)


# ===== helpers =====
def _code(e: ClientError):
    return e.response.get("Error", {}).get("Code")


def _poll_task_status(ecs, cluster, task_arn, wanted_statuses, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_task(ecs, cluster, task_arn)
        if last["lastStatus"] in wanted_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"task never reached {wanted_statuses}; last status={last['lastStatus'] if last else None}")


def _poll_confirms_stable(ecs, cluster, task_arn, expected_status, duration_s=15.0, interval_s=3.0):
    """Sample DescribeTasks repeatedly over a bounded window, asserting no regression on any sample."""
    deadline = time.monotonic() + duration_s
    samples = 0
    last = None
    while time.monotonic() < deadline:
        last = _describe_task(ecs, cluster, task_arn)
        assert last["lastStatus"] == expected_status, (
            f"task status regressed from {expected_status} to {last['lastStatus']} after a later state report"
        )
        samples += 1
        time.sleep(interval_s)
    assert samples >= 1, "did not take any samples while confirming terminal status stability"
    return last



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


def _describe_task(ecs, cluster, task_arn, timeout_s=60.0):
    """DescribeTasks for one task, retrying while ECS does not list it yet.

    Right after RunTask, DescribeTasks can briefly answer with the task under `failures`
    (reason MISSING) instead of `tasks`.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        tasks = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
        if tasks:
            return tasks[0]
        if time.monotonic() >= deadline:
            raise AssertionError(f"DescribeTasks never listed task {task_arn} within {timeout_s}s")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
