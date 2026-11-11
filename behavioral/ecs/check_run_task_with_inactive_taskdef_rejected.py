"""run-task-with-inactive-taskdef-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-task-with-inactive-taskdef-rejected"
GROUP = "representation"
SERVICES = ["ecs"]

_TAGS = [{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:check", "value": CHECK}]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask on a deregistered (INACTIVE) revision is rejected with InvalidParameterException
    and places no task, while a sibling ACTIVE revision reaches RUNNING."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    net_cfg = {"awsvpcConfiguration": {"subnets": [subnet_id], "assignPublicIp": "ENABLED"}}
    if sg_id:
        net_cfg["awsvpcConfiguration"]["securityGroups"] = [sg_id]
    family = ctx.unique_name("sim2real-ecs-inactive-")

    def _register():
        return ecs.register_task_definition(
            family=family,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            cpu="256",
            memory="512",
            containerDefinitions=[
                {"name": "c", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "essential": True}
            ],
            tags=_TAGS,
        )["taskDefinition"]["taskDefinitionArn"]

    inactive_arn = _register()
    ecs.deregister_task_definition(taskDefinition=inactive_arn)

    def _cleanup_inactive():
        ecs.delete_task_definitions(taskDefinitions=[inactive_arn])

    ctx.on_cleanup(_cleanup_inactive)

    cluster_name = ctx.unique_name("sim2real-ecs-inactive-cl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_TAGS)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    # --- negative: RunTask against the INACTIVE revision must be rejected ---
    error = _error(
        lambda: ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=inactive_arn,
            launchType="FARGATE",
            networkConfiguration=net_cfg,
            count=1,
        )
    )
    assert error["Code"] == "InvalidParameterException", (
        f"RunTask on an INACTIVE task definition revision must fail with InvalidParameterException, "
        f"got {error['Code']!r} ({error.get('Message')!r})"
    )
    assert error.get("Message") == "TaskDefinition is inactive", (
        "the refusal must attribute itself to the revision's INACTIVE status, got "
        f"{error.get('Message')!r}"
    )

    tasks_after_reject = ecs.list_tasks(cluster=cluster_arn).get("taskArns", [])
    assert tasks_after_reject == [], f"a task was placed despite the rejected RunTask call: {tasks_after_reject}"

    # --- positive control: a fresh ACTIVE revision of the same family must actually run ---
    active_arn = _register()

    def _cleanup_active():
        ecs.delete_task_definitions(taskDefinitions=[active_arn])

    ctx.on_cleanup(_cleanup_active)
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=active_arn))

    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=active_arn,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        count=1,
    )
    assert run_resp.get("tasks"), f"positive control RunTask on an ACTIVE revision failed: {run_resp.get('failures')}"
    control_task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster_arn, task=control_task_arn, reason="cleanup"))

    # The API accepting the call is not "runs successfully" — prove the task actually reaches
    # RUNNING via an independent read, not the RunTask response that placed it.
    def _describe_control():
        return ecs.describe_tasks(cluster=cluster_arn, tasks=[control_task_arn])["tasks"][0]

    settled = _poll_until(
        _describe_control,
        lambda t: t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert settled["lastStatus"] == "RUNNING", (
        "the positive-control task on a fresh ACTIVE revision never reached RUNNING "
        f"(stopped early: {settled.get('stoppedReason')!r})"
    )


# ===== helpers =====
def _default_subnet_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to place a Fargate task")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to place a Fargate task")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return subnets[0]["SubnetId"], sg_id


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")



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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
