"""deploy-ecs-runtask-fargate-incompatible-taskdef-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecs-runtask-fargate-incompatible-taskdef-rejected"
GROUP = "deploy"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask with launchType=FARGATE on a non-awsvpc task definition is rejected with
    InvalidParameterException and creates no task; the family's awsvpc revision runs."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    subnet_id, sg_id = _default_subnet_and_sg(ec2, ctx=ctx)

    family = ctx.unique_name("sim2real-behav-td-")
    image = "public.ecr.aws/docker/library/busybox:latest"

    bad_def = ecs.register_task_definition(
        family=family,
        networkMode="bridge",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": image,
                "command": ["sh", "-c", "sleep 60"],
                "memory": 128,
                "essential": True,
            }
        ],
    )["taskDefinition"]
    ctx.on_cleanup(
        lambda arn=bad_def["taskDefinitionArn"]: _retire_task_definition(ecs, arn)
    )

    good_def = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        requiresCompatibilities=["FARGATE"],
        containerDefinitions=[
            {
                "name": "app",
                "image": image,
                "command": ["sh", "-c", "sleep 300"],
                "essential": True,
            }
        ],
    )["taskDefinition"]
    ctx.on_cleanup(
        lambda arn=good_def["taskDefinitionArn"]: _retire_task_definition(ecs, arn)
    )

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    # ECS rejects the network-mode/launch-type mismatch synchronously with an error,
    # not via a `failures` entry.
    code = message = None
    try:
        bad_resp = ecs.run_task(
            cluster=cluster_name,
            taskDefinition=bad_def["taskDefinitionArn"],
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
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")

    assert code == "InvalidParameterException", (
        f"expected RunTask to reject the bridge-network task definition under FARGATE with "
        f"InvalidParameterException, got code={code!r} response={bad_resp if code is None else None!r}"
    )
    assert message == 'Task definition does not support launch_type FARGATE.', f"expected the exact network-mode message, got {message!r}"

    # effect absent: no task was ever placed under this family on the cluster
    task_arns = ecs.list_tasks(cluster=cluster_name, family=family)["taskArns"]
    assert task_arns == [], f"expected no tasks placed, found {task_arns}"

    run_resp = ecs.run_task(
        cluster=cluster_name,
        taskDefinition=good_def["taskDefinitionArn"],
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
    assert not run_resp.get("failures"), run_resp.get("failures")
    good_task_arn = run_resp["tasks"][0]["taskArn"]

    def _stop() -> None:
        try:
            ecs.stop_task(cluster=cluster_name, task=good_task_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        _wait_task_stopped(ecs, cluster_name, good_task_arn, timeout_s=120.0)

    ctx.on_cleanup(_stop)

    described = ecs.describe_tasks(cluster=cluster_name, tasks=[good_task_arn])["tasks"]
    assert described, f"expected DescribeTasks to find the just-run task {good_task_arn}"
    status = described[0]["lastStatus"]
    assert status in (
        "PROVISIONING",
        "PENDING",
        "RUNNING",
    ), f"expected the Fargate-compatible control task to be alive, DescribeTasks reported {status!r}"




def _default_subnet_and_sg(ec2: Any, *, ctx) -> tuple[str, str]:

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account/region has no shared network VPC to attach the Fargate task to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    public = [s for s in subnets if s.get("MapPublicIpOnLaunch")]
    subnet_id = (public or subnets)[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _wait_task_stopped(ecs: Any, cluster: str, task_arn: str, timeout_s: float) -> None:
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if not tasks or tasks[0]["lastStatus"] == "STOPPED":
            return
        time.sleep(5.0)



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
                if exc.response["Error"]["Code"] not in (
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                    "ServiceNotActiveException",
                ):
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
