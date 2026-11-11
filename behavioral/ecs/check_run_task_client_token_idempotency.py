"""run-task-client-token-idempotency."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "run-task-client-token-idempotency"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]

_ECS_TAGS = [{"key": "sim2real", "value": "true"}]


def _refusal(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because a target accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _register_fargate_td(ctx, ecs):
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=_ECS_TAGS,
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=arn))
    return arn


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask calls reusing one clientToken with identical parameters return the same task,
    while reusing the token with a different task definition is rejected with ConflictException."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC available for Fargate tasks")
    vpc_id = vpcs[0]["VpcId"]
    subnets = [
        s["SubnetId"]
        for s in ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        ).get("Subnets", [])
    ]
    if not subnets:
        raise AssertionError("shared network has no network subnets")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError("no default security group available")
    sg = sgs[0]["GroupId"]
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }

    cluster = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"), tags=_ECS_TAGS
    )["cluster"]
    name = cluster["clusterName"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    td1_arn = _register_fargate_td(ctx, ecs)
    td2_arn = _register_fargate_td(ctx, ecs)
    token = ctx.unique_name("token-")

    first = ecs.run_task(
        cluster=name,
        taskDefinition=td1_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net_cfg,
        clientToken=token,
    )
    assert not first.get("failures"), f"unexpected RunTask failures: {first.get('failures')}"
    task_arn = first["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=name, task=task_arn, reason="behavioral-cleanup"))

    second = ecs.run_task(
        cluster=name,
        taskDefinition=td1_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net_cfg,
        clientToken=token,
    )
    assert not second.get("failures"), f"unexpected RunTask failures on retry: {second.get('failures')}"
    assert len(second["tasks"]) == 1, f"expected one task on the deduped retry, got {second['tasks']}"
    assert second["tasks"][0]["taskArn"] == task_arn, (
        f"reusing the same clientToken with identical params must return the SAME task, "
        f"got {second['tasks'][0]['taskArn']} vs {task_arn}"
    )

    listed = ecs.list_tasks(cluster=name)["taskArns"]
    assert listed.count(task_arn) == 1, (
        f"a deduped RunTask retry must not have launched a second task; ListTasks shows "
        f"{listed.count(task_arn)} occurrences of {task_arn}"
    )

    # overly-permissive boundary: same token, DIFFERENT task definition.
    code, message = _refusal(
        lambda: ecs.run_task(
            cluster=name,
            taskDefinition=td2_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration=net_cfg,
            clientToken=token,
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException reusing a clientToken with a different request, got {code}"
    )
    assert message == "The RunTask request could not be processed due to conflicts. The provided clientToken is already in use with a different request.", f"refusal message {message!r}"

    # ConflictException must be a real rejection, not a label on a request that ran
    # anyway: an independent read must show no new task appeared.
    after_conflict = ecs.list_tasks(cluster=name)["taskArns"]
    assert set(after_conflict) == set(listed), (
        f"a clientToken conflict rejected with ConflictException must have zero effect; "
        f"ListTasks changed from {sorted(listed)} to {sorted(after_conflict)}"
    )



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
