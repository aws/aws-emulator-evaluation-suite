"""run-task-missing-task-definition-rejected."""
from __future__ import annotations

import time
from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "run-task-missing-task-definition-rejected"
GROUP = "error-semantics"
SERVICES = ["ecs"]

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": ["sh", "-c", "sleep 3600"],
    }
]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask on a never-registered task definition family fails with ClientException and
    creates no task, while RunTask on a registered definition succeeds in the same cluster."""
    ecs = ctx.client("ecs")
    cluster_arn = _create_cluster(ctx)
    net = _default_network(ctx)
    network_config = {
        "awsvpcConfiguration": {
            "subnets": [net["subnet_id"]],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }

    task_def_arn = _register_task_def(ctx, ecs)
    good_run = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        networkConfiguration=network_config,
    )
    assert not good_run.get("failures"), (
        f"positive control RunTask against a real task definition reported failures: "
        f"{good_run.get('failures')}"
    )
    good_tasks = good_run.get("tasks", [])
    assert len(good_tasks) == 1, f"expected exactly one task from the positive control, got {good_tasks}"
    good_task_arn = good_tasks[0]["taskArn"]
    ctx.on_cleanup(lambda: _safe_stop_task(ecs, cluster_arn, good_task_arn))

    baseline_arns = set(ecs.list_tasks(cluster=cluster_arn)["taskArns"])
    assert good_task_arn in baseline_arns, (
        f"positive control task {good_task_arn} not visible via ListTasks: {baseline_arns}"
    )

    bogus_family = ctx.unique_name("sim2real-behav-nosuchtaskdef-")
    code, message = _refusal(
        lambda: ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=bogus_family,
            launchType="FARGATE",
            networkConfiguration=network_config,
        )
    )
    assert code == "ClientException", f"expected ClientException for nonexistent task definition, got {code}"
    assert message == "TaskDefinition not found.", f"refusal message {message!r}"

    after_arns = set(ecs.list_tasks(cluster=cluster_arn)["taskArns"])
    assert after_arns == baseline_arns, (
        f"RunTask against a missing task definition must create no task, but ListTasks changed: "
        f"before={baseline_arns} after={after_arns}"
    )


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


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets in shared network")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group in shared network")
    return {"subnet_id": subnets[0]["SubnetId"], "sg_id": sgs[0]["GroupId"]}


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-cluster-")
    arn = ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, arn))
    return arn


def _register_task_def(ctx, ecs):
    family = ctx.unique_name("sim2real-behav-nosuchtaskdef-real-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe_deregister_task_def(ecs, arn))
    return arn


def _safe_deregister_task_def(ecs, arn: str) -> None:
    try:
        ecs.deregister_task_definition(taskDefinition=arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
        ):
            raise
    ecs.delete_task_definitions(taskDefinitions=[arn])


def _safe_stop_task(ecs, cluster_arn: str, task_arn: str) -> None:
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _safe_delete_cluster(ecs, arn: str) -> None:
    _drain_and_delete_ecs_cluster(ecs, arn)



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
