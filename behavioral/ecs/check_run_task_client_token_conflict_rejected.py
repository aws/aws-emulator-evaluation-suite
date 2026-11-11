"""run-task-client-token-conflict-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "run-task-client-token-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a RunTask clientToken with the same parameters returns the same task; reusing it
    with a different task definition is rejected with ConflictException and starts no task."""
    ecs = ctx.client("ecs")
    cluster_arn = _create_cluster(ctx)
    net = _default_network(ctx)
    td1 = _register_sleep_task_def(ctx, family_prefix="sim2real-behav-ctok-a")
    td2 = _register_sleep_task_def(ctx, family_prefix="sim2real-behav-ctok-b")
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [net["subnet_id"]],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }
    token = str(uuid.uuid4())
    run_task_kwargs = dict(
        cluster=cluster_arn,
        taskDefinition=td1["taskDefinitionArn"],
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        clientToken=token,
    )

    resp1 = ecs.run_task(**run_task_kwargs)
    assert not resp1.get("failures"), f"unexpected RunTask failures: {resp1['failures']}"
    task_arn = resp1["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_task_ignore(ecs, cluster_arn, task_arn))

    replay = ecs.run_task(**run_task_kwargs)
    assert not replay.get("failures"), f"unexpected RunTask failures on identical-params replay: {replay['failures']}"
    assert len(replay["tasks"]) == 1, f"expected the deduped replay to describe exactly one task, got {replay['tasks']}"
    assert replay["tasks"][0]["taskArn"] == task_arn, (
        f"reusing clientToken with the ORIGINAL parameters must return the SAME task "
        f"(dedup), got {replay['tasks'][0]['taskArn']} vs {task_arn}"
    )

    code, message = _refusal(
        lambda: ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=td2["taskDefinitionArn"],
            launchType="FARGATE",
            networkConfiguration=net_cfg,
            clientToken=token,
        )
    )
    assert code == "ConflictException", f"expected ConflictException reusing clientToken with different params, got {code}"
    assert message == "The RunTask request could not be processed due to conflicts. The provided clientToken is already in use with a different request.", f"refusal message {message!r}"

    listed = ecs.list_tasks(cluster=cluster_arn)["taskArns"]
    assert listed.count(task_arn) == 1 and len(listed) == 1, (
        f"the rejected clientToken-conflict RunTask must not have left a second task behind; "
        f"ListTasks on {cluster_arn} shows {listed}, expected exactly [{task_arn}]"
    )


def _refusal(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; success raises."""
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
    arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, arn))
    return arn


def _safe_delete_cluster(ecs, arn: str) -> None:
    _drain_and_delete_ecs_cluster(ecs, arn)


def _register_sleep_task_def(ctx, family_prefix="sim2real-behav-sleep"):
    ecs = ctx.client("ecs")
    family = ctx.unique_name(f"{family_prefix}-")
    td = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "900"],
                "essential": True,
            }
        ],
    )["taskDefinition"]

    def _cleanup():
        try:
            ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"])
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
        ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]])

    ctx.on_cleanup(_cleanup)
    return td


def _stop_task_ignore(ecs, cluster_arn: str, task_arn: str) -> None:
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-behav-cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services or tasks remain, and a running task's ENI blocks
    deleting the network.
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
