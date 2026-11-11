"""run-task-cpu-override-exceeds-taskdef-limit-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "run-task-cpu-override-exceeds-taskdef-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask rejects a container CPU override exceeding the task definition's declared cpu."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_subnet_and_sg(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-cpu-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecs-taskdef-")
    taskdef_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[{
            "name": "app",
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "cpu": 128,
            "essential": True,
            "command": ["sleep", "3600"],
        }],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, taskdef_arn))

    net_cfg = {"awsvpcConfiguration": {"subnets": [subnet_id], "assignPublicIp": "ENABLED"}}
    if sg_id:
        net_cfg["awsvpcConfiguration"]["securityGroups"] = [sg_id]

    # The container's own declared cpu (128) is NOT the enforced ceiling for an override: RunTask
    # accepts a container cpu override above it (confirmed against real AWS with 200). What RunTask
    # actually enforces is the task definition's own declared cpu (256) -- 300 sits strictly above
    # that while still far under Fargate's absolute per-task cpu ceiling, so it isolates the
    # taskdef-level rule instead of merely tripping a generic out-of-range check.
    _override_holder = {}

    def _run_with_override():
        r = ecs.run_task(
            cluster=cluster_name, taskDefinition=taskdef_arn, launchType="FARGATE",
            networkConfiguration=net_cfg,
            overrides={"containerOverrides": [{"name": "app", "cpu": 300}]},
        )
        _override_holder["resp"] = r
        return r

    try:
        code, message = _refusal(_run_with_override)
    finally:
        for _t in (_override_holder.get("resp") or {}).get("tasks", []):
            ecs.stop_task(cluster=cluster_name, task=_t["taskArn"], reason="sim2real behavioral check cleanup")
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "Sum of container 'cpu' greater than task 'cpu'.", f"refusal message {message!r}"

    # effect absent: no task was launched for the rejected override
    arns = ecs.list_tasks(cluster=cluster_name)["taskArns"]
    assert arns == [], f"expected no tasks after the rejected RunTask call, found {arns}"

    # positive control: an override within the task definition's declared cpu is accepted
    started_task_arn = None
    try:
        resp = ecs.run_task(
            cluster=cluster_name, taskDefinition=taskdef_arn, launchType="FARGATE",
            networkConfiguration=net_cfg,
            overrides={"containerOverrides": [{"name": "app", "cpu": 64}]},
        )
        assert resp["tasks"], f"expected a task to be created, failures={resp.get('failures')}"
        started_task_arn = resp["tasks"][0]["taskArn"]
        # independent read at the destination, not just the RunTask response: confirm the task
        # is really tracked by the cluster before the check declares the positive control accepted.
        listed = ecs.list_tasks(cluster=cluster_name)["taskArns"]
        assert listed == [started_task_arn], f"expected the started task to be listed, found {listed}"
    finally:
        if started_task_arn:
            ecs.stop_task(cluster=cluster_name, task=started_task_arn, reason="sim2real behavioral check cleanup")


# ===== helpers =====

def _default_subnet_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision a Fargate task network interface")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to provision a Fargate task network interface")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return subnets[0]["SubnetId"], sg_id


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
