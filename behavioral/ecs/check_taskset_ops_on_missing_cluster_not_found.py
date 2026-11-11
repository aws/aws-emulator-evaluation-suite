"""taskset-ops-on-missing-cluster-not-found."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "taskset-ops-on-missing-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['ecs']

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "cpu": 64,
        "memory": 128,
        "essential": True,
    }
]


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTaskSet, DeleteTaskSet, DescribeTaskSets, UpdateTaskSet and
    UpdateServicePrimaryTaskSet on a nonexistent cluster return ClusterNotFoundException, while
    all five succeed on a real cluster, service and task set."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_cluster = ctx.unique_name("no-such-cluster-")
    fake_service = ctx.unique_name("svc-")
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    td = ecs.register_task_definition(
        family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    fake_taskset_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:task-set/{bogus_cluster}/{fake_service}/"
        "ecs-svc/0123456789012345678"
    )

    # ---- positive control: a real cluster/service/task set ----
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no shared network VPC subnets available for the awsvpc task set")
    subnet_id = subnets[0]["SubnetId"]
    vpc_id = subnets[0]["VpcId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available in the shared network")
    sg_id = sgs[0]["GroupId"]

    real_family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    real_td_arn = ecs.register_task_definition(
        family=real_family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal", "essential": True}
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=real_td_arn))

    real_cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))[
        "cluster"
    ]["clusterName"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, real_cluster))

    real_service = ctx.unique_name("sim2real-behav-ecs-svc-ext-")
    ecs.create_service(
        cluster=real_cluster,
        serviceName=real_service,
        desiredCount=0,
        deploymentController={"type": "EXTERNAL"},
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=real_cluster, service=real_service, force=True))

    real_ts = ecs.create_task_set(
        cluster=real_cluster,
        service=real_service,
        taskDefinition=real_td_arn,
        scale={"value": 0, "unit": "PERCENT"},
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": {"subnets": [subnet_id], "securityGroups": [sg_id]}},
    )["taskSet"]
    real_ts_id = real_ts["id"]
    assert real_ts["status"] in ("ACTIVE", "PRIMARY"), (
        f"positive control CreateTaskSet: expected ACTIVE/PRIMARY, got {real_ts['status']}"
    )

    real_primary = ecs.update_service_primary_task_set(
        cluster=real_cluster, service=real_service, primaryTaskSet=real_ts_id
    )["taskSet"]
    assert real_primary["status"] == "PRIMARY", (
        f"positive control UpdateServicePrimaryTaskSet: expected PRIMARY, got {real_primary['status']}"
    )

    real_sets = ecs.describe_task_sets(cluster=real_cluster, service=real_service, taskSets=[real_ts_id])[
        "taskSets"
    ]
    assert len(real_sets) == 1 and real_sets[0]["status"] == "PRIMARY", (
        f"positive control DescribeTaskSets: expected one PRIMARY task set, got {real_sets}"
    )

    real_updated = ecs.update_task_set(
        cluster=real_cluster,
        service=real_service,
        taskSet=real_ts_id,
        scale={"value": 1, "unit": "PERCENT"},
    )["taskSet"]
    assert real_updated["scale"]["value"] == 1, (
        f"positive control UpdateTaskSet: expected scale 1, got {real_updated['scale']}"
    )

    ecs.delete_task_set(cluster=real_cluster, service=real_service, taskSet=real_ts_id, force=True)

    # ---- negative: every op below fails on the missing cluster ----
    not_found = ("ClusterNotFoundException", "Cluster not found.")

    error = _error(
        lambda: ecs.create_task_set(
            cluster=bogus_cluster, service=fake_service, taskDefinition=td_arn
        )
    )
    assert error == not_found, f"CreateTaskSet: got {error!r}"

    error = _error(
        lambda: ecs.delete_task_set(
            cluster=bogus_cluster, service=fake_service, taskSet=fake_taskset_arn
        )
    )
    assert error == not_found, f"DeleteTaskSet: got {error!r}"

    error = _error(
        lambda: ecs.describe_task_sets(
            cluster=bogus_cluster, service=fake_service, taskSets=[fake_taskset_arn]
        )
    )
    assert error == not_found, f"DescribeTaskSets: got {error!r}"

    error = _error(
        lambda: ecs.update_task_set(
            cluster=bogus_cluster,
            service=fake_service,
            taskSet=fake_taskset_arn,
            scale={"value": 1.0, "unit": "PERCENT"},
        )
    )
    assert error == not_found, f"UpdateTaskSet: got {error!r}"

    error = _error(
        lambda: ecs.update_service_primary_task_set(
            cluster=bogus_cluster, service=fake_service, primaryTaskSet=fake_taskset_arn
        )
    )
    assert error == not_found, f"UpdateServicePrimaryTaskSet: got {error!r}"



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until they stop, then delete it: DeleteCluster is
    refused while services or tasks remain, and a running task's ENI blocks network deletion."""
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
