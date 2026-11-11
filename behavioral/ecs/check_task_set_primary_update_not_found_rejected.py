"""task-set-primary-update-not-found-rejected."""
from __future__ import annotations

import time
from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "task-set-primary-update-not-found-rejected"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateServicePrimaryTaskSet with an unknown task set is rejected and leaves PRIMARY untouched."""
    from botocore.exceptions import ClientError

    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    cluster_name = ctx.unique_name("sim2real-ts-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "check_task_set_primary_update_not_found_rejected"}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    # Real AWS rejects CreateTaskSet on an awsvpc-mode task definition without a
    # networkConfiguration ("Network Configuration must be provided when networkMode 'awsvpc' is
    # specified."), even with scale=0.
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("unreachable: no shared network VPC subnets available for the awsvpc task set")
    subnet_id = subnets[0]["SubnetId"]
    vpc_id = subnets[0]["VpcId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("unreachable: no default security group available in the shared network")
    sg_id = sgs[0]["GroupId"]
    network_configuration = {"awsvpcConfiguration": {"subnets": [subnet_id], "securityGroups": [sg_id]}}

    family = ctx.unique_name("sim2real-ts-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal", "essential": True}],
        tags=[{"key": "sim2real", "value": "check_task_set_primary_update_not_found_rejected"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-ts-svc-")
    # Real AWS rejects CreateService without desiredCount ("DesiredCount is missing"), even for
    # the EXTERNAL deployment controller where task sets (not the service) drive scale.
    ecs.create_service(
        cluster=cluster_name, serviceName=service_name, desiredCount=0, deploymentController={"type": "EXTERNAL"},
        tags=[{"key": "sim2real", "value": "check_task_set_primary_update_not_found_rejected"}],
    )
    ctx.on_cleanup(lambda: _delete_service_best_effort(ecs, cluster_name, service_name))

    ts = ecs.create_task_set(
        cluster=cluster_name,
        service=service_name,
        taskDefinition=td_arn,
        scale={"value": 0, "unit": "PERCENT"},
        launchType="FARGATE",
        networkConfiguration=network_configuration,
        tags=[{"key": "sim2real", "value": "check_task_set_primary_update_not_found_rejected"}],
    )["taskSet"]
    ts_id = ts["id"]
    ctx.on_cleanup(lambda: _delete_task_set_best_effort(ecs, cluster_name, service_name, ts_id))

    # positive control: making the real task set primary succeeds
    ecs.update_service_primary_task_set(cluster=cluster_name, service=service_name, primaryTaskSet=ts_id)
    # Real AWS requires an explicit `taskSets` filter on DescribeTaskSets — it does not default
    # to "all task sets for this service" and instead rejects an empty/omitted list with
    # InvalidParameterException: "TaskSets cannot be empty."
    before = ecs.describe_task_sets(cluster=cluster_name, service=service_name, taskSets=[ts_id])["taskSets"]
    assert len(before) == 1, f"expected exactly 1 task set, got {len(before)}"
    assert before[0]["status"] == "PRIMARY", f"expected the positive control to be PRIMARY, got {before[0]['status']}"

    # negative: an unknown task set ARN is rejected with the specific not-found code
    bogus_id = ts_id[:-4] + "0000" if ts_id[-4:].isdigit() else ts_id + "-bogus"
    try:
        ecs.update_service_primary_task_set(cluster=cluster_name, service=service_name, primaryTaskSet=bogus_id)
        raise AssertionError(f"UpdateServicePrimaryTaskSet accepted the unknown task set {bogus_id!r}")
    except ClientError as err:
        error = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
    expected = (
        "TaskSetNotFoundException",
        f"Unable to find task set with id {bogus_id} on service {service_name}.",
    )
    assert error == expected, f"expected {expected!r}, got {error!r}"

    # the effect must be absent: the real task set is still (and only) PRIMARY
    after = ecs.describe_task_sets(cluster=cluster_name, service=service_name, taskSets=[ts_id])["taskSets"]
    assert len(after) == 1, f"expected the rejected call to leave exactly 1 task set, got {len(after)}"
    assert after[0]["id"] == ts_id, f"expected the surviving task set to still be {ts_id}, got {after[0]['id']}"
    assert after[0]["status"] == "PRIMARY", "a rejected UpdateServicePrimaryTaskSet call must not disturb the existing PRIMARY task set"


# ===== helpers =====

def _delete_service_best_effort(ecs, cluster_name, service_name):
    from botocore.exceptions import ClientError

    try:
        ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _delete_task_set_best_effort(ecs, cluster_name, service_name, ts_id):
    from botocore.exceptions import ClientError

    try:
        ecs.delete_task_set(cluster=cluster_name, service=service_name, taskSet=ts_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
            "TaskSetNotFoundException",
        ):
            raise



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
