"""update-service-network-configuration-wrong-network-mode-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-service-network-configuration-wrong-network-mode-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateService rejects a networkConfiguration for a service whose task def isn't awsvpc."""
    ecs = ctx.client("ecs")
    _, subnet_id, sg_id = _default_subnet_and_sg(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-netmode-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-ecs-netmode-td-")
    task_def = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["EC2"],
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def["taskDefinitionArn"]))

    service_name = ctx.unique_name("sim2real-ecs-netmode-svc-")
    service = ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def["taskDefinitionArn"],
        desiredCount=0,
        launchType="EC2",
        tags=[{"key": "sim2real", "value": "true"}],
    )["service"]
    ctx.on_cleanup(lambda: _delete_service_and_wait(ecs, cluster_arn, service["serviceArn"]))
    assert service.get("networkConfiguration") is None, (
        f"newly created bridge-mode service already had a networkConfiguration: {service.get('networkConfiguration')!r}"
    )

    code, message = _error(
        lambda: ecs.update_service(
            cluster=cluster_arn,
            service=service_name,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [subnet_id],
                    "securityGroups": [sg_id] if sg_id else [],
                }
            },
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected_message = "Network Configuration is not valid for the given networkMode of this task definition."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the service's network configuration is still unset.
    described = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
    assert described.get("networkConfiguration") is None, "networkConfiguration was applied to a bridge-mode service"

    # Positive control: an update that doesn't touch networkConfiguration succeeds, proving the
    # earlier rejection was specific to networkConfiguration rather than the service being wedged.
    ecs.update_service(cluster=cluster_arn, service=service_name, desiredCount=1)
    after_good = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
    assert after_good["status"] == "ACTIVE", (
        f"service was not ACTIVE via an independent read after the accepted update: {after_good['status']!r}"
    )
    assert after_good["desiredCount"] == 1, (
        f"desiredCount did not reach 1 via an independent read after the accepted update: "
        f"{after_good['desiredCount']!r}"
    )


# ===== helpers =====
def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _default_subnet_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to build an awsvpc network configuration")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for an awsvpc network configuration")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return vpc_id, subnet_id, sg_id


def _delete_service_and_wait(ecs, cluster_arn, service_arn, timeout_s=90.0):
    try:
        ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_services(cluster=cluster_arn, services=[service_arn])
        services = resp.get("services", [])
        if not services or services[0]["status"] == "INACTIVE":
            return
        time.sleep(3)



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
