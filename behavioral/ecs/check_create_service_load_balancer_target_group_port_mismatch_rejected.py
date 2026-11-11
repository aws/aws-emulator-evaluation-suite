"""create-service-load-balancer-target-group-port-mismatch-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-service-load-balancer-target-group-port-mismatch-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateService rejects a load balancer entry whose containerPort has no matching port mapping."""
    ecs = ctx.client("ecs")
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)

    tg_name = ctx.unique_name("sim2realtg")[:32].rstrip("-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    # ECS validates that a service's target group has an associated load balancer, so build a
    # real (throwaway) ALB + listener in front of it -- a bare target group is rejected too, but
    # for a different reason than the port mismatch this check targets.
    lb_name = ctx.unique_name("sim2real-lb")[:32].rstrip("-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    cluster_name = ctx.unique_name("sim2real-ecs-lbmismatch-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "behavioral"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-ecs-lbmismatch-td-")
    task_def = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["EC2"],
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "memory": 128,
                "essential": True,
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
            }
        ],
        tags=[{"key": "sim2real", "value": "behavioral"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[task_def["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=task_def["taskDefinitionArn"]))

    bad_service_name = ctx.unique_name("sim2real-ecs-lbmismatch-svc-")
    code, message = _error(
        lambda: ecs.create_service(
            cluster=cluster_arn,
            serviceName=bad_service_name,
            taskDefinition=task_def["taskDefinitionArn"],
            desiredCount=0,
            launchType="EC2",
            loadBalancers=[{"targetGroupArn": tg_arn, "containerName": "app", "containerPort": 9999}],
        )
    )
    if code != "InvalidParameterException":
        raise AssertionError(repr(code))
    expected_message = "The container app did not have a container port 9999 defined."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no service object was created.
    described = ecs.describe_services(cluster=cluster_arn, services=[bad_service_name])
    assert described["services"] == [], "a service was created despite the load balancer port mismatch"
    failures = described.get("failures", [])
    assert any(f.get("reason") == "MISSING" for f in failures), (
        f"expected a MISSING failure for {bad_service_name!r}, got {failures!r}"
    )

    # Positive control: a containerPort that matches the declared port mapping is accepted.
    good_service_name = ctx.unique_name("sim2real-ecs-lbmismatch-ok-")
    good = ecs.create_service(
        cluster=cluster_arn,
        serviceName=good_service_name,
        taskDefinition=task_def["taskDefinitionArn"],
        desiredCount=0,
        launchType="EC2",
        loadBalancers=[{"targetGroupArn": tg_arn, "containerName": "app", "containerPort": 80}],
        tags=[{"key": "sim2real", "value": "behavioral"}],
    )["service"]
    ctx.on_cleanup(lambda: _delete_service_and_wait(ecs, cluster_arn, good["serviceArn"]))

    # Terminal read is independent of the create_service response that produced `good`.
    described_good = ecs.describe_services(cluster=cluster_arn, services=[good_service_name])["services"]
    assert described_good, f"good service not visible via an independent describe_services: {good_service_name!r}"
    assert described_good[0]["status"] == "ACTIVE", (
        f"expected ACTIVE via describe_services, got {described_good[0]['status']!r}"
    )
    assert described_good[0]["loadBalancers"][0]["containerPort"] == 80, described_good[0]["loadBalancers"]


# ===== helpers =====
def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to create the target group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in at least two AZs for an ALB")
    return vpc_id, list(by_az.values())[:2]


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


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
