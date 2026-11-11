"""ecs-service-reaches-steady-state."""
from __future__ import annotations

import time


from behavioral_harness import tags

CHECK = "ecs-service-reaches-steady-state"
GROUP = 'service-steady-state'
SERVICES = ['ecs']

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": ["sh", "-c", "sleep 3600"],
    }
]

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Fargate service (desired 1) is created ACTIVE with desiredCount echoed, DescribeServices
    reports the same, and after DeleteService it reads back INACTIVE. Running-count convergence is
    not observed here.
    """
    ecs = ctx.client("ecs")
    try:
        iam = ctx.client("iam")
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception as exc:  # noqa: BLE001 — already-exists is success
        msg = str(exc).lower()
        if "has been taken" not in msg and "already" not in msg and "invalidinput" not in msg:
            raise
    ec2 = ctx.client("ec2")
    _vpcs = ec2.describe_vpcs(
        Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]
    ).get("Vpcs", [])
    if not _vpcs:
        raise AssertionError("no shared network VPC available for Fargate tasks")
    subnets = [
        s["SubnetId"]
        for s in ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [_vpcs[0]["VpcId"]]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        ).get("Subnets", [])
    ]
    if not subnets:
        raise AssertionError("shared network has no network subnets")
    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    cluster_name = cluster["clusterName"]
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    service_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    svc = ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnets, "assignPublicIp": "ENABLED"}
        },
    )["service"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))
    assert svc["status"] == "ACTIVE", svc["status"]
    assert svc["desiredCount"] == 1

    described = ecs.describe_services(
        cluster=cluster_name, services=[service_name]
    ).get("services", [])
    assert described, "created service missing from DescribeServices"
    assert described[0]["status"] == "ACTIVE", described[0]["status"]
    assert described[0]["desiredCount"] == 1, described[0].get("desiredCount")

    # Drain the service before the cluster is deleted, and prove the delete
    # actually took effect via an independent read rather than merely not raising.
    try:
        ecs.update_service(cluster=cluster_name, service=service_name, desiredCount=0)
    except Exception:
        pass
    ecs.delete_service(cluster=cluster_name, service=service_name, force=True)

    _deadline = time.monotonic() + 180
    _final_status = "ACTIVE"
    while True:
        _svcs = ecs.describe_services(
            cluster=cluster_name, services=[service_name]
        ).get("services") or [{}]
        _final_status = _svcs[0].get("status", "INACTIVE")
        if _final_status == "INACTIVE":
            break
        if time.monotonic() >= _deadline:
            break
        time.sleep(5)
    assert _final_status == "INACTIVE", (
        f"service did not reach INACTIVE within {180}s of delete_service, got {_final_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
