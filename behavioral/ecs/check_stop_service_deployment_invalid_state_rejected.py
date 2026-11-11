"""stop-service-deployment-invalid-state-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "stop-service-deployment-invalid-state-rejected"
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


_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _own_network(ctx):
    """Create a dedicated VPC with one public subnet (internet gateway + default route,
    so a Fargate task can pull a public-ECR image) and return
    {"vpc_id", "subnet_ids", "sg_id"} using that VPC's own default security group.

    One cleanup tears the stack down; it is registered before any ECS resource, so it
    runs last and first waits out the Fargate ENIs that linger after tasks stop."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    state = {"subnet_id": None, "igw_id": None}

    def _teardown_network():
        deadline = time.monotonic() + 540
        subnet_id, igw_id = state["subnet_id"], state["igw_id"]
        if subnet_id:
            while time.monotonic() < deadline:
                enis = ec2.describe_network_interfaces(
                    Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
                ).get("NetworkInterfaces", [])
                if not enis:
                    break
                time.sleep(10)
            while True:
                try:
                    ec2.delete_subnet(SubnetId=subnet_id)
                    break
                except ClientError as exc:
                    if exc.response["Error"]["Code"] == "InvalidSubnetID.NotFound":
                        break
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(10)
        if igw_id:
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        while True:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                    break
                if time.monotonic() >= deadline:
                    raise
                time.sleep(10)

    ctx.on_cleanup(_teardown_network)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.198.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    state["subnet_id"] = subnet_id
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    state["igw_id"] = igw_id
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]
    return {"vpc_id": vpc_id, "subnet_ids": [subnet_id], "sg_id": sg_id}


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_cluster(ecs, cluster_name):
    """Delete the cluster, waiting out ClusterContainsTasksException while stopped tasks drain."""
    deadline = time.monotonic() + 300
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterContainsTasksException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopServiceDeployment on a completed deployment is rejected with ConflictException and leaves
    its status unchanged; the same call on an IN_PROGRESS deployment succeeds, so the rejection
    targets the SUCCESSFUL state.
    """
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster_name))

    # --- positive control: an EC2-launchType service with no container
    # instances to place on stays genuinely IN_PROGRESS forever, so
    # StopServiceDeployment against it must succeed. ---
    stuck_family = ctx.unique_name("sim2real-behav-ecs-taskdef-stuck-")
    stuck_td = ecs.register_task_definition(
        family=stuck_family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "memory": 128,
                "essential": True,
            }
        ],
    )["taskDefinition"]
    stuck_td_arn = stuck_td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[stuck_td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=stuck_td_arn))

    stuck_service_name = ctx.unique_name("sim2real-behav-ecs-svc-stuck-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=stuck_service_name,
        taskDefinition=stuck_td_arn,
        desiredCount=1,
        launchType="EC2",
    )
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster_name, service=stuck_service_name, force=True)
    )

    stuck_deployment_arn = _poll_until(
        lambda: ecs.list_service_deployments(cluster=cluster_name, service=stuck_service_name).get(
            "serviceDeployments", []
        ),
        lambda ds: len(ds) > 0,
        timeout_s=60,
        interval_s=3,
        description="the capacity-less service's deployment becomes listable",
    )[0]["serviceDeploymentArn"]

    stuck_status = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[stuck_deployment_arn])[
            "serviceDeployments"
        ][0],
        lambda d: d["status"] in ("PENDING", "IN_PROGRESS"),
        timeout_s=30,
        interval_s=3,
        description="the capacity-less deployment to stay genuinely in-progress",
    )
    assert stuck_status["status"] in ("PENDING", "IN_PROGRESS"), (
        f"expected the capacity-less EC2 service to stay in-flight, got {stuck_status['status']}"
    )

    resp = ecs.stop_service_deployment(serviceDeploymentArn=stuck_deployment_arn)
    assert resp.get("serviceDeploymentArn") == stuck_deployment_arn, (
        f"expected StopServiceDeployment to succeed on a genuinely in-progress deployment, got {resp!r}"
    )
    # Poll past the transient STOP_REQUESTED / ROLLBACK_IN_PROGRESS states to a terminal one.
    stopped_stuck = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[stuck_deployment_arn])[
            "serviceDeployments"
        ][0],
        lambda d: d["status"] in ("STOPPED", "SUCCESSFUL", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED"),
        timeout_s=300,
        interval_s=5,
        description="the stopped deployment to reach a terminal state",
    )
    # A service's first deployment has no earlier revision to roll back to, so the
    # user-requested rollback ends in ROLLBACK_FAILED.
    assert stopped_stuck["status"] == "ROLLBACK_FAILED", (
        f"expected the stopped first deployment to end in ROLLBACK_FAILED, got {stopped_stuck!r}"
    )
    assert stopped_stuck.get("statusReason") == "No rollback candidate was found to run the rollback.", (
        f"unexpected statusReason on the stopped deployment: {stopped_stuck!r}"
    )
    assert stopped_stuck.get("rollback", {}).get("reason") == "Service deployment rolled back by user.", (
        f"unexpected rollback reason on the stopped deployment: {stopped_stuck!r}"
    )

    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))
    net = _own_network(ctx)
    subnets, sg = net["subnet_ids"], net["sg_id"]

    service_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))

    deployment_arn = _poll_until(
        lambda: ecs.list_service_deployments(cluster=cluster_name, service=service_name).get(
            "serviceDeployments", []
        ),
        lambda ds: len(ds) > 0,
        timeout_s=60,
        interval_s=3,
        description="the initial deployment becomes listable",
    )[0]["serviceDeploymentArn"]

    completed = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])[
            "serviceDeployments"
        ][0],
        lambda d: d["status"] in ("SUCCESSFUL", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED", "STOPPED"),
        timeout_s=300,
        interval_s=5,
        description="the initial deployment completes",
    )
    assert completed["status"] == "SUCCESSFUL", (
        f"expected the initial deployment to complete, got {completed['status']}"
    )

    code, message = _error(lambda: ecs.stop_service_deployment(serviceDeploymentArn=deployment_arn))
    assert code == "ConflictException", (
        f"expected ConflictException stopping an already-completed deployment, got {code}"
    )
    expected_message = f"ServiceDeployment is stopping or has already finished for arn: {deployment_arn}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still = ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])[
        "serviceDeployments"
    ][0]
    assert still["status"] == "SUCCESSFUL", (
        f"expected the deployment status to remain unchanged after the rejected stop, got {still['status']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
