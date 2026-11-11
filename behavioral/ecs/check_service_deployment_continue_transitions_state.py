"""service-deployment-continue-transitions-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-deployment-continue-transitions-state"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A BLUE_GREEN service deployment created with a PRE_SCALE_UP pause hook actually pauses
    (AWAITING_ACTION), and ContinueServiceDeployment advances the hook past that stage."""
    ecs = ctx.client("ecs")
    net = _own_network(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-bg-cluster-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_empty(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-behav-bg-task-")
    task_def = _register_sleep_task_def(ctx, family)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": net["subnet_ids"],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }

    # Trigger the PRE_SCALE_UP pause hook on the service's VERY FIRST (creation)
    # deployment rather than creating a plain service, waiting for it to reach
    # steady state, and THEN updating it into a BLUE_GREEN deployment. On real
    # AWS the initial steady-state wait plus the BLUE_GREEN update's own
    # infrastructure provisioning can together exceed the runner's overall
    # per-check timeout; a hook pause is a lifecycle checkpoint of the
    # deployment strategy itself and fires just as well on the first
    # (0 -> desiredCount) deployment, so folding the two into one deployment
    # keeps the whole check within budget without weakening what's asserted.
    service_name = ctx.unique_name("sim2real-behav-bg-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        deploymentConfiguration={
            "strategy": "BLUE_GREEN",
            "lifecycleHooks": [{"targetType": "PAUSE", "lifecycleStages": ["PRE_SCALE_UP"]}],
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True)
        )
    )

    deployment_arn = _poll_until(
        lambda: _latest_deployment_arn(ecs, cluster_arn, service_name),
        lambda arn: arn is not None,
        timeout_s=30,
        interval_s=3,
    )

    paused = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])[
            "serviceDeployments"
        ][0],
        lambda d: any(h["status"] == "AWAITING_ACTION" for h in d.get("lifecycleHookDetails", [])),
        timeout_s=200,
        interval_s=5,
    )
    hook = next(h for h in paused["lifecycleHookDetails"] if h["status"] == "AWAITING_ACTION")
    assert paused["status"] in ("PENDING", "IN_PROGRESS"), (
        f"expected the deployment to still be in-flight while its hook awaits action, "
        f"got status={paused['status']!r}"
    )

    ecs.continue_service_deployment(
        serviceDeploymentArn=deployment_arn, hookId=hook["hookId"], action="CONTINUE"
    )

    resolved_status = _poll_until(
        lambda: _hook_status(ecs, deployment_arn, hook["hookId"]),
        lambda s: s in ("SUCCEEDED", "FAILED", "TIMED_OUT"),
        timeout_s=40,
        interval_s=5,
    )
    assert resolved_status == "SUCCEEDED", (
        f"expected ContinueServiceDeployment(action=CONTINUE) to resolve the PRE_SCALE_UP hook "
        f"as SUCCEEDED, got {resolved_status!r}"
    )


# ===== helpers =====
def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
    from botocore.exceptions import ClientError

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


def _delete_cluster_when_empty(ecs, cluster_arn, timeout_s=240.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterContainsTasksException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _register_sleep_task_def(ctx, family):
    ecs = ctx.client("ecs")
    return ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "command": ["sleep", "1800"],
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]


def _latest_deployment_arn(ecs, cluster_arn, service_name):
    deployments = ecs.list_service_deployments(cluster=cluster_arn, service=service_name).get(
        "serviceDeployments", []
    )
    if not deployments:
        return None
    deployments.sort(key=lambda d: d.get("createdAt", 0), reverse=True)
    return deployments[0]["serviceDeploymentArn"]


def _hook_status(ecs, deployment_arn, hook_id):
    deployment = ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])[
        "serviceDeployments"
    ][0]
    for hook in deployment.get("lifecycleHookDetails", []):
        if hook["hookId"] == hook_id:
            return hook["status"]
    return None


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
