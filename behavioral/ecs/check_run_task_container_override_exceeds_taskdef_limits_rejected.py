"""run-task-container-override-exceeds-taskdef-limits-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-task-container-override-exceeds-taskdef-limits-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0
#: The container-image prerequisite (a public image the target pulls; never pulled by the check).
CONTAINER_IMAGE = "public.ecr.aws/amazonlinux/amazonlinux:2023"


# The refusal is a synchronous control-plane validation; cap:c3 is the positive control's Fargate task.
@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask rejects a container memory override greater than the task memory."""
    ecs = ctx.client("ecs")
    _vpc_id, subnets, sg_id = _own_network(ctx)
    subnet_id = subnets[0]

    cluster_name = ctx.unique_name("sim2real-ecs-override-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-ecs-override-td-")
    task_def = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": CONTAINER_IMAGE,
                "memory": 256,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def["taskDefinitionArn"]))

    net_config = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id] if sg_id else [],
            "assignPublicIp": "ENABLED",
        }
    }

    refused = _expect_error(
                  lambda: ecs.run_task(
                      cluster=cluster_arn,
                      taskDefinition=task_def["taskDefinitionArn"],
                      launchType="FARGATE",
                      networkConfiguration=net_config,
                      overrides={"containerOverrides": [{"name": "app", "memory": 4096}]},
                      count=1,
        ),
                  ("InvalidParameterException",),
                  contains=("app",),
    )
    expected_message = "'memory' setting for container 'app' is greater than for task."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    # Effect absent: no task was launched under this family.
    task_arns = ecs.list_tasks(cluster=cluster_arn, family=family)["taskArns"]
    assert task_arns == [], "a task was launched despite the out-of-range container override"

    # Positive control: an override within the declared hard limit succeeds.
    good = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def["taskDefinitionArn"],
        launchType="FARGATE",
        networkConfiguration=net_config,
        overrides={"containerOverrides": [{"name": "app", "memory": 128}]},
        count=1,
        tags=[{"key": "sim2real", "value": "true"}],
    )
    # Placing a task needs a real container runtime; a target that accepts RunTask but places
    # nothing has no data plane.
    assert good["tasks"], (
        f"DATAPLANE_UNIMPLEMENTED: RunTask placed no task for an in-range override, so no container "
        f"runtime is behind the API; failures={good.get('failures')}"
    )
    task_arn = good["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_task_and_wait(ecs, cluster_arn, task_arn))

    # Terminal read is independent of the mutating RunTask call: the accepted override's
    # task must actually be visible through ListTasks, not just echoed in RunTask's own response.
    listed = ecs.list_tasks(cluster=cluster_arn, family=family)["taskArns"]
    assert task_arn in listed, (
        f"expected {task_arn} to appear in list_tasks after the in-range override was accepted, got {listed}"
    )


# ===== helpers =====
def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _own_network(ctx, n_subnets=1):
    """A check-owned VPC: public subnet(s) in distinct AZs, an internet gateway with a
    default route, and the VPC's own default security group. Returns (vpc_id, subnets, sg_id).

    One code path on every target; one cleanup tears it all down in dependency order once the
    ENIs the workload left behind have detached."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    subnets: list = []
    igw_id = None

    def _teardown_network():
        deadline = time.monotonic() + POLL_BUDGET_S
        for subnet_id in subnets:
            while True:
                if not ec2.describe_network_interfaces(
                    Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
                ).get("NetworkInterfaces"):
                    break
                if time.monotonic() > deadline:
                    raise AssertionError(f"ENIs still attached in {subnet_id}; network not torn down")
                time.sleep(2)
            _retry_dependency(lambda s=subnet_id: ec2.delete_subnet(SubnetId=s), deadline,
                              gone=("InvalidSubnetID.NotFound",))
        if igw_id:
            _retry_dependency(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
                              deadline, gone=("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"))
            _retry_dependency(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id), deadline,
                              gone=("InvalidInternetGatewayID.NotFound",))
        _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id), deadline, gone=("InvalidVpcID.NotFound",))

    ctx.on_cleanup(_teardown_network)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    # The AZs' region is an EC2 fact graded by the EC2 members, not by this prerequisite.
    assert len(zones) >= n_subnets, f"expected {n_subnets} available AZs, got {zones!r}"
    for i, az in enumerate(zones[:n_subnets]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.198.0.{i * 64}/26",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
        )["Subnet"]["SubnetId"]
        subnets.append(subnet_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]
        if sg["GroupName"] == "default"
    )
    return vpc_id, subnets, sg_id


def _retry_dependency(call, deadline, *, gone=()):
    """Run a teardown call, retrying while a dependency (a detaching ENI) still blocks it."""
    while True:
        try:
            call()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in gone:
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _delete_cluster(ecs, cluster: str) -> None:
    """Stop any task a target launched (an accepted refusal included), then delete the cluster."""
    for page in ecs.get_paginator("list_tasks").paginate(cluster=cluster):
        for task in page.get("taskArns", []):
            ecs.stop_task(cluster=cluster, task=task, reason="sim2real-cleanup")
    ecs.delete_cluster(cluster=cluster)


def _stop_task_and_wait(ecs, cluster_arn, task_arn, timeout_s=120.0):
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if not tasks or tasks[0]["lastStatus"] == "STOPPED":
            return
        time.sleep(3)


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
