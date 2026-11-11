"""run-task-container-override-exit-code."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "run-task-container-override-exit-code"
GROUP = 'task'
SERVICES = ['ecs']
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0
#: The container-image prerequisite (a public image the target pulls; never pulled by the check).
CONTAINER_IMAGE = "public.ecr.aws/amazonlinux/amazonlinux:2023"

_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _own_network(ctx, n_subnets=1):
    """A check-owned VPC with public subnets in distinct AZs, an internet gateway and default
    route; returns (vpc_id, subnets, sg_id). Cleanup waits for leftover ENIs to detach."""
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


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status (any 4xx when None), the exact message and the ids
    it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    if status is None:
        assert isinstance(got_status, int) and 400 <= got_status < 500, f"expected a 4xx with {code}, got {got_status!r}"
    else:
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


def _ignore(codes, call):
    """Teardown call that tolerates the resource already being gone."""
    try:
        call()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _assert_cluster_gone(ecs, name, arn):
    """Gone beats 1-2 for a cluster: INACTIVE tombstone or MISSING, and absent from ListClusters."""
    resp = ecs.describe_clusters(clusters=[name])
    statuses = [c["status"] for c in resp.get("clusters", [])]
    missing = [f.get("reason") for f in resp.get("failures", [])]
    assert statuses == ["INACTIVE"] or (not statuses and missing == ["MISSING"]), (
        f"expected the deleted cluster INACTIVE or MISSING, got clusters {statuses!r} failures {missing!r}"
    )
    _poll_until(
        lambda: arn in [a for page in ecs.get_paginator("list_clusters").paginate()
                        for a in page.get("clusterArns", [])],
        lambda listed: not listed,
        interval_s=2,
    )


def _poll_until(fn, pred, *, timeout_s=POLL_BUDGET_S, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={val!r})")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A RunTask containerOverrides command replaces the task definition's command: the exit
    code DescribeTasks reports is the override's 42, not the default's 0."""
    ecs = ctx.client("ecs")
    _vpc_id, subnets, sg = _own_network(ctx)

    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    name = cluster["clusterName"]
    ctx.on_cleanup(lambda: _ignore(("ClusterNotFoundException",), lambda: ecs.delete_cluster(cluster=name)))

    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": CONTAINER_IMAGE,
                "essential": True,
                "command": ["sh", "-c", "exit 0"],
            }
        ],
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _ignore(("ClientException",), lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn])))
    ctx.on_cleanup(lambda: _ignore(("ClientException",), lambda: ecs.deregister_task_definition(taskDefinition=td_arn)))

    run_resp = ecs.run_task(
        cluster=name,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
        overrides={"containerOverrides": [{"name": "app", "command": ["sh", "-c", "exit 42"]}]},
    )
    assert not run_resp.get("failures"), f"unexpected RunTask failures: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _ignore(("ClusterNotFoundException", "InvalidParameterException"),
                                   lambda: ecs.stop_task(cluster=name, task=task_arn, reason="behavioral-cleanup")))

    echoed = run_resp["tasks"][0].get("overrides", {}).get("containerOverrides", [])
    assert any(
        co.get("name") == "app" and co.get("command") == ["sh", "-c", "exit 42"] for co in echoed
    ), f"expected the RunTask response to echo the container override, got {echoed}"

    def _container():
        # DescribeTasks is eventually consistent right after RunTask — the task
        # ARN (and its container records) can be briefly absent, so tolerate an
        # empty list / missing container and let the poll retry.
        tasks = ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"]
        if not tasks:
            return None
        return next((c for c in tasks[0].get("containers", []) if c.get("name") == "app"), None)

    try:
        terminal = _poll_until(
            _container,
            lambda c: c is not None and c.get("lastStatus") == "STOPPED",
        )
    except AssertionError as exc:
        # The exit code exists only if a container runtime actually ran the task.
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: task {task_arn} never ran to STOPPED, so no container "
            f"runtime executed it: {exc}"
        ) from exc
    assert terminal.get("exitCode") == 42, (
        f"expected the OVERRIDE's exit code (42), not the task definition's own default, got {terminal}"
    )
    stopped = _poll_until(
        lambda: ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"][0],
        lambda t: t.get("lastStatus") == "STOPPED",
    )
    assert stopped.get("stopCode") == "EssentialContainerExited", (
        f"expected the STOPPED task's stopCode EssentialContainerExited, got {stopped.get('stopCode')!r}"
    )

    net = {"awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}}

    # The cluster is deleted and gone: tombstone/MISSING, unlisted, and RunTask on it is refused.
    ecs.delete_cluster(cluster=name)
    _assert_cluster_gone(ecs, name, cluster["clusterArn"])
    refused = _expect_error(lambda: ecs.run_task(cluster=name, taskDefinition=td_arn, launchType="FARGATE",
                                                 networkConfiguration=net),
                            ("ClusterNotFoundException",))
    expected_message = "The referenced cluster was inactive."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    # The task definition is deleted and gone: launching it on a live cluster is refused.
    ecs.deregister_task_definition(taskDefinition=td_arn)
    ecs.delete_task_definitions(taskDefinitions=[td_arn])
    # Gone beat 1: the revision reads as its documented DELETE_IN_PROGRESS tombstone, or not at all
    # once ECS has purged it.
    try:
        td_status = ecs.describe_task_definition(taskDefinition=td_arn)["taskDefinition"].get("status")
    except ClientError as exc:
        _assert_error(exc, ("ClientException",))
    else:
        assert td_status == "DELETE_IN_PROGRESS", (
            f"expected the deleted revision's tombstone status DELETE_IN_PROGRESS, got {td_status!r}"
        )
    # Gone beat 2: the revision is absent from its family's ACTIVE listing.
    active = [a for page in ecs.get_paginator("list_task_definitions").paginate(familyPrefix=family, status="ACTIVE")
              for a in page.get("taskDefinitionArns", [])]
    assert td_arn not in active, f"expected {td_arn} absent from the ACTIVE task-definition listing, got {active!r}"
    probe = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]["clusterName"]
    ctx.on_cleanup(lambda: _ignore(("ClusterNotFoundException",), lambda: ecs.delete_cluster(cluster=probe)))
    # RunTask on a deleted revision may draw either ECS client-error code with any 4xx status.
    _expect_error(lambda: ecs.run_task(cluster=probe, taskDefinition=td_arn, launchType="FARGATE",
                                       networkConfiguration=net),
                  ("ClientException", "InvalidParameterException"), status=None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
