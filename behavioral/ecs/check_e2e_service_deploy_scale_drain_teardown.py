"""e2e-service-deploy-scale-drain-teardown."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-service-deploy-scale-drain-teardown"
GROUP = "e2e"
SERVICES = ["ecs"]
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0
#: The container-image prerequisite (a public image the target pulls; never pulled by the check).
CONTAINER_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """Service create -> scale to 3 -> drain to 0 -> delete: RUNNING counts converge at each step,
    each running task logs this run's marker, and service, cluster, log group and role are gone."""
    ecs = ctx.client("ecs")
    _vpc_id, subnets, sg = _own_network(ctx, n_subnets=2)
    net = {"subnets": subnets, "securityGroups": [sg]}

    cluster_name = ctx.unique_name("sim2real-ecs-e2e-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]

    def _cleanup_cluster() -> None:
        _ignore(("ClusterNotFoundException",), lambda: ecs.delete_cluster(cluster=cluster_arn))

    ctx.on_cleanup(_cleanup_cluster)

    logs = ctx.client("logs")
    marker = ctx.unique_name("sim2real-marker-")
    log_group = "/sim2real/" + ctx.unique_name("ecs-e2e-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: _ignore(("ResourceNotFoundException",),
                                   lambda: logs.delete_log_group(logGroupName=log_group)))
    role_name = ctx.unique_name("sim2real-ecs-exec-")
    role_arn = _create_execution_role(ctx, role_name)

    family = ctx.unique_name("sim2real-ecs-taskdef-")
    task_def_arn = _register_sleep_task_def(
        ctx, family, command=["sh", "-c", f"echo {marker}; sleep 1800"],
        log_group=log_group, execution_role_arn=role_arn,
    )

    def _cleanup_taskdef() -> None:
        _retire_task_definition(ecs, task_def_arn)

    ctx.on_cleanup(_cleanup_taskdef)

    service_name = ctx.unique_name("sim2real-ecs-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=3,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnets"],
                "securityGroups": net["securityGroups"],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )

    def _cleanup_service() -> None:
        _ignore(("ServiceNotFoundException", "ServiceNotActiveException", "ClusterNotFoundException"),
                lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))

    ctx.on_cleanup(_cleanup_service)

    def _describe_service() -> dict:
        return ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]

    try:
        scaled_up = _poll_until(
            lambda: _describe_service(),
            lambda s: s["runningCount"] == 3 and s["pendingCount"] == 0,
            ctx=ctx, interval_s=2.0,
        )
    except AssertionError as exc:
        # A service that never runs a single task means the target has no data plane.
        if _describe_service()["runningCount"] == 0:
            raise AssertionError(
                f"DATAPLANE_UNIMPLEMENTED: service {service_name} never ran a single task within "
                f"{POLL_BUDGET_S}s of desiredCount=3, so no container runtime placed its tasks"
            ) from exc
        raise
    assert scaled_up["runningCount"] == 3, f"expected runningCount=3, got {scaled_up['runningCount']}"
    assert scaled_up["desiredCount"] == 3, f"expected desiredCount=3, got {scaled_up['desiredCount']}"
    assert scaled_up["status"] == "ACTIVE", f"expected status=ACTIVE, got {scaled_up['status']!r}"

    # RUNNING is backed by its effect: every running task's container wrote this run's marker.
    running = [
        t for page in ecs.get_paginator("list_tasks").paginate(
            cluster=cluster_arn, serviceName=service_name, desiredStatus="RUNNING")
        for t in page.get("taskArns", [])
    ]
    assert len(running) == 3, f"expected 3 RUNNING tasks for {service_name}, listed {running!r}"
    for task_arn in running:
        stream = f"sim2real/app/{task_arn.rsplit('/', 1)[-1]}"
        messages = _poll_until(lambda s=stream: _stream_messages(logs, log_group, s),
                               lambda ms: any(marker in m for m in ms), ctx=ctx, interval_s=1.0)
        assert any(marker in m for m in messages), f"marker absent from {log_group}/{stream}: {messages[:5]!r}"

    ecs.update_service(cluster=cluster_arn, service=service_name, desiredCount=0)

    scaled_down = _poll_until(
        lambda: _describe_service(),
        lambda s: s["runningCount"] == 0 and s["desiredCount"] == 0,
        ctx=ctx, interval_s=2.0,
    )
    assert scaled_down["runningCount"] == 0, (
        f"expected runningCount=0 after drain, got {scaled_down['runningCount']}"
    )

    # Confirm the drain actually stopped the tasks (not merely a counter flip).
    remaining_running = [
        t for page in ecs.get_paginator("list_tasks").paginate(
            cluster=cluster_arn, serviceName=service_name, desiredStatus="RUNNING")
        for t in page.get("taskArns", [])
    ]
    assert remaining_running == [], f"expected no RUNNING tasks after drain, found {remaining_running}"

    ecs.delete_service(cluster=cluster_arn, service=service_name)

    # Service gone beat 1: an INACTIVE tombstone or a MISSING failure.
    def _service_state() -> str:
        resp = ecs.describe_services(cluster=cluster_arn, services=[service_name])
        services = resp.get("services", [])
        if services:
            return services[0]["status"]
        reasons = [f.get("reason") for f in resp.get("failures", [])]
        return "MISSING" if reasons == ["MISSING"] else f"failures={reasons!r}"

    gone_state = _poll_until(_service_state, lambda st: st in ("INACTIVE", "MISSING"), ctx=ctx)
    assert gone_state in ("INACTIVE", "MISSING"), gone_state
    # Service gone beat 2: the cluster's service listing no longer contains it.
    listed = [a for page in ecs.get_paginator("list_services").paginate(cluster=cluster_arn)
              for a in page.get("serviceArns", [])]
    assert not any(a.endswith(f"/{service_name}") for a in listed), (
        f"deleted service {service_name} still listed: {listed!r}"
    )
    # Service gone beat 3: scaling the dead service is refused.
    refused = _expect_error(lambda: ecs.update_service(cluster=cluster_arn, service=service_name, desiredCount=1),
                            ("ServiceNotActiveException", "ServiceNotFoundException"))
    expected_message = "Service was not ACTIVE."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    ecs.delete_cluster(cluster=cluster_arn)

    # Cluster gone beat 1: an INACTIVE tombstone or a MISSING failure.
    def _cluster_state() -> str:
        resp = ecs.describe_clusters(clusters=[cluster_arn])
        clusters = resp.get("clusters", [])
        if clusters:
            return clusters[0]["status"]
        reasons = [f.get("reason") for f in resp.get("failures", [])]
        return "MISSING" if reasons == ["MISSING"] else f"failures={reasons!r}"

    final = _poll_until(_cluster_state, lambda st: st in ("INACTIVE", "MISSING"), ctx=ctx)
    assert final in ("INACTIVE", "MISSING"), final
    # Cluster gone beat 2: ListClusters no longer contains it (bounded convergence).
    _poll_until(
        lambda: cluster_arn in [a for page in ecs.get_paginator("list_clusters").paginate()
                                for a in page.get("clusterArns", [])],
        lambda listed: not listed,
        ctx=ctx,
    )
    # Cluster gone beat 3: creating a service on the dead cluster is refused.
    refused = _expect_error(lambda: ecs.create_service(
                  cluster=cluster_arn, serviceName=ctx.unique_name("sim2real-ecs-svc-"), taskDefinition=task_def_arn,
                  desiredCount=0, launchType="FARGATE",
                  networkConfiguration={"awsvpcConfiguration": {"subnets": net["subnets"], "securityGroups": net["securityGroups"]}},
    ), ("ClusterNotFoundException",))
    expected_message = "The referenced cluster was inactive."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    # Log group gone: DescribeLogStreams refused, absent from DescribeLogGroups, PutLogEvents refused.
    logs.delete_log_group(logGroupName=log_group)
    refused = _expect_error(lambda: logs.describe_log_streams(logGroupName=log_group), ("ResourceNotFoundException",))
    expected_message = "The specified log group does not exist."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    listed_groups = [g["logGroupName"] for g in logs.describe_log_groups(
        logGroupNamePrefix=log_group).get("logGroups", [])]
    assert log_group not in listed_groups, f"DescribeLogGroups still lists deleted {log_group}"
    refused = _expect_error(lambda: logs.put_log_events(
                  logGroupName=log_group, logStreamName="gone",
                  logEvents=[{"timestamp": int(time.time() * 1000), "message": "gone"}],
    ), ("ResourceNotFoundException",))
    expected_message = "The specified log group does not exist."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    # Execution role gone: GetRole NoSuchEntity/404, absent from ListRoles, PutRolePolicy refused.
    iam = ctx.client("iam")
    iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY)
    iam.delete_role(RoleName=role_name)
    refused = _expect_error(lambda: iam.get_role(RoleName=role_name), ("NoSuchEntity",), status=404,
                            contains=(role_name,))
    expected_message = f"The role with name {role_name} cannot be found."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate() for r in page["Roles"]]
    assert role_name not in roles, f"ListRoles still lists deleted role {role_name}"
    refused = _expect_error(lambda: iam.put_role_policy(RoleName=role_name, PolicyName="gone", PolicyDocument=json.dumps(
                  {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:GetQueueUrl", "Resource": "*"}]}
    )), ("NoSuchEntity",), status=404)
    expected_message = f"The role with name {role_name} cannot be found."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'


_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


def _create_execution_role(ctx, name: str) -> str:
    """This run's own ECS task execution role (awslogs delivery); detach+delete registered."""
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=_NET_TAGS)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore(("NoSuchEntity",), lambda: iam.delete_role(RoleName=name)))
    iam.attach_role_policy(RoleName=name, PolicyArn=_EXEC_POLICY)
    ctx.on_cleanup(lambda: _ignore(("NoSuchEntity",),
                                   lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_EXEC_POLICY)))
    return arn


def _stream_messages(logs, group: str, stream: str) -> list:
    """Every message in one log stream, oldest first; [] while it does not exist yet."""
    try:
        events = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return []
        raise
    return [e["message"] for e in events["events"]]


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


def _ignore(codes, call):
    """Teardown call that tolerates the resource already being gone."""
    try:
        call()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, ctx=None, timeout_s=POLL_BUDGET_S, interval_s=1.0):
    """Probe every interval_s until predicate holds, within timeout_s and ctx's time left."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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


def _register_sleep_task_def(ctx, family, command=None, log_group=None, execution_role_arn=None):
    ecs = ctx.client("ecs")
    container = {
        "name": "app",
        "image": CONTAINER_IMAGE,
        "command": command or ["sleep", "1800"],
        "essential": True,
    }
    if log_group:
        container["logConfiguration"] = {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group,
                "awslogs-region": ctx.region,
                "awslogs-stream-prefix": "sim2real",
            },
        }
    kwargs: dict = dict(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[container],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    if execution_role_arn:
        kwargs["executionRoleArn"] = execution_role_arn
    resp = ecs.register_task_definition(**kwargs)
    return resp["taskDefinition"]["taskDefinitionArn"]


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
