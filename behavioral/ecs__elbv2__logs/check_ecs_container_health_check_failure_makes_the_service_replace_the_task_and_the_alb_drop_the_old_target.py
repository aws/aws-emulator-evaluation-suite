"""ecs-container-health-check-failure-makes-the-service-replace-the-task-and-the-alb-drop-the-old-target."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "ecs-container-health-check-failure-makes-the-service-replace-the-task-and-the-alb-drop-the-old-target"
)

GROUP = "service-steady-state"

SERVICES = ["ecs", "elbv2", "logs"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A failing container HEALTHCHECK drives replacement all the way out to the ALB target set.
    The task goes UNHEALTHY, ECS replaces it, the old IP leaves the target group and the new one is
    healthy, and HTTP through the ALB answers 200 before and after.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/healthcheck.html
    """
    ecs = ctx.client("ecs")
    vpc_id, subnets = _public_vpc(ctx, min_subnets=2)
    subnets = subnets[:2]
    alb_sg = _open_http_sg(ctx, vpc_id, 80, cidrs=ctx.ingress_cidrs())
    task_sg = _open_http_sg(ctx, vpc_id, 80, source_sg=alb_sg)
    log_group = _create_log_group(ctx)
    _role, exec_role = _iam_role(
        ctx,
        "ecs-exec",
        "ecs-tasks.amazonaws.com",
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
    )
    cluster = _create_cluster(ctx)

    marker = "sim2real-hc-" + ctx.unique_name("")[:10]
    td = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
                "command": _breakable_httpd_command(marker),
                "healthCheck": {
                    "command": ["CMD-SHELL", "test -f /tmp/healthy"],
                    "interval": 5,
                    "timeout": 2,
                    "retries": 2,
                    "startPeriod": 30,
                },
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=exec_role,
    )

    tg = _create_target_group(ctx, vpc_id)
    tg_arn = tg["TargetGroupArn"]
    lb = _create_alb(ctx, subnets, [alb_sg])
    _create_listener(ctx, lb["LoadBalancerArn"], tg_arn)

    svc = _create_fargate_service(
        ctx,
        cluster,
        td["taskDefinitionArn"],
        subnets,
        desired_count=1,
        sg_ids=[task_sg],
        load_balancers=[
            {"targetGroupArn": tg_arn, "containerName": "app", "containerPort": 80}
        ],
        # Short, so the scheduler acts on the UNHEALTHY container soon after the break; `/`
        # answers 200 from the first second, so the ALB check never needs the grace.
        health_check_grace_period_seconds=10,
        # 0/200 so the scheduler is free to stop the unhealthy task without waiting for a
        # replacement first; the HTTP assertions are taken before the break and after the new
        # target is healthy, never during the gap.
        deployment_configuration={"minimumHealthyPercent": 0, "maximumPercent": 200},
    )
    service = svc["serviceName"]

    tasks = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 1,
        timeout_s=_budget_s(ctx, 600),
        interval_s=1,
        description=f"service {service} has 1 RUNNING task",
        ctx=ctx,
    )
    old_task_arn = tasks[0]["taskArn"]
    old_ip = _task_private_ip(tasks[0])
    assert old_ip, (
        f"the first task has no awsvpc private IP: {tasks[0].get('attachments')!r}"
    )
    _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: h.get(old_ip) == "healthy",
        timeout_s=_budget_s(ctx, 600),
        interval_s=1,
        description=f"target {old_ip} healthy in {tg_arn}",
        ctx=ctx,
    )
    # The container's own probe must be passing first, or "it went UNHEALTHY" says nothing.
    _poll_until(
        lambda: _container_health(ctx, cluster, old_task_arn),
        lambda h: h == "HEALTHY",
        timeout_s=_budget_s(ctx, 420),
        interval_s=1,
        description=f"container healthStatus HEALTHY on {old_task_arn}",
        ctx=ctx,
    )

    url = "http://" + lb["DNSName"] + "/"
    first_status, first_body = _poll_until(
        lambda: _http_get(ctx, url),
        lambda r: r[0] == 200,
        timeout_s=_budget_s(ctx, 420),
        interval_s=1,
        description=f"HTTP 200 through the load balancer at {url}",
        ctx=ctx,
    )
    assert first_status == 200 and marker in first_body, (
        f"the service was not serving its own body before the break: "
        f"{first_status!r} {first_body!r}"
    )

    # --- The act: break the container's health probe from outside, over HTTP.
    break_status, break_body = _poll_until(
        lambda: _http_get(ctx, url + "cgi-bin/break"),
        lambda r: r[0] == 200,
        timeout_s=_budget_s(ctx, 180),
        interval_s=1,
        description=f"the /cgi-bin/break endpoint answering at {url}",
        ctx=ctx,
    )
    assert f"{marker}-BREAK-OK" in break_body, (
        f"the break endpoint did not confirm it removed the sentinel: "
        f"{break_status!r} {break_body!r}"
    )

    unhealthy_seen = _poll_until(
        lambda: _container_health(ctx, cluster, old_task_arn),
        lambda h: h in ("UNHEALTHY", "GONE"),
        timeout_s=_budget_s(ctx, 420),
        interval_s=1,
        description=f"container healthStatus UNHEALTHY on {old_task_arn}",
        ctx=ctx,
    )
    assert unhealthy_seen == "UNHEALTHY", (
        f"the container health check never reported UNHEALTHY after the break — the task went "
        f"away without the probe ever failing, so the replacement is not attributable to it "
        f"(last observed {unhealthy_seen!r})"
    )

    new_tasks = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 1 and ts[0]["taskArn"] != old_task_arn,
        timeout_s=_budget_s(ctx, 900),
        interval_s=1,
        description=f"service {service} back to one RUNNING task with a different arn",
        ctx=ctx,
    )
    new_task_arn = new_tasks[0]["taskArn"]
    new_ip = _task_private_ip(new_tasks[0])
    assert new_task_arn != old_task_arn, (
        f"the service never replaced the unhealthy task (still {old_task_arn!r})"
    )
    assert new_ip, f"the replacement task has no awsvpc private IP: {new_tasks[0]!r}"

    healthy_ids_after = _poll_until(
        lambda: {k for k, v in _target_health(ctx, tg_arn).items() if v == "healthy"},
        lambda ids: ids == {new_ip},
        timeout_s=_budget_s(ctx, 600),
        interval_s=1,
        description=f"the only healthy target is the replacement task {new_ip}",
        ctx=ctx,
    )
    assert old_ip not in healthy_ids_after, (
        f"the ALB still lists the replaced task's IP as healthy: {healthy_ids_after!r} "
        f"(old {old_ip!r})"
    )
    assert new_ip in healthy_ids_after, (
        f"the replacement task never became a healthy target: {healthy_ids_after!r} "
        f"(new {new_ip!r})"
    )

    last_status, last_body = _poll_until(
        lambda: _http_get(ctx, url),
        lambda r: r[0] == 200,
        timeout_s=_budget_s(ctx, 420),
        interval_s=1,
        description=f"HTTP 200 through the load balancer after self-healing at {url}",
        ctx=ctx,
    )
    assert last_status == 200 and marker in last_body, (
        f"the service does not serve after self-healing: {last_status!r} {last_body!r}"
    )

    # A witness independent of the ALB: the replacement container really booted its own httpd,
    # read out of the replacement task's own log stream rather than inferred from a response.
    new_stream = f"ecs/app/{new_task_arn.rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, log_group, new_stream, timeout_s=420)
    new_msgs = _poll_until(
        lambda: _log_messages(ctx, log_group, new_stream),
        lambda ms: any(f"{marker} httpd-start" in m for m in ms),
        timeout_s=_budget_s(ctx, 420),
        interval_s=1,
        description=f"the replacement container's start line in {new_stream}",
        ctx=ctx,
    )
    assert any(f"{marker} httpd-start" in m for m in new_msgs), new_msgs


def _container_health(ctx, cluster, task_arn) -> str:
    """The essential container's healthStatus, or 'GONE' once the task is no longer describable.

    'GONE' lets the poll stop and the assertion fail if a task vanishes without going UNHEALTHY."""
    found = (
        ctx.client("ecs")
        .describe_tasks(cluster=cluster, tasks=[task_arn])
        .get("tasks", [])
    )
    if not found:
        return "GONE"
    task = found[0]
    for c in task.get("containers", []):
        if c.get("name") == "app":
            return c.get("healthStatus") or "UNKNOWN"
    return "GONE"


def _breakable_httpd_command(marker: str) -> list[str]:
    """busybox httpd on :80 serving "<marker> <hostname>" at / and a CGI /cgi-bin/break that removes
    the healthCheck sentinel; `/` keeps answering 200 so the ALB health check never causes the
    replacement."""
    return [
        "sh",
        "-c",
        "\n".join(
            [
                "mkdir -p /www/cgi-bin",
                f'echo "{marker} $(hostname)" > /www/index.html',
                "cat > /www/cgi-bin/break <<'EOF'",
                "#!/bin/sh",
                "rm -f /tmp/healthy",
                'echo "Content-Type: text/plain"',
                "echo",
                f"echo {marker}-BREAK-OK",
                "EOF",
                "chmod +x /www/cgi-bin/break",
                "touch /tmp/healthy",
                f'echo "{marker} httpd-start $(hostname)"',
                "exec httpd -f -v -p 80 -h /www",
            ]
        ),
    ]


# ECR Public busybox: a tiny multi-arch image an anonymous Fargate pull can always fetch, so a
# check about the container runtime is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    """Run one teardown call: a resource already gone is fine; any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ListenerNotFound",
            "LoadBalancerNotFound",
            "NoSuchEntity",
            "ResourceNotFoundException",
            "ServiceNotActiveException",
            "ServiceNotFoundException",
            "TargetGroupNotFound",
        ):
            raise


def _safe(fn):
    """Run fn() and return its result, or None if it raised (probe helper)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _public_vpc(ctx, min_subnets=1):
    """(vpc_id, subnet_ids) of a new VPC with one public subnet per AZ, an internet gateway and a
    default route, so a Fargate task with a public IP can pull its image. No NAT gateway or EIP;
    teardown waits for task ENIs to detach."""
    ec2 = ctx.client("ec2")

    def _tag_spec(resource_type):
        tags = [{"Key": "Name", "Value": ctx.unique_name(_XSVC_PREFIX + "net-")}] + _tags_kv()
        return [{"ResourceType": resource_type, "Tags": tags}]

    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    if len(zones) < min_subnets:
        raise AssertionError(f"region {ctx.region} offers {zones!r}; need {min_subnets} zones")
    vpc_id = ec2.create_vpc(CidrBlock="10.87.0.0/16", TagSpecifications=_tag_spec("vpc"))["Vpc"]["VpcId"]
    made: dict = {"subnets": [], "igw": None, "rt": None}

    def _teardown():
        _leaks: list = []
        deadline = time.monotonic() + 600
        while made["subnets"] and time.monotonic() < deadline:
            if not ec2.describe_network_interfaces(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("NetworkInterfaces"):
                break
            time.sleep(2)
        steps = [lambda s=s: ec2.delete_subnet(SubnetId=s) for s in made["subnets"]]
        if made["rt"]:
            steps.append(lambda: ec2.delete_route_table(RouteTableId=made["rt"]))
        if made["igw"]:
            steps.append(lambda: ec2.detach_internet_gateway(InternetGatewayId=made["igw"], VpcId=vpc_id))
            steps.append(lambda: ec2.delete_internet_gateway(InternetGatewayId=made["igw"]))
        steps.append(lambda: ec2.delete_vpc(VpcId=vpc_id))
        for step in steps:
            while True:
                try:
                    step()
                    break
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code.endswith("NotFound") or code == "Gateway.NotAttached":
                        break
                    if code != "DependencyViolation" or time.monotonic() >= deadline:
                        _leaks.append((f"VPC {vpc_id} teardown step failed: {code}", exc))
                        break
                    time.sleep(2)
        if _leaks:
            raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                (e for _, e in _leaks if e is not None), None
            )

    ctx.on_cleanup(_teardown)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw = ec2.create_internet_gateway(TagSpecifications=_tag_spec("internet-gateway"))[
        "InternetGateway"]["InternetGatewayId"]
    made["igw"] = igw
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    rt = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=_tag_spec("route-table"))[
        "RouteTable"]["RouteTableId"]
    made["rt"] = rt
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    for i, az in enumerate(zones[:max(min_subnets, 1)]):
        sn = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.87.{i}.0/24", AvailabilityZone=az,
                               TagSpecifications=_tag_spec("subnet"))["Subnet"]["SubnetId"]
        made["subnets"].append(sn)
        ec2.modify_subnet_attribute(SubnetId=sn, MapPublicIpOnLaunch={"Value": True})
        ec2.associate_route_table(RouteTableId=rt, SubnetId=sn)
    return vpc_id, list(made["subnets"])


def _iam_role(ctx, kind, trust_service, statements):
    """Create a role trusting trust_service with ONE inline policy; returns (name, arn).

    The role and policy are polled back (IAM is eventually consistent); trust propagation is
    absorbed by the later bounded poll for the task reaching RUNNING."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_XSVC_PREFIX + kind + "-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": trust_service},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _drop():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _swallow(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_drop)
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    _poll_until(
        lambda: _safe(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
        lambda r: r is not None,
        timeout_s=60,
        interval_s=2,
        description=f"role {name} inline policy readable",
    )
    return name, arn


def _ensure_ecs_slr(ctx) -> None:
    """RunTask on Fargate needs AWSServiceRoleForECS (CreateService auto-creates it,
    RunTask does not). Idempotent — already-exists is success."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInput", "InvalidInputException"):
            raise


def _create_cluster(ctx, settings=None) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-cluster-")
    kwargs: dict = {"clusterName": name, "tags": _ecs_tags_kv()}
    if settings:
        kwargs["settings"] = settings
    ecs.create_cluster(**kwargs)

    def _drop():
        # A DRAINING service / stopping task can block delete briefly; retry.
        last = None
        for _ in range(40):
            try:
                ecs.delete_cluster(cluster=name)
                return
            except Exception as exc:  # noqa: BLE001 - retried; the last one is raised
                if getattr(exc, "response", {}).get("Error", {}).get("Code") == "ClusterNotFoundException":
                    return
                last = exc
                time.sleep(2)
        raise RuntimeError(f"cluster {name} was not deleted: {last!r}")

    ctx.on_cleanup(_drop)
    return name


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(_XSVC_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _awslogs(log_group: str, region: str, prefix: str = "ecs") -> dict:
    return {
        "logDriver": "awslogs",
        "options": {
            "awslogs-group": log_group,
            "awslogs-region": region,
            "awslogs-stream-prefix": prefix,
        },
    }


def _register_task_def(
    ctx,
    container_defs,
    *,
    execution_role_arn=None,
    task_role_arn=None,
    volumes=None,
    runtime_platform=None,
    family=None,
    cpu="256",
    memory="512",
    network_mode="awsvpc",
    requires_compatibilities=("FARGATE",),
):
    """Register one revision. cpu/memory are task-level and must be OMITTED (not None) for a
    non-Fargate revision, where the size lives on the container definition instead."""
    ecs = ctx.client("ecs")
    kwargs: dict = dict(
        family=family or ctx.unique_name(_XSVC_PREFIX + "td-"),
        containerDefinitions=container_defs,
        requiresCompatibilities=list(requires_compatibilities),
        networkMode=network_mode,
        tags=_ecs_tags_kv(),
    )
    if cpu:
        kwargs["cpu"] = cpu
    if memory:
        kwargs["memory"] = memory
    if execution_role_arn:
        kwargs["executionRoleArn"] = execution_role_arn
    if task_role_arn:
        kwargs["taskRoleArn"] = task_role_arn
    if volumes:
        kwargs["volumes"] = volumes
    if runtime_platform:
        kwargs["runtimePlatform"] = runtime_platform
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(
        lambda: _retire_task_definition(ecs, arn)
    )
    return td


def _run_task(ctx, cluster, td_arn, subnets, sg_ids=None) -> str:
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    awsvpc: dict = {"subnets": subnets, "assignPublicIp": "ENABLED"}
    if sg_ids:
        awsvpc["securityGroups"] = sg_ids
    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={"awsvpcConfiguration": awsvpc},
    )
    assert not resp.get("failures"), f"RunTask failures: {resp.get('failures')}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.stop_task(cluster=cluster, task=arn)))
    return arn


def _await_task(ctx, cluster, task_arn, statuses, timeout_s=600.0):
    ecs = ctx.client("ecs")

    def probe():
        found = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return found[0] if found else {}

    return _poll_until(
        probe,
        lambda t: t.get("lastStatus") in statuses,
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=1,
        description=f"task {task_arn} lastStatus in {sorted(statuses)}",
        ctx=ctx,
    )


def _log_messages(ctx, group: str, stream: str) -> list[str]:
    """Every event in the stream, PAGINATED forward from the head."""
    logs = ctx.client("logs")
    msgs: list[str] = []
    token = None
    while True:
        kwargs: dict = {
            "logGroupName": group,
            "logStreamName": stream,
            "startFromHead": True,
        }
        if token:
            kwargs["nextToken"] = token
        page = _safe(lambda: logs.get_log_events(**kwargs))
        if page is None:
            return msgs
        events = page.get("events", [])
        msgs += [e.get("message", "") for e in events]
        nxt = page.get("nextForwardToken")
        if not events or nxt == token:
            return msgs
        token = nxt


def _await_log_stream(ctx, group: str, stream: str, timeout_s=300.0) -> None:
    logs = ctx.client("logs")
    _poll_until(
        lambda: [
            s["logStreamName"]
            for s in logs.describe_log_streams(
                logGroupName=group, logStreamNamePrefix=stream
            ).get("logStreams", [])
        ],
        lambda names: stream in names,
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=1,
        description=f"awslogs stream {stream} in {group}",
        ctx=ctx,
    )


def _open_http_sg(ctx, vpc_id: str, port: int = 80, *, cidrs=(), source_sg=None) -> str:
    """A tagged security group in vpc_id allowing inbound tcp/port from cidrs or source_sg.
    Created before the ALB and tasks so its LIFO teardown runs after theirs; the delete is retried
    because an ENI keeps the group referenced briefly after its owner is deleted."""
    ec2 = ctx.client("ec2")
    gid = ec2.create_security_group(
        GroupName=ctx.unique_name(_XSVC_PREFIX + "sg-"),
        Description="sim2real xsvc container archetype HTTP ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]

    def _drop():
        last = None
        for _ in range(90):
            try:
                ec2.delete_security_group(GroupId=gid)
                return
            except Exception as exc:  # noqa: BLE001 - ENI still detaching
                last = exc
                time.sleep(2)
        raise RuntimeError(f"security group {gid} was never deleted: {last!r}")

    ctx.on_cleanup(_drop)
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": c} for c in cidrs],
                "UserIdGroupPairs": [{"GroupId": source_sg}] if source_sg else [],
            }
        ],
    )
    return gid


def _create_target_group(ctx, vpc_id, **kwargs):
    """An ELBv2 target group; deregistration delay is squeezed to 5s so a target swap is
    observable (and teardown is not blocked for minutes)."""
    elb = ctx.client("elbv2")
    params = dict(
        Name=ctx.unique_name(_XSVC_PREFIX + "tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=5,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        HealthCheckTimeoutSeconds=4,
        Matcher={"HttpCode": "200"},
        Tags=_tags_kv(),
    )
    params.update(kwargs)
    tg = elb.create_target_group(**params)["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop():
        last = None
        for _ in range(30):
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except Exception as exc:  # noqa: BLE001 - still referenced by a listener/service
                if getattr(exc, "response", {}).get("Error", {}).get("Code") == "TargetGroupNotFound":
                    return
                last = exc
                time.sleep(2)
        raise RuntimeError(f"target group {arn} was not deleted: {last!r}")

    ctx.on_cleanup(_drop)
    elb.modify_target_group_attributes(
        TargetGroupArn=arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "5"}],
    )
    return tg


def _create_alb(ctx, subnets, sg_ids):
    """An internet-facing ALB, waited to 'active'. Internet-facing (not internal) so the
    check can make a REAL HTTP request through it from outside the VPC."""
    elb = ctx.client("elbv2")
    lb = elb.create_load_balancer(
        Name=ctx.unique_name(_XSVC_PREFIX + "lb-"),
        Subnets=subnets,
        SecurityGroups=sg_ids,
        Scheme="internet-facing",
        Type="application",
        IpAddressType="ipv4",
        Tags=_tags_kv(),
    )["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop():
        _swallow(lambda: elb.delete_load_balancer(LoadBalancerArn=arn))
        # Wait for the ALB's ENIs to go away before the security group teardown runs.
        for _ in range(75):
            if (
                _safe(lambda: elb.describe_load_balancers(LoadBalancerArns=[arn]))
                is None
            ):
                return
            time.sleep(2)
        raise RuntimeError(f"load balancer {arn} was not deleted")

    ctx.on_cleanup(_drop)
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "failed"),
        timeout_s=_budget_s(ctx, 420),
        interval_s=1,
        description=f"load balancer {arn} active",
        ctx=ctx,
    )
    assert lb["State"]["Code"] == "active", lb["State"]
    return lb


def _create_listener(ctx, lb_arn, tg_arn, port=80):
    elb = ctx.client("elbv2")
    listener = elb.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_tags_kv(),
    )["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: elb.delete_listener(ListenerArn=arn)))
    return listener


def _target_health(ctx, tg_arn) -> dict[str, str]:
    """{target-id: health-state} for every target currently in the group."""
    descs = ctx.client("elbv2").describe_target_health(TargetGroupArn=tg_arn)[
        "TargetHealthDescriptions"
    ]
    return {d["Target"]["Id"]: d["TargetHealth"]["State"] for d in descs}


def _task_private_ip(task: dict) -> str | None:
    """The awsvpc ENI's private IPv4 — the address an ELBv2 'ip' target group registers."""
    for att in task.get("attachments", []):
        if att.get("type") == "ElasticNetworkInterface":
            for detail in att.get("details", []):
                if detail.get("name") == "privateIPv4Address":
                    return detail.get("value")
    return None


def _http_get(ctx, url: str, timeout_s: float = 10.0):
    """(status, body) for a plain GET. An HTTP error STATUS is returned, not raised, so a
    503-from-the-load-balancer is an observation rather than an exception; a transport
    failure (DNS not yet propagated, connection refused) returns (None, reason)."""
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, headers={**({"User-Agent": "sim2real-xsvc"}), **_route})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # retried by the caller
        return None, f"{type(exc).__name__}: {exc}"


def _create_fargate_service(
    ctx,
    cluster,
    td_arn,
    subnets,
    *,
    desired_count=1,
    sg_ids=None,
    load_balancers=None,
    health_check_grace_period_seconds=None,
    deployment_configuration=None,
):
    """A Fargate service; teardown drains it to INACTIVE before cluster teardown (an ACTIVE service
    blocks cluster deletion), keyed by service name so tasks ECS replaced mid-check are covered."""
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-svc-")
    awsvpc: dict = {"subnets": subnets, "assignPublicIp": "ENABLED"}
    if sg_ids:
        awsvpc["securityGroups"] = sg_ids
    kwargs: dict = dict(
        cluster=cluster,
        serviceName=name,
        taskDefinition=td_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": awsvpc},
        tags=_ecs_tags_kv(),
    )
    if load_balancers:
        kwargs["loadBalancers"] = load_balancers
    if health_check_grace_period_seconds is not None:
        kwargs["healthCheckGracePeriodSeconds"] = health_check_grace_period_seconds
    if deployment_configuration is not None:
        kwargs["deploymentConfiguration"] = deployment_configuration
    svc = ecs.create_service(**kwargs)["service"]

    def _drop():
        _swallow(
            lambda: ecs.update_service(cluster=cluster, service=name, desiredCount=0)
        )
        _swallow(lambda: ecs.delete_service(cluster=cluster, service=name, force=True))
        _poll_until(
            lambda: (
                ecs.describe_services(cluster=cluster, services=[name]).get(
                    "services"
                )
                or [{}]
            )[0].get("status", "INACTIVE"),
            lambda st: st == "INACTIVE",
            timeout_s=420,
            interval_s=5,
            description=f"service {name} drained to INACTIVE",
        )

    ctx.on_cleanup(_drop)
    return svc


def _service_task_arns(ctx, cluster, service) -> list[str]:
    """Every RUNNING-desired task arn for the service, PAGINATED."""
    ecs = ctx.client("ecs")
    arns: list[str] = []
    token = None
    while True:
        kwargs: dict = {
            "cluster": cluster,
            "serviceName": service,
            "desiredStatus": "RUNNING",
        }
        if token:
            kwargs["nextToken"] = token
        page = ecs.list_tasks(**kwargs)
        arns += page.get("taskArns", [])
        token = page.get("nextToken")
        if not token:
            return arns


def _running_service_tasks(ctx, cluster, service) -> list[dict]:
    """DescribeTasks for the service's RUNNING-desired tasks, RUNNING ones only."""
    ecs = ctx.client("ecs")
    arns = _service_task_arns(ctx, cluster, service)
    if not arns:
        return []
    tasks = ecs.describe_tasks(cluster=cluster, tasks=arns).get("tasks", [])
    return [t for t in tasks if t.get("lastStatus") == "RUNNING"]


def _primary_deployment(ctx, cluster, service) -> dict:
    svc = ctx.client("ecs").describe_services(cluster=cluster, services=[service])[
        "services"
    ][0]
    for d in svc.get("deployments", []):
        if d.get("status") == "PRIMARY":
            return d
    return {}


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
