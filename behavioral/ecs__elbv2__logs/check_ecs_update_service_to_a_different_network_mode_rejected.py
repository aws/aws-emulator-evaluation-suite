"""ecs-update-service-to-a-different-network-mode-rejected."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-update-service-to-a-different-network-mode-rejected"

GROUP = "overly-permissive"

SERVICES = ["ecs", "elbv2", "logs"]


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """UpdateService refuses to move a live awsvpc, ALB-attached Fargate service onto a bridge-mode
    revision with InvalidParameterException, the service keeps answering HTTP through its load
    balancer, and the same call succeeds once only the network mode is repaired.
    """
    ecs = ctx.client("ecs")
    vpc_id, subnets = _default_vpc(ctx, min_subnets=2)
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

    marker = "sim2real-netmode-" + ctx.unique_name("")[:10]
    family = ctx.unique_name(_XSVC_PREFIX + "td-netmode-")
    v1 = _awsvpc_revision(ctx, family, exec_role, log_group, f"{marker}-a")
    v1_arn = v1["taskDefinitionArn"]

    tg = _create_target_group(ctx, vpc_id)
    tg_arn = tg["TargetGroupArn"]
    lb = _create_alb(ctx, subnets, [alb_sg])
    _create_listener(ctx, lb["LoadBalancerArn"], tg_arn)

    svc = _create_fargate_service(
        ctx,
        cluster,
        v1_arn,
        subnets,
        desired_count=1,
        sg_ids=[task_sg],
        load_balancers=[
            {"targetGroupArn": tg_arn, "containerName": "app", "containerPort": 80}
        ],
        health_check_grace_period_seconds=120,
    )
    service = svc["serviceName"]

    tasks = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 1,
        timeout_s=600,
        interval_s=10,
        description=f"service {service} has 1 RUNNING task",
    )
    task_arn_before = tasks[0]["taskArn"]
    ip = _task_private_ip(tasks[0])
    assert ip, f"the task has no awsvpc private IP: {tasks[0].get('attachments')!r}"
    _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: h.get(ip) == "healthy",
        timeout_s=600,
        interval_s=10,
        description=f"target {ip} healthy in {tg_arn}",
    )
    url = "http://" + lb["DNSName"] + "/"
    status_before, body_before = _poll_until(
        lambda: _http_get(ctx, url),
        lambda r: r[0] == 200,
        timeout_s=420,
        interval_s=10,
        description=f"HTTP 200 through the load balancer at {url}",
    )
    assert status_before == 200 and f"{marker}-a" in body_before, (
        f"the service was not serving revision A before the rejected update: "
        f"{status_before!r} {body_before!r}"
    )

    # --- Break exactly one thing: the network mode. Fargate forbids bridge outright, so the
    # revision is registered EC2-compatible; that pairing is itself measured below.
    code, message = _error(
        lambda: ecs.register_task_definition(
            family=family,
            requiresCompatibilities=["FARGATE"],
            networkMode="bridge",
            cpu="256",
            memory="512",
            containerDefinitions=[
                {"name": "app", "image": _PUBLIC_IMAGE, "essential": True}
            ],
            tags=_ecs_tags_kv(),
        )
    )
    assert (code, message) == (
        "ClientException",
        "Fargate only supports network mode ‘awsvpc’.",
    ), (
        "a FARGATE task definition declaring networkMode=bridge should be rejected outright: "
        f"{code!r} {message!r}"
    )

    bridge = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "memory": 512,
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
                "command": _httpd_command(f"{marker}-bridge"),
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=exec_role,
        family=family,
        network_mode="bridge",
        requires_compatibilities=["EC2"],
        cpu=None,
        memory=None,
    )
    assert bridge["networkMode"] == "bridge", bridge.get("networkMode")

    code, message = _error(
        lambda: ecs.update_service(
            cluster=cluster, service=service, taskDefinition=bridge["taskDefinitionArn"]
        )
    )
    assert (code, message) == (
        "InvalidParameterException",
        "Task definition does not support launch_type FARGATE.",
    ), (
        f"expected InvalidParameterException for a network-mode change on a live Fargate service, "
        f"got {code!r} {message!r}"
    )

    # --- The effect is absent, control plane AND data plane.
    svc_after = ecs.describe_services(cluster=cluster, services=[service])["services"][
        0
    ]
    assert svc_after["taskDefinition"] == v1_arn, (
        f"the rejected update still moved the service: {svc_after['taskDefinition']!r} != {v1_arn!r}"
    )
    tasks_after = _running_service_tasks(ctx, cluster, service)
    assert len(tasks_after) == 1, tasks_after
    assert tasks_after[0]["taskArn"] == task_arn_before, (
        f"the rejected update replaced the task: {task_arn_before!r} -> "
        f"{tasks_after[0]['taskArn']!r}"
    )
    status_after, body_after = _http_get(ctx, url)
    assert status_after == 200 and f"{marker}-a" in body_after, (
        f"the service stopped serving revision A after a REJECTED update: "
        f"{status_after!r} {body_after!r}"
    )

    # --- The positive control: same call shape, only the network mode repaired.
    control = _awsvpc_revision(ctx, family, exec_role, log_group, f"{marker}-c")
    ecs.update_service(
        cluster=cluster, service=service, taskDefinition=control["taskDefinitionArn"]
    )
    _poll_until(
        lambda: _primary_deployment(ctx, cluster, service),
        lambda d: (
            d.get("rolloutState") == "COMPLETED"
            and d.get("taskDefinition") == control["taskDefinitionArn"]
        ),
        timeout_s=900,
        interval_s=10,
        description=f"service {service} rolled onto the awsvpc control revision",
    )
    control_status, control_body = _poll_until(
        lambda: _http_get(ctx, url),
        lambda r: r[0] == 200 and f"{marker}-c" in (r[1] or ""),
        timeout_s=600,
        interval_s=10,
        description=f"the control revision's body served through {url}",
    )
    assert control_status == 200 and f"{marker}-c" in control_body, (
        f"the positive control update did not take effect, so the rejection proves nothing about "
        f"the network mode specifically: {control_status!r} {control_body!r}"
    )

    # A witness independent of the ALB: the control task's OWN startup line names revision C, and
    # nothing anywhere ever started the bridge revision.
    control_tasks = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 1 and ts[0]["taskArn"] != task_arn_before,
        timeout_s=420,
        interval_s=10,
        description=f"service {service} settled on the control task",
    )
    control_stream = f"ecs/app/{control_tasks[0]['taskArn'].rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, log_group, control_stream, timeout_s=420)
    control_msgs = _poll_until(
        lambda: _log_messages(ctx, log_group, control_stream),
        lambda ms: any(f"{marker}-c httpd-start" in m for m in ms),
        timeout_s=420,
        interval_s=5,
        description=f"the control container's start line in {control_stream}",
    )
    assert not any(f"{marker}-bridge" in m for m in control_msgs), (
        f"the bridge revision's body appears in the control task's stream, so the rejected "
        f"revision ran after all: {control_msgs!r}"
    )


def _awsvpc_revision(ctx, family, exec_role, log_group, body_marker):
    return _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
                "command": _httpd_command(body_marker),
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=exec_role,
        family=family,
    )


def _httpd_command(body_marker: str) -> list[str]:
    """busybox httpd serving GET / -> "<body_marker> <hostname>" on :80, in the foreground."""
    return [
        "sh",
        "-c",
        (
            "mkdir -p /www && "
            f'echo "{body_marker} $(hostname)" > /www/index.html && '
            f'echo "{body_marker} httpd-start $(hostname)" && '
            "exec httpd -f -v -p 80 -h /www"
        ),
    ]


# ===== helpers =====
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


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _default_vpc(ctx, min_subnets=1):
    """(vpc_id, subnet_ids) from the account's DEFAULT VPC, one subnet per AZ.

    The container archetype deliberately reuses the default VPC and NEVER builds a
    NAT gateway or EIP: default subnets already have an internet-gateway route, so a
    Fargate task with assignPublicIp=ENABLED can pull its image with zero billable
    networking left behind if teardown is interrupted."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get(
        "Vpcs", []
    )
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    ).get("Subnets", [])
    per_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["SubnetId"]):
        if sn.get("AvailableIpAddressCount", 0) > 0:
            per_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    ids = [per_az[az] for az in sorted(per_az)]
    if len(ids) < min_subnets:
        raise AssertionError(
            f"shared network VPC {vpc_id} has {len(ids)} usable subnets, need {min_subnets}"
        )
    return vpc_id, ids


def _iam_role(ctx, kind, trust_service, statements):
    """Create a role trusting trust_service with ONE inline policy; returns (name, arn).

    IAM is eventually consistent, so the role + its inline policy are POLLED back
    before any service is asked to assume it. Any residual trust-policy propagation
    delay to the assuming service is absorbed by the bounded polls this check already
    runs downstream (task placement, ALB target health) — it is never gated by a
    sleep here."""
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
        # A DRAINING service / stopping task blocks the delete briefly; retry only that, then raise.
        deadline = time.monotonic() + 80
        while True:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ClusterNotFoundException":
                    return
                if code not in (
                    "ClusterContainsServicesException", "ClusterContainsTasksException",
                    "ClusterContainsContainerInstancesException", "UpdateInProgressException",
                ) or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

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
        timeout_s=timeout_s,
        interval_s=5,
        description=f"task {task_arn} lastStatus in {sorted(statuses)}",
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
        timeout_s=timeout_s,
        interval_s=5,
        description=f"awslogs stream {stream} in {group}",
    )


def _open_http_sg(ctx, vpc_id: str, port: int = 80, *, cidrs=(), source_sg=None) -> str:
    """A security group in vpc_id allowing inbound tcp/port from cidrs or source_sg, TAGGED AT
    CREATION. Create it before the ALB and tasks so its LIFO teardown runs after theirs — an
    ENI keeps the group referenced for a while after its owner is deleted, so the delete is
    retried on a bounded loop and raises if the group never goes."""
    ec2 = ctx.client("ec2")
    gid = ec2.create_security_group(
        GroupName=ctx.unique_name(_XSVC_PREFIX + "sg-"),
        Description="sim2real xsvc container archetype HTTP ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]

    def _drop():
        last = None
        for _ in range(18):
            try:
                ec2.delete_security_group(GroupId=gid)
                return
            except Exception as exc:  # noqa: BLE001 - ENI still detaching
                last = exc
                time.sleep(10)
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
        HealthCheckIntervalSeconds=10,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        HealthCheckTimeoutSeconds=5,
        Matcher={"HttpCode": "200"},
        Tags=_tags_kv(),
    )
    params.update(kwargs)
    tg = elb.create_target_group(**params)["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop():
        # The target group stays in use until its listener and service are gone; retry only that.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "TargetGroupNotFound":
                    return
                if code != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

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
        for _ in range(30):
            if (
                _safe(lambda: elb.describe_load_balancers(LoadBalancerArns=[arn]))
                is None
            ):
                return
            time.sleep(5)

    ctx.on_cleanup(_drop)
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "failed"),
        timeout_s=420,
        interval_s=10,
        description=f"load balancer {arn} active",
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
    """A Fargate service; teardown DRAINS it (desiredCount=0 -> delete force -> wait for
    INACTIVE) before the cluster teardown registered earlier can run, because an ACTIVE
    service blocks cluster deletion. Teardown is registered BY SERVICE NAME, never by a task
    arn captured at setup, so a task ECS replaced mid-check is still accounted for."""
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
        _swallow(
            lambda: _poll_until(
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


def _error(fn) -> tuple[str, str]:
    """(code, message) of the AWS error raised by fn(). Raises if fn SUCCEEDS.

    A falsy sentinel on success would turn the strongest possible signal — an emulator accepting
    input real AWS rejects — into an error-code mismatch that reads like a naming difference, so
    the unexpected success is raised instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(
        f"the call was expected to be REJECTED but it succeeded: {result!r}"
    )


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
