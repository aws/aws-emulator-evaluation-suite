"""ecs-service-scale-out-and-in-tracks-alb-targets."""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "ecs-service-scale-out-and-in-tracks-alb-targets"

GROUP = "container-load-balancing"

SERVICES = ["ecs", "elbv2", "logs"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """Scaling out to 2 adds a second healthy ALB 'ip' target, both task hostnames answer through
    the ALB and each task logs to its own stream; scaling in to 1 deregisters the surplus target
    while the ALB keeps answering 200."""
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
            },
            {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"], "Resource": "*"}
        ],
    )
    cluster = _create_cluster(ctx)

    marker = "sim2real-scale-" + ctx.unique_name("")[:8]
    td = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": _target_image(ctx, "busybox"),
                "essential": True,
                "command": _httpd_command(marker),
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=exec_role,
    )

    tg = _create_target_group(ctx, vpc_id)
    tg_arn = tg["TargetGroupArn"]
    lb = _create_alb(ctx, subnets, [alb_sg])
    _create_listener(ctx, lb["LoadBalancerArn"], tg_arn)
    url = "http://" + lb["DNSName"] + "/"

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
        health_check_grace_period_seconds=120,
    )
    service = svc["serviceName"]

    first = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 1,
        timeout_s=600,
        interval_s=10,
        description=f"service {service} has 1 RUNNING task",
    )
    first_ip = _task_private_ip(first[0])
    assert first_ip, first[0].get("attachments")
    _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: h.get(first_ip) == "healthy",
        timeout_s=600,
        interval_s=10,
        description=f"first target {first_ip} healthy",
    )

    # --- Scale out: the second task must appear as a second HEALTHY target.
    ecs.update_service(cluster=cluster, service=service, desiredCount=2)
    both = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 2,
        timeout_s=600,
        interval_s=10,
        description=f"service {service} has 2 RUNNING tasks",
    )
    ips = sorted(filter(None, (_task_private_ip(t) for t in both)))
    assert len(ips) == 2, f"expected two awsvpc IPs, got {ips}"
    _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: all(h.get(i) == "healthy" for i in ips) and len(h) == 2,
        timeout_s=600,
        interval_s=10,
        description=f"both targets {ips} healthy",
    )

    # --- Both containers really receive traffic through the load balancer; each serves its own
    # hostname, so distinct bodies prove two distinct tasks.
    seen: set[str] = set()

    def _sample():
        status, body = _http_get(ctx, url)
        if status == 200 and marker in body:
            seen.add(body.strip())
        return set(seen)

    bodies = _poll_until(
        _sample,
        lambda s: len(s) >= 2,
        timeout_s=300,
        interval_s=2,
        description="load balancer answered from both tasks (distinct hostnames)",
    )
    assert len(bodies) >= 2, f"only one container ever answered: {bodies}"

    # --- Both replicas' stdout is delivered under their OWN task-id log streams.
    for task in both:
        stream = f"ecs/app/{task['taskArn'].rsplit('/', 1)[-1]}"
        _await_log_stream(ctx, log_group, stream, timeout_s=300)
        msgs = _poll_until(
            lambda s=stream: _log_messages(ctx, log_group, s),
            lambda ms: any(f"{marker} httpd-start" in m for m in ms),
            timeout_s=300,
            interval_s=5,
            description=f"httpd start line in {stream}",
        )
        assert any(f"{marker} httpd-start" in m for m in msgs), (stream, msgs)

    # --- Scale in: the surplus target must be DEREGISTERED, not just marked down.
    ecs.update_service(cluster=cluster, service=service, desiredCount=1)
    remaining = _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: len(h) == 1,
        timeout_s=600,
        interval_s=10,
        description="target group is back to exactly one registered target",
    )
    left_ip, left_state = next(iter(remaining.items()))
    assert left_ip in ips, f"unexpected surviving target {left_ip} (was {ips})"
    _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: h.get(left_ip) == "healthy",
        timeout_s=300,
        interval_s=10,
        description=f"surviving target {left_ip} still healthy (was {left_state})",
    )
    status, body = _poll_until(
        lambda: _http_get(ctx, url),
        lambda r: r[0] == 200,
        timeout_s=300,
        interval_s=5,
        description="load balancer still serving after scale-in",
    )
    assert marker in body, (status, body)




_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown
        pass


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
    """(vpc_id, subnet_ids) from the default VPC, one subnet per AZ; its subnets already route to
    an internet gateway, so tasks with a public IP pull images without a NAT gateway or EIP."""
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


def _open_http_sg(ctx, vpc_id: str, port: int = 80, *, cidrs=(), source_sg=None) -> str:
    """A tagged security group in vpc_id allowing inbound tcp/port from cidrs or source_sg, made
    before the ALB and tasks so it is torn down after them; an ENI keeps it referenced for a
    while, so the delete is retried on a bounded loop and raises if the group never goes."""
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


def _iam_role(ctx, kind, trust_service, statements):
    """Create a role trusting trust_service with one inline policy and return (name, arn); IAM is
    eventually consistent, so the role and policy are polled back, then a short settle covers
    trust-policy propagation to the assuming service."""
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
    time.sleep(10)  # IAM propagation has no observable; the same settle runs on every target
    return name, arn


def _ensure_ecs_slr(ctx) -> None:
    """RunTask on Fargate needs AWSServiceRoleForECS (CreateService auto-creates it,
    RunTask does not). Idempotent — already-exists is success."""
    _swallow(
        lambda: ctx.client("iam").create_service_linked_role(
            AWSServiceName="ecs.amazonaws.com"
        )
    )


def _create_cluster(ctx, settings=None) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-cluster-")
    kwargs: dict = {"clusterName": name, "tags": _ecs_tags_kv()}
    if settings:
        kwargs["settings"] = settings
    ecs.create_cluster(**kwargs)

    def _drop():
        # A DRAINING service / stopping task can block delete briefly; retry.
        for _ in range(8):
            try:
                ecs.delete_cluster(cluster=name)
                return
            except Exception:  # noqa: BLE001
                time.sleep(10)

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
    ctx, container_defs, *, execution_role_arn=None, task_role_arn=None
):
    ecs = ctx.client("ecs")
    kwargs: dict = dict(
        family=ctx.unique_name(_XSVC_PREFIX + "td-"),
        containerDefinitions=container_defs,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=_ecs_tags_kv(),
    )
    if execution_role_arn:
        kwargs["executionRoleArn"] = execution_role_arn
    if task_role_arn:
        kwargs["taskRoleArn"] = task_role_arn
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(
        lambda: _retire_task_definition(ecs, arn)
    )
    return td


def _task_private_ip(task: dict) -> str | None:
    """The awsvpc ENI's private IPv4 — the address an ELBv2 'ip' target group registers."""
    for att in task.get("attachments", []):
        if att.get("type") == "ElasticNetworkInterface":
            for detail in att.get("details", []):
                if detail.get("name") == "privateIPv4Address":
                    return detail.get("value")
    return None


def _log_messages(ctx, group: str, stream: str) -> list[str]:
    ev = _safe(
        lambda: ctx.client("logs").get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True
        )
    )
    return [e.get("message", "") for e in (ev or {}).get("events", [])]


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
    except Exception as exc:  # noqa: BLE001 - transport-level, retried by the caller
        return None, f"{type(exc).__name__}: {exc}"


def _httpd_command(marker: str) -> list[str]:
    """busybox httpd serving GET / -> "<marker> <hostname>" on :80 in the foreground, so a
    response through the load balancer identifies the task that served it."""
    return [
        "sh",
        "-c",
        (
            "mkdir -p /www && "
            f'echo "{marker} $(hostname)" > /www/index.html && '
            f'echo "{marker} httpd-start $(hostname)" && '
            "exec httpd -f -v -p 80 -h /www"
        ),
    ]


def _create_target_group(ctx, vpc_id, **kwargs):
    """An ELBv2 target group; deregistration delay is squeezed to 5s so scale-in
    deregistration is observable (and teardown is not blocked for minutes)."""
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
        for _ in range(10):
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except Exception:  # noqa: BLE001 - still referenced by a listener/service
                time.sleep(6)

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
):
    """A Fargate service; teardown DRAINS it (desiredCount=0 -> delete force -> wait for
    INACTIVE) before the cluster teardown registered earlier can run, because an ACTIVE
    service blocks cluster deletion."""
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
                timeout_s=300,
                interval_s=5,
                description=f"service {name} drained to INACTIVE",
            )
        )

    ctx.on_cleanup(_drop)
    return svc


def _service_task_arns(ctx, cluster, service) -> list[str]:
    return (
        ctx.client("ecs")
        .list_tasks(cluster=cluster, serviceName=service, desiredStatus="RUNNING")
        .get("taskArns", [])
    )


def _running_service_tasks(ctx, cluster, service) -> list[dict]:
    """DescribeTasks for the service's RUNNING-desired tasks; raises if one already
    STOPPED so an image-pull/logging failure surfaces instead of a timeout."""
    ecs = ctx.client("ecs")
    arns = _service_task_arns(ctx, cluster, service)
    if not arns:
        return []
    tasks = ecs.describe_tasks(cluster=cluster, tasks=arns).get("tasks", [])
    for t in tasks:
        if t.get("lastStatus") == "STOPPED":
            raise AssertionError(
                f"service task stopped: stopCode={t.get('stopCode')} "
                f"reason={t.get('stoppedReason')}"
            )
    return [t for t in tasks if t.get("lastStatus") == "RUNNING"]


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


#: Images the tasks run: the reference, its linux/amd64 image ID (the config digest), and the
#: `docker save` archive it is pre-seeded as. The check never pulls from a registry.
_SEED_IMAGES = {
    "busybox": (
        "public.ecr.aws/docker/library/busybox:1.36",
        "sha256:b116e155074440ffd9e449559433feb4cd2341eb3554b1da1c638c976e56451d",
        "busybox-1.36.tar",
    ),
}
_SEED_DIR = pathlib.Path.home() / ".cache" / "sim2real" / "images"
_LAYER_PART_BYTES = 8 * 1024 * 1024
_PUSHED: dict[tuple[int, str], tuple[object, str]] = {}


def _seeded_image(key: str) -> tuple[bytes, list[bytes]]:
    """The pre-seeded image's config and gzip layers, verified against its pinned image ID; a
    missing or mismatched archive raises RequiredToolMissing."""
    from fidelity_tests_runner import RequiredToolMissing

    ref, image_id, archive_name = _SEED_IMAGES[key]
    path = _SEED_DIR / archive_name
    need = (
        f"{ref} ({image_id}) saved at {path}; pre-seed it with `docker pull --platform "
        f"linux/amd64 {ref} && docker save {ref} -o {path}`"
    )
    try:
        with tarfile.open(path) as archive:
            entry = json.load(archive.extractfile("manifest.json"))[0]
            config = archive.extractfile(entry["Config"]).read()
            raw = [archive.extractfile(name).read() for name in entry["Layers"]]
        plain = [gzip.decompress(b) if b[:2] == b"\x1f\x8b" else b for b in raw]
        recorded = json.loads(config).get("rootfs", {}).get("diff_ids")
    except (OSError, EOFError, tarfile.TarError, KeyError, IndexError, ValueError, TypeError,
            AttributeError) as exc:
        raise RequiredToolMissing([f"{need} ({type(exc).__name__}: {exc})"]) from None
    diff_ids = ["sha256:" + hashlib.sha256(b).hexdigest() for b in plain]
    if "sha256:" + hashlib.sha256(config).hexdigest() != image_id or recorded != diff_ids:
        raise RequiredToolMissing([f"{need} (the archive there holds another image)"])
    return config, [gzip.compress(b, compresslevel=1, mtime=0) for b in plain]


def _target_image(ctx, key: str = "busybox") -> str:
    """URI of the pre-seeded image, pushed once into an ECR repository this check creates through
    the target's ECR layer-upload API (InitiateLayerUpload, UploadLayerPart, CompleteLayerUpload,
    PutImage), so the task's image comes from the target."""
    hit = _PUSHED.get((id(ctx), key))
    if hit and hit[0] is ctx:
        return hit[1]
    config, layers = _seeded_image(key)
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-img-").lower()
    repo = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    descriptors = []
    for blob in [config, *layers]:
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
        for first in range(0, len(blob), _LAYER_PART_BYTES):
            part = blob[first:first + _LAYER_PART_BYTES]
            ecr.upload_layer_part(
                repositoryName=name, uploadId=upload_id, partFirstByte=first,
                partLastByte=first + len(part) - 1, layerPartBlob=part,
            )
        ecr.complete_layer_upload(repositoryName=name, uploadId=upload_id, layerDigests=[digest])
        descriptors.append({"size": len(blob), "digest": digest})
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", **descriptors[0]},
        "layers": [
            {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", **d}
            for d in descriptors[1:]
        ],
    }
    ecr.put_image(
        repositoryName=name, imageManifest=json.dumps(manifest), imageTag="seeded",
        imageManifestMediaType=manifest["mediaType"],
    )
    uri = f"{repo['repositoryUri']}:seeded"
    _PUSHED[(id(ctx), key)] = (ctx, uri)
    return uri


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
