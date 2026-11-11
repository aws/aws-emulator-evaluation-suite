"""ecs-rolling-update-serves-http-continuously-while-the-task-revision-swaps."""

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

CHECK = "ecs-rolling-update-serves-http-continuously-while-the-task-revision-swaps"

GROUP = "service-deployment"

SERVICES = ["ecs", "elbv2", "logs"]

#: Sampling cadence. Deliberately not a wait: the loop's exit condition is the deployment
#: reaching COMPLETED *and* the served revision having settled on v2, both observable.
_SAMPLE_INTERVAL_S = 2.0


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A ROLLING update at minimumHealthyPercent=100 answers every ALB request with 200, both
    revisions serve during the rollout, and once the old target is deregistered only v2 answers.
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
            },
            {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"], "Resource": "*"}
        ],
    )
    cluster = _create_cluster(ctx)

    marker = "sim2real-roll-" + ctx.unique_name("")[:10]
    family = ctx.unique_name(_XSVC_PREFIX + "td-roll-")
    v1 = _revision(ctx, family, exec_role, log_group, f"{marker}-v1")
    v2 = _revision(ctx, family, exec_role, log_group, f"{marker}-v2")

    tg = _create_target_group(ctx, vpc_id)
    tg_arn = tg["TargetGroupArn"]
    lb = _create_alb(ctx, subnets, [alb_sg])
    _create_listener(ctx, lb["LoadBalancerArn"], tg_arn)

    svc = _create_fargate_service(
        ctx,
        cluster,
        v1["taskDefinitionArn"],
        subnets,
        desired_count=1,
        sg_ids=[task_sg],
        load_balancers=[
            {"targetGroupArn": tg_arn, "containerName": "app", "containerPort": 80}
        ],
        health_check_grace_period_seconds=120,
        # 100/200 is the whole point: AWS must keep a healthy target throughout, so a dropped
        # request is a fidelity failure and not an over-claim.
        deployment_configuration={"minimumHealthyPercent": 100, "maximumPercent": 200},
    )
    service = svc["serviceName"]

    old_tasks = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 1,
        timeout_s=600,
        interval_s=10,
        description=f"service {service} has 1 RUNNING task",
    )
    old_task_arn = old_tasks[0]["taskArn"]
    old_ip = _task_private_ip(old_tasks[0])
    assert old_ip, (
        f"the v1 task has no awsvpc private IP: {old_tasks[0].get('attachments')!r}"
    )
    _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: h.get(old_ip) == "healthy",
        timeout_s=600,
        interval_s=10,
        description=f"v1 target {old_ip} healthy in {tg_arn}",
    )

    url = "http://" + lb["DNSName"] + "/"
    first = _poll_until(
        lambda: _http_get(ctx, url),
        lambda r: r[0] == 200,
        timeout_s=420,
        interval_s=10,
        description=f"HTTP 200 through the load balancer at {url}",
    )
    assert _revision_of(first[1], marker) == "v1", (
        f"the load balancer is not serving v1 before the update: {first!r}"
    )

    # With maximumPercent=200 both revisions are healthy targets for a while and the ALB
    # round-robins across them, so only continuity is asserted during the rollout.
    ecs.update_service(
        cluster=cluster, service=service, taskDefinition=v2["taskDefinitionArn"]
    )

    rollout: list[tuple[int | None, str | None]] = []
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        status, body = _http_get(ctx, url)
        rollout.append((status, _revision_of(body, marker)))
        if len(rollout) % 5 == 0 and (
            _primary_deployment(ctx, cluster, service).get("rolloutState")
            == "COMPLETED"
        ):
            break
        time.sleep(_SAMPLE_INTERVAL_S)
    else:
        raise AssertionError(
            f"the rollout never reached COMPLETED within 900s: {len(rollout)} samples "
            f"{rollout!r} deployment={_primary_deployment(ctx, cluster, service)!r}"
        )

    assert len(rollout) >= 10, (
        f"only {len(rollout)} samples taken during the rollout; the continuity claim needs a real "
        f"time series: {rollout!r}"
    )
    assert all(s == 200 for s, _ in rollout), (
        f"the rolling update dropped requests at minimumHealthyPercent=100: "
        f"{[s for s, _ in rollout if s != 200]!r} of {len(rollout)} samples were not 200 "
        f"(full series {rollout!r})"
    )
    unrecognised = [i for i, (_, rev) in enumerate(rollout) if rev is None]
    assert not unrecognised, (
        f"samples at {unrecognised!r} came from neither revision, so something other than our two "
        f"containers answered through the load balancer: {rollout!r}"
    )
    assert rollout[0][1] == "v1", (
        f"the first sample after UpdateService was already {rollout[0][1]!r}, so the series does "
        f"not span the swap: {rollout!r}"
    )
    assert any(rev == "v2" for _, rev in rollout), (
        f"the new revision never answered a request during the rollout, so nothing was actually "
        f"swapped in the data plane: {rollout!r}"
    )

    # After the old target is deregistered, the old revision must never answer again.
    new_tasks = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 1 and ts[0]["taskArn"] != old_task_arn,
        timeout_s=420,
        interval_s=10,
        description=f"service {service} settled on one NEW task",
    )
    new_ip = _task_private_ip(new_tasks[0])
    assert new_ip, (
        f"the v2 task has no awsvpc private IP: {new_tasks[0].get('attachments')!r}"
    )
    healthy_ids = _poll_until(
        lambda: {k for k, v in _target_health(ctx, tg_arn).items() if v == "healthy"},
        lambda ids: ids == {new_ip},
        timeout_s=420,
        interval_s=10,
        description=f"the only healthy target is the v2 task {new_ip}",
    )
    assert healthy_ids == {new_ip}, (
        f"the old task's IP is still a healthy target after COMPLETED: healthy={healthy_ids!r} "
        f"new={new_ip!r} old={old_ip!r}"
    )

    settled: list[tuple[int | None, str | None]] = []
    for _ in range(12):
        status, body = _http_get(ctx, url)
        settled.append((status, _revision_of(body, marker)))
        time.sleep(1)
    assert all(s == 200 for s, _ in settled), (
        f"the service stopped answering after the rollout settled: {settled!r}"
    )
    assert {rev for _, rev in settled} == {"v2"}, (
        f"the OLD revision answered again after its target was deregistered — the rollout did not "
        f"roll forward, it flapped: {settled!r} (healthy targets {healthy_ids!r}, new {new_ip!r})"
    )

    # A witness independent of the ALB: the replacement container's OWN startup line, out of its
    # own log stream, names v2 — so the swap is not an inference from a response body alone.
    new_stream = f"ecs/app/{new_tasks[0]['taskArn'].rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, log_group, new_stream, timeout_s=420)
    new_msgs = _poll_until(
        lambda: _log_messages(ctx, log_group, new_stream),
        lambda ms: any(f"{marker}-v2 httpd-start" in m for m in ms),
        timeout_s=420,
        interval_s=5,
        description=f"the v2 container's start line in {new_stream}",
    )
    assert not any(f"{marker}-v1 httpd-start" in m for m in new_msgs), (
        f"the replacement task's own stream reports v1, so it is not the new revision: "
        f"{new_msgs!r}"
    )


def _revision(ctx, family, exec_role, log_group, body_marker):
    """One revision of `family` whose served body carries `body_marker`. Two of these differ in
    exactly one thing: the string the container writes into its index."""
    return _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": _target_image(ctx, "busybox"),
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


def _revision_of(body: str, marker: str) -> str | None:
    """'v1' / 'v2' / None, matched on the whole per-revision token (neither is a prefix of the
    other); an unrecognised body reads as None."""
    if body is None:
        return None
    if f"{marker}-v1 " in body or body.strip() == f"{marker}-v1":
        return "v1"
    if f"{marker}-v2 " in body or body.strip() == f"{marker}-v2":
        return "v2"
    return None



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
    """(vpc_id, subnet_ids) from the account's default VPC, one subnet per AZ.

    Default subnets route to an internet gateway, so no NAT gateway or EIP is needed."""
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
    """Create a role trusting trust_service with one inline policy; returns (name, arn).

    IAM is eventually consistent, so the role and policy are polled back; trust propagation is
    bounded by the later poll for the service's first RUNNING task."""
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
    except Exception as exc:  # noqa: BLE001 - transport-level, retried by the caller
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


#: Images the tasks run: the reference, its linux/amd64 image ID (the config digest), and the file
#: it is pre-seeded as with `docker save`. The check never pulls from a registry.
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
    """The pre-seeded image's config and gzip layers, verified against its pinned image ID.

    A missing or mismatched archive raises RequiredToolMissing, not a finding about the target.
    """
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
    """The URI of the pre-seeded image in an ECR repository this check creates, pushed once.

    Every blob goes through the target's own ECR layer-upload API (InitiateLayerUpload,
    UploadLayerPart, CompleteLayerUpload, PutImage), so the task's image comes from the target.
    """
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
