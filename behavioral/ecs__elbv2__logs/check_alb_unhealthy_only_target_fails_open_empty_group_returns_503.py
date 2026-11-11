"""alb-unhealthy-only-target-fails-open-empty-group-returns-503."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alb-unhealthy-only-target-fails-open-empty-group-returns-503"

GROUP = "container-load-balancing"

SERVICES = ["ecs", "elbv2", "logs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ALB whose only target is unhealthy (Target.ResponseCodeMismatch) fails open and serves it
    with 200; an empty target group returns 503; fixing the health-check path restores healthy 200s.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-health-checks.html
    """
    elb = ctx.client("elbv2")

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

    marker = "sim2real-503-" + ctx.unique_name("")[:8]
    td = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "command": _httpd_command(marker),
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=exec_role,
    )
    task_arn = _run_task(ctx, cluster, td["taskDefinitionArn"], subnets[:1], [task_sg])
    task = _await_task(ctx, cluster, task_arn, {"RUNNING", "STOPPED"}, timeout_s=720)
    assert task["lastStatus"] == "RUNNING", (
        f"the app task never started: stopCode={task.get('stopCode')} "
        f"reason={task.get('stoppedReason')}"
    )
    ip = _task_private_ip(task)
    assert ip, task.get("attachments")

    stream = f"ecs/app/{task_arn.rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, log_group, stream, timeout_s=300)
    _poll_until(
        lambda: _log_messages(ctx, log_group, stream),
        lambda ms: any(f"{marker} httpd-start" in m for m in ms),
        timeout_s=300,
        interval_s=5,
        description=f"httpd start line in {stream}",
    )

    # Only the health-check path is wrong; the container keeps serving on :80. A standalone task
    # rather than a service, so ECS cannot replace it when the health check fails.
    bad_path = "/sim2real-no-such-path"
    tg = _create_target_group(ctx, vpc_id, HealthCheckPath=bad_path)
    tg_arn = tg["TargetGroupArn"]
    lb = _create_alb(ctx, subnets, [alb_sg])
    _create_listener(ctx, lb["LoadBalancerArn"], tg_arn)
    url = "http://" + lb["DNSName"] + "/"

    elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": ip, "Port": 80}])
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: elb.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": ip, "Port": 80}])
        )
    )

    health = _poll_until(
        lambda: _target_health_reason(ctx, tg_arn, ip),
        lambda t: t.get("State") == "unhealthy",
        timeout_s=420,
        interval_s=10,
        description=f"target {ip} goes unhealthy against {bad_path}",
    )
    assert (
        health.get("Reason") == "Target.ResponseCodeMismatch"
    ), f"expected Target.ResponseCodeMismatch for a 404 on {bad_path}, got {health}"
    assert health.get("Description") == "Health checks failed with these codes: [404]", health

    # Routing and reported health are read together on every poll, so a forwarded request cannot
    # be explained by a health check that had not converged yet.
    _assert_stays(
        lambda: (_http_get(ctx, url), _target_health_reason(ctx, tg_arn, ip)),
        lambda observed: observed[0][0] == 200
        and marker in observed[0][1]
        and observed[1].get("State") == "unhealthy",
        seconds=60,
        interval_s=10,
        description=(
            f"with its only target unhealthy the ALB must FAIL OPEN -- serving 200 with the "
            f"container's marker {marker!r} while DescribeTargetHealth still reports unhealthy for "
            f"{ip}"
        ),
    )

    elb.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": ip, "Port": 80}])
    emptied = _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: not h,
        timeout_s=300,
        interval_s=10,
        description=f"target group {tg_arn} drains to empty after DeregisterTargets",
    )
    assert emptied == {}, (
        f"DeregisterTargets must leave the group with no targets at all, got {emptied}"
    )
    status, body = _poll_until(
        lambda: _http_get(ctx, url),
        lambda r: r[0] == 503,
        timeout_s=300,
        interval_s=10,
        description=f"load balancer returns 503 with an EMPTY target group at {url}",
    )
    assert status == 503, (status, body)
    assert marker not in body, (
        f"with no registered target there is nothing to forward to, so the container's marker "
        f"{marker!r} cannot appear in the response: body={body!r}"
    )
    still = _await_task(ctx, cluster, task_arn, {"RUNNING", "STOPPED"}, timeout_s=30)
    assert still["lastStatus"] == "RUNNING", (
        "the 503 must come from the routing decision, but the task itself stopped: "
        f"{still.get('stoppedReason')}"
    )
    elb.modify_target_group(TargetGroupArn=tg_arn, HealthCheckPath="/")
    elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": ip, "Port": 80}])
    _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: h.get(ip) == "healthy",
        timeout_s=420,
        interval_s=10,
        description=f"target {ip} healthy after the health-check path is corrected",
    )
    status, body = _poll_until(
        lambda: _http_get(ctx, url),
        lambda r: r[0] == 200,
        timeout_s=300,
        interval_s=5,
        description="load balancer serves the container once the target is healthy",
    )
    assert status == 200, (status, body)
    assert marker in body, body


# ECR Public busybox: an anonymous Fargate pull needs no registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


def _target_health_reason(ctx, tg_arn, target_id) -> dict:
    for d in ctx.client("elbv2").describe_target_health(TargetGroupArn=tg_arn)[
        "TargetHealthDescriptions"
    ]:
        if d["Target"]["Id"] == target_id:
            return d["TargetHealth"]
    return {}


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
            "TargetGroupNotFound",
        ):
            raise


def _safe(fn):
    """Run fn() and return its result, or None if it raised (probe helper)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _assert_stays(probe, predicate, *, seconds=60.0, interval_s=10.0, description="condition"):
    """Re-assert predicate(probe()) repeatedly across a bounded window; return the last observation.

    A steady-state routing rule needs repeated samples, since one response could be a stale node.
    """
    deadline = time.monotonic() + seconds
    while True:
        observed = probe()
        assert predicate(observed), f"{description} -- observed {observed!r}"
        if time.monotonic() >= deadline:
            return observed
        time.sleep(interval_s)


def _default_vpc(ctx, min_subnets=1):
    """(vpc_id, subnet_ids) from the run's shared network VPC, one subnet per AZ.

    No NAT gateway: a Fargate task with assignPublicIp=ENABLED pulls its image via the IGW route.
    """
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
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
    """A security group allowing inbound tcp/port from cidrs or source_sg.

    The delete is retried because an ENI keeps the group referenced after its owner is deleted.
    """
    ec2 = ctx.client("ec2")
    gid = ec2.create_security_group(
        GroupName=ctx.unique_name(_XSVC_PREFIX + "sg-"),
        Description="sim2real xsvc container archetype HTTP ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]

    def _drop():
        # An ENI that is still detaching keeps the group in use (DependencyViolation); retry that.
        deadline = time.monotonic() + 180.0
        while True:
            try:
                ec2.delete_security_group(GroupId=gid)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

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
    """Create a role trusting trust_service with one inline policy; returns (name, arn).

    IAM is eventually consistent, so the inline policy is polled back before use.
    """
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
    """Ensure AWSServiceRoleForECS exists; RunTask, unlike CreateService, does not create it.

    No teardown: the role is account-level and shared, and its delete fails while referenced.
    """
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        error = exc.response["Error"]
        # The role already exists: IAM refuses the name as taken.
        taken = (
            "Service role name AWSServiceRoleForECS has been taken in this account, please try a "
            "different suffix."
        )
        if (error["Code"], error.get("Message")) != ("InvalidInput", taken):
            raise AssertionError(f"cannot create the ECS service-linked role: {exc}") from exc
        return
    _poll_until(
        lambda: _safe(lambda: iam.get_role(RoleName="AWSServiceRoleForECS")),
        lambda r: r is not None,
        timeout_s=30,
        interval_s=2,
        description="AWSServiceRoleForECS visible after create",
    )


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


def _register_task_def(ctx, container_defs, *, execution_role_arn=None, task_role_arn=None):
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
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
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
            for s in logs.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream).get(
                "logStreams", []
            )
        ],
        lambda names: stream in names,
        timeout_s=timeout_s,
        interval_s=5,
        description=f"awslogs stream {stream} in {group}",
    )


def _http_get(ctx, url: str, timeout_s: float = 10.0):
    """(status, body) for a plain GET; an HTTP error status is returned, not raised.

    A transport failure returns (None, reason).
    """
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, headers={**({"User-Agent": "sim2real-xsvc"}), **_route})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # transport-level, retried by the caller
        return None, f"{type(exc).__name__}: {exc}"


def _httpd_command(marker: str) -> list[str]:
    """busybox httpd serving GET / -> "<marker> <hostname>" on :80, in the foreground.

    The body carries the container's hostname so a response can be attributed to a task."""
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
    """An ELBv2 target group with a 5s deregistration delay, so deregistration completes quickly."""
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
    """An internet-facing ALB, waited to 'active', so HTTP requests can reach it from outside."""
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
            if _safe(lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])) is None:
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


def _run_task(ctx, cluster, td_arn, subnets, sg_ids=None, retries=15, retry_sleep_s=8.0) -> str:
    """RunTask, with a bounded retry on the transient "unable to assume" role error.

    Covers a service-linked role or execution role that IAM has not yet propagated.
    """
    from botocore.exceptions import ClientError

    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    awsvpc: dict = {"subnets": subnets, "assignPublicIp": "ENABLED"}
    if sg_ids:
        awsvpc["securityGroups"] = sg_ids
    last_exc: Exception | None = None
    resp = None
    for _ in range(retries):
        try:
            resp = ecs.run_task(
                cluster=cluster,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration={"awsvpcConfiguration": awsvpc},
            )
            break
        except ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code")
            msg = str(exc).lower()
            if code in ("ClientException", "InvalidParameterException") and (
                "assume" in msg or "service linked role" in msg or "service-linked role" in msg
            ):
                time.sleep(retry_sleep_s)
                continue
            raise
    else:
        raise AssertionError(f"RunTask never succeeded after {retries} retries: {last_exc}")
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


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it.

    A deregistered revision stays INACTIVE until DeleteTaskDefinitions removes it.
    """
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
