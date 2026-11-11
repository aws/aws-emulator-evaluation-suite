"""deep-ecs-1-guestdepth-firelens-fluentbit-routes-app-output."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-ecs-1-guestdepth-firelens-fluentbit-routes-app-output"

GROUP = "guest-log-routing"

SERVICES = ["ec2", "ecs", "logs"]

_FLUENT_BIT_IMAGE = "public.ecr.aws/aws-observability/aws-for-fluent-bit:stable"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """With awsfirelens, a fluent-bit sidecar writes the app's stdout/stderr as JSON records (log, source,
    ecs_task_arn) under its own stream name; an awslogs twin task writes the raw lines under
    ecs/app/<task-id> in its own group, and nothing of the FireLens app reaches that path.
    """
    subnets, sg = _network(ctx)
    fl_group = _create_log_group(ctx)
    aw_group = _create_log_group(ctx)
    router_group = _create_log_group(ctx)
    _r, exec_role = _iam_role(
        ctx, "ecs-exec", "ecs-tasks.amazonaws.com",
        [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
          "Resource": "*"}],
    )
    _r2, task_role = _iam_role(
        ctx, "ecs-task", "ecs-tasks.amazonaws.com",
        [{"Effect": "Allow",
          "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
          "Resource": "*"}],
    )
    cluster = _create_cluster(ctx)

    marker = ctx.unique_name("sim2real-flmark-")
    out_line, err_line = f"{marker}-stdout", f"{marker}-stderr"
    fl_stream = ctx.unique_name("fl-")
    # Linger a few flush intervals so fluent-bit has flushed before the essential app exit stops
    # the task.
    app_cmd = ["sh", "-c", f"echo {out_line}; echo {err_line} >&2; sleep 5"]

    fl_td = _register_task_def(
        ctx,
        [
            {
                "name": "log_router",
                "image": _FLUENT_BIT_IMAGE,
                "essential": False,
                "memoryReservation": 64,
                "firelensConfiguration": {"type": "fluentbit"},
                "logConfiguration": _awslogs(router_group, ctx.region, "router"),
            },
            {
                "name": "app",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "command": app_cmd,
                "dependsOn": [{"containerName": "log_router", "condition": "START"}],
                "logConfiguration": {
                    "logDriver": "awsfirelens",
                    "options": {
                        "Name": "cloudwatch_logs",
                        "region": ctx.region,
                        "log_group_name": fl_group,
                        "log_stream_name": fl_stream,
                        "auto_create_group": "false",
                    },
                },
            },
        ],
        execution_role_arn=exec_role,
        task_role_arn=task_role,
        runtime_platform={"operatingSystemFamily": "LINUX", "cpuArchitecture": "X86_64"},
    )
    aw_td = _register_task_def(
        ctx,
        [{"name": "app", "image": _PUBLIC_IMAGE, "essential": True, "command": app_cmd,
          "logConfiguration": _awslogs(aw_group, ctx.region, "ecs")}],
        execution_role_arn=exec_role,
        runtime_platform={"operatingSystemFamily": "LINUX", "cpuArchitecture": "X86_64"},
    )

    (fl_arn, fl_task), (aw_arn, aw_task) = _run_assumed(
        ctx, cluster, [fl_td["taskDefinitionArn"], aw_td["taskDefinitionArn"]], subnets, [sg],
        timeout_s=900)
    for label, task in (("firelens", fl_task), ("awslogs twin", aw_task)):
        app = {c["name"]: c for c in task.get("containers", [])}.get("app", {})
        assert app.get("exitCode") == 0, (
            f"{label} app did not exit 0: {app!r} stoppedReason={task.get('stoppedReason')!r}"
        )

    # --- FireLens path: JSON records written by fluent-bit under ITS stream name.
    _await_log_stream(ctx, fl_group, fl_stream, timeout_s=420)
    fl_msgs = _poll_until(
        lambda: _log_messages(ctx, fl_group, fl_stream),
        lambda ms: sum(1 for m in ms if marker in m) >= 2,
        timeout_s=420, interval_s=2, ctx=ctx,
        description=f"both marker lines in firelens stream {fl_stream}",
    )
    records = []
    for m in fl_msgs:
        try:
            records.append(json.loads(m))
        except ValueError:
            raise AssertionError(f"FireLens event is not a JSON record: {m!r}") from None
    by_log = {r.get("log"): r for r in records if isinstance(r, dict)}
    out_rec, err_rec = by_log.get(out_line), by_log.get(err_line)
    assert out_rec and err_rec, (
        f"FireLens stream lacks records whose log field is exactly the marker lines: {records!r}"
    )
    assert (out_rec.get("source"), err_rec.get("source")) == ("stdout", "stderr"), (
        f"FireLens did not tag the two lines by stream: out={out_rec!r} err={err_rec!r}"
    )
    for rec in (out_rec, err_rec):
        assert rec.get("ecs_task_arn") == fl_arn and rec.get("container_name") == "app", (
            f"FireLens record does not carry this task's ECS metadata (task {fl_arn!r}): {rec!r}"
        )
    tasks_seen = {r.get("ecs_task_arn") for r in records if isinstance(r, dict)}
    assert tasks_seen == {fl_arn}, (
        f"the FireLens group received records from tasks other than the FireLens one: "
        f"{sorted(map(str, tasks_seen))!r} (twin was {aw_arn!r})"
    )
    fl_streams = _stream_names(ctx, fl_group)
    assert fl_streams == [fl_stream], (
        f"the FireLens group should hold only fluent-bit's stream {fl_stream!r}: {fl_streams!r}"
    )

    # --- awslogs twin: the raw lines, under the driver's own naming, in its own group.
    aw_stream = f"ecs/app/{aw_arn.rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, aw_group, aw_stream, timeout_s=420)
    aw_msgs = _poll_until(
        lambda: _log_messages(ctx, aw_group, aw_stream),
        lambda ms: out_line in ms and err_line in ms,
        timeout_s=420, interval_s=2, ctx=ctx,
        description=f"both raw marker lines in awslogs stream {aw_stream}",
    )
    assert sorted(m for m in aw_msgs if marker in m) == sorted([out_line, err_line]), (
        f"awslogs should carry the two raw lines verbatim, got {aw_msgs!r}"
    )

    # The FireLens app container had no awslogs path: nothing of it reached the router's group.
    fl_id = fl_arn.rsplit("/", 1)[-1]
    router_streams = _stream_names(ctx, router_group)
    assert not any(s.endswith(f"/app/{fl_id}") for s in router_streams), (
        f"the FireLens app container also got an awslogs stream: {router_streams!r}"
    )
    _release_network(ctx, subnets)


def _stream_names(ctx, group: str) -> list[str]:
    """Every stream in the group, PAGINATED."""
    logs = ctx.client("logs")
    names: list[str] = []
    token = None
    while True:
        kwargs = {"logGroupName": group}
        if token:
            kwargs["nextToken"] = token
        page = logs.describe_log_streams(**kwargs)
        names += [s["logStreamName"] for s in page.get("logStreams", [])]
        token = page.get("nextToken")
        if not token:
            return names


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
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown
        pass


#: Error-code endings that mean a teardown's target is already gone.
_GONE_SUFFIXES = ("NotFound", "NotFoundException", "NoSuchEntity", "NotAttached")


def _delete(fn, retry=("DependencyViolation",), timeout_s=60.0):
    """Teardown step: a not-found means already gone and a *retry* code is retried every 2 s to
    timeout_s; every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - re-raised unless the target is already gone
            code = str(getattr(exc, "response", {}).get("Error", {}).get("Code") or "")
            if code.endswith(_GONE_SUFFIXES):
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition",
                ctx=None):
    """Poll probe() until predicate(result) is truthy; raise on timeout (ctx caps the wait)."""
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
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _network(ctx):
    """A VPC of this check's own: 2 public subnets in 2 derived AZs + an IGW route, nothing ambient.

    Its teardown first waits for the Fargate ENIs ECS deletes asynchronously after a task stops: a
    subnet still holding one fails DeleteSubnet with DependencyViolation.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(_XSVC_PREFIX + "vpc-")

    def tagspec(rtype):
        return [{"ResourceType": rtype, "Tags": _tags_kv() + [{"Key": "Name", "Value": name}]}]

    made: dict = {"subnets": []}
    vpc_id = ec2.create_vpc(CidrBlock="10.77.0.0/16",
                            TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    made["vpc"] = vpc_id

    def _drop():
        def enis():
            return ec2.describe_network_interfaces(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("NetworkInterfaces", [])
        _delete(lambda: _poll_until(enis, lambda r: not r, timeout_s=420, interval_s=2,
                                     description=f"ENIs gone from {vpc_id}"))
        for sn in made["subnets"]:
            _delete(lambda sn=sn: ec2.delete_subnet(SubnetId=sn))
        if made.get("igw"):
            _delete(lambda: ec2.detach_internet_gateway(InternetGatewayId=made["igw"],
                                                         VpcId=vpc_id))
            _delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=made["igw"]))
        last = None
        for _ in range(6):
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except Exception as exc:  # noqa: BLE001 - a just-deleted subnet can lag
                if getattr(exc, "response", {}).get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    return
                last = exc
                time.sleep(10)
        raise RuntimeError(f"VPC {vpc_id} was not deleted: {last!r}")

    ctx.on_cleanup(_drop)
    _poll_until(lambda: _safe(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]),
                lambda s: s == "available", timeout_s=120, interval_s=2, ctx=ctx,
                description=f"{vpc_id} available")
    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    made["igw"] = igw
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    main_rt = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=main_rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"need two available AZs, region offers {zones!r}"
    for i, az in enumerate(zones[:2]):
        sn = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
        made["subnets"].append(sn)
    sg = ec2.describe_security_groups(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]},
    ])["SecurityGroups"][0]["GroupId"]
    return list(made["subnets"]), sg


def _release_network(ctx, subnets) -> None:
    """Wait (bounded, never asserting) for the task ENIs ECS deletes after STOPPED to leave.

    Done in the body because cleanup is bounded at 60 s, and a subnet still holding a Fargate ENI
    fails DeleteSubnet/DeleteVpc.
    """
    ec2 = ctx.client("ec2")
    _swallow(lambda: _poll_until(
        lambda: ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": list(subnets)}]).get("NetworkInterfaces", []),
        lambda r: not r, timeout_s=300, interval_s=2, ctx=ctx,
        description="task ENIs released from this check's subnets"))


def _iam_role(ctx, kind, trust_service, statements=None, managed_arns=()):
    """Create a role trusting trust_service with an inline policy and/or managed policies.

    IAM is eventually consistent: the role and policy are polled back here; trust-policy
    propagation to the assuming service is covered by retrying the first use (_run_assumed).
    """
    iam = ctx.client("iam")
    name = ctx.unique_name(_XSVC_PREFIX + kind + "-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _drop():
        _delete(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        for m in managed_arns:
            _delete(lambda m=m: iam.detach_role_policy(RoleName=name, PolicyArn=m))
        _delete(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_drop)
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="inline",
                            PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                       "Statement": statements}))
        _poll_until(lambda: _safe(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
                    lambda r: r is not None, timeout_s=60, interval_s=2, ctx=ctx,
                    description=f"role {name} inline policy readable")
    for m in managed_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=m)
    return name, arn


def _ensure_ecs_slr(ctx) -> None:
    """RunTask on Fargate needs AWSServiceRoleForECS (CreateService auto-creates it, RunTask does
    not). Idempotent — already-exists is success."""
    _swallow(
        lambda: ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    )


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags_kv())

    def _drop():
        last = None
        for _ in range(8):
            try:
                ecs.delete_cluster(cluster=name)
                return
            except Exception as exc:  # noqa: BLE001 - a stopping task can block delete briefly
                if getattr(exc, "response", {}).get("Error", {}).get("Code") == "ClusterNotFoundException":
                    return
                last = exc
                time.sleep(10)
        raise RuntimeError(f"cluster {name} was not deleted: {last!r}")

    ctx.on_cleanup(_drop)
    _poll_until(lambda: _safe(lambda: ecs.describe_clusters(clusters=[name])["clusters"][0]
                              ["status"]),
                lambda s: s == "ACTIVE", timeout_s=120, interval_s=2, ctx=ctx,
                description=f"cluster {name} ACTIVE")
    return name


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(_XSVC_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _delete(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _awslogs(log_group: str, region: str, prefix: str = "ecs") -> dict:
    return {
        "logDriver": "awslogs",
        "options": {"awslogs-group": log_group, "awslogs-region": region,
                    "awslogs-stream-prefix": prefix},
    }


def _register_task_def(ctx, container_defs, *, execution_role_arn=None, task_role_arn=None,
                       volumes=None, runtime_platform=None, pid_mode=None, cpu="256",
                       memory="512"):
    ecs = ctx.client("ecs")
    kwargs: dict = dict(
        family=ctx.unique_name(_XSVC_PREFIX + "td-"),
        containerDefinitions=container_defs,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu=cpu,
        memory=memory,
        tags=_ecs_tags_kv(),
    )
    if execution_role_arn:
        kwargs["executionRoleArn"] = execution_role_arn
    if task_role_arn:
        kwargs["taskRoleArn"] = task_role_arn
    if volumes:
        kwargs["volumes"] = volumes
    if runtime_platform:
        kwargs["runtimePlatform"] = runtime_platform
    if pid_mode:
        kwargs["pidMode"] = pid_mode
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    arn = td["taskDefinitionArn"]

    def _drop():
        _delete(lambda: ecs.deregister_task_definition(taskDefinition=arn))
        _delete(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))

    ctx.on_cleanup(_drop)
    return td


def _run_task(ctx, cluster, td_arn, subnets, sg_ids, **extra) -> str:
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    resp = _with_new_cluster_retry(lambda: ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="FARGATE",
        platformVersion="LATEST",
        count=1,
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnets, "securityGroups": sg_ids, "assignPublicIp": "ENABLED"}},
        **extra,
    ))
    assert not resp.get("failures"), f"RunTask failures: {resp.get('failures')!r}"
    arn = resp["tasks"][0]["taskArn"]

    def _drop():
        _delete(lambda: ecs.stop_task(cluster=cluster, task=arn))
        _delete(lambda: _await_task(ctx, cluster, arn, {"STOPPED"}, timeout_s=240))

    ctx.on_cleanup(_drop)
    return arn


def _run_assumed(ctx, cluster, td_arns, subnets, sg_ids, timeout_s):
    """Start every task definition, then await each STOPPED; a task the fresh roles could not yet
    serve (RunTask refused, or the task stopped, on role assumption) is rerun, every 2 s to a deadline."""
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    arns: list = [None] * len(td_arns)
    tasks: list = [None] * len(td_arns)
    while True:
        for i, td_arn in enumerate(td_arns):
            if arns[i] is None:
                try:
                    arns[i] = _run_task(ctx, cluster, td_arn, subnets, sg_ids)
                except Exception as exc:  # noqa: BLE001 - re-raised unless it is the propagation refusal
                    message = str(getattr(exc, "response", {}).get("Error", {}).get("Message", ""))
                    if "assume" not in message.lower() or time.monotonic() >= deadline:
                        raise
        for i, arn in enumerate(arns):
            if arn is not None and tasks[i] is None:
                task = _await_task(ctx, cluster, arn, {"STOPPED"}, timeout_s=timeout_s, bound=True)
                if "assume" in str(task.get("stoppedReason") or "").lower() \
                        and time.monotonic() < deadline:
                    arns[i] = None
                else:
                    tasks[i] = task
        if all(t is not None for t in tasks):
            return list(zip(arns, tasks))
        time.sleep(2)


def _with_new_cluster_retry(call, timeout_s=90.0):
    """Run call(), retrying ONLY ClusterNotFoundException for a bounded window.

    RunTask seconds after CreateCluster (even with DescribeClusters ACTIVE) can still answer
    ClusterNotFoundException; any other outcome is returned or raised unchanged.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except Exception as exc:  # noqa: BLE001 - re-raised unless it is the propagation code
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "ClusterNotFoundException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _await_task(ctx, cluster, task_arn, statuses, timeout_s=600.0, bound=False):
    ecs = ctx.client("ecs")

    def probe():
        found = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return found[0] if found else {}

    return _poll_until(
        probe,
        lambda t: t.get("lastStatus") in statuses,
        timeout_s=timeout_s,
        interval_s=2,
        ctx=ctx if bound else None,
        description=f"task {task_arn} lastStatus in {sorted(statuses)}",
    )


def _log_messages(ctx, group: str, stream: str) -> list[str]:
    """Every event in the stream, PAGINATED forward from the head."""
    logs = ctx.client("logs")
    msgs: list[str] = []
    token = None
    while True:
        kwargs: dict = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
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
        lambda: [s["logStreamName"] for s in logs.describe_log_streams(
            logGroupName=group, logStreamNamePrefix=stream).get("logStreams", [])],
        lambda names: stream in names,
        timeout_s=timeout_s,
        interval_s=2,
        ctx=ctx,
        description=f"log stream {stream} in {group}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
