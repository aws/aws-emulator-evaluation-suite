"""container-insights-publishes-cluster-metrics-and-performance-logs."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "container-insights-publishes-cluster-metrics-and-performance-logs"

GROUP = "container-insights"

SERVICES = ["cloudwatch", "ecs", "logs"]

# The task definition's reservations. Container Insights republishes both of these as
# metrics, so they are asserted back out of CloudWatch verbatim -- that is what ties the
# metric stream to THIS task definition rather than to a plausible-looking fabrication.
_TASK_CPU = "256"

_TASK_MEMORY_MB = 512

# Megabytes the task holds in tmpfs while MemoryUtilized is sampled. Evidence, not a threshold:
# Fargate still reports MemoryUtilized as 0 for it.
_BALLAST_MB = 48

# Metric names Container Insights publishes for a standalone Fargate task.
_TASK_METRICS = frozenset(
    {
        "CpuUtilized",
        "CpuReserved",
        "MemoryUtilized",
        "MemoryReserved",
        "EphemeralStorageUtilized",
        "EphemeralStorageReserved",
        "NetworkRxBytes",
        "NetworkTxBytes",
        "StorageReadBytes",
        "StorageWriteBytes",
    }
)

# Cluster-level metrics, published under ClusterName alone by the ClusterTelemetry stream.
_CLUSTER_METRICS = frozenset({"TaskCount", "ContainerInstanceCount", "ServiceCount"})


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics-ECS.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Enabling Container Insights publishes ECS/ContainerInsights metrics whose Reserved values,
    units and dimension sets match the task definition, plus a performance log group with records.
    """
    ecs = ctx.client("ecs")
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")

    subnets = [_public_subnet(ctx)]
    app_log_group = _create_log_group(ctx)
    cluster = _create_cluster(ctx, settings=[{"name": "containerInsights", "value": "enabled"}])
    perf_group = f"/aws/ecs/containerinsights/{cluster}/performance"
    # The telemetry agent keeps flushing after the task stops and recreates the group, so a
    # single delete is not enough. See _delete_perf_group.
    ctx.on_cleanup(lambda: _delete_perf_group(ctx, cluster, perf_group))

    described = ecs.describe_clusters(clusters=[cluster], include=["SETTINGS"])["clusters"][0]
    settings = {s["name"]: s["value"] for s in described.get("settings", [])}
    assert settings.get("containerInsights") == "enabled", settings

    dimensions = [{"Name": "ClusterName", "Value": cluster}]
    baseline = cw.list_metrics(Namespace="ECS/ContainerInsights", Dimensions=dimensions).get(
        "Metrics", []
    )
    assert baseline == [], f"metrics already exist for a brand-new cluster: {baseline}"

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
    marker = "sim2real-insights-" + ctx.unique_name("")[:8]
    td = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "command": [
                    "sh",
                    "-c",
                    # The ballast is allocated BEFORE the marker is echoed, so a run that
                    # reaches the app-log assertion at the end has necessarily allocated it.
                    f"dd if=/dev/zero of=/dev/shm/ballast bs=1M count={_BALLAST_MB} "
                    f"&& echo {marker}; sleep 900",
                ],
                "logConfiguration": _awslogs(app_log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=exec_role,
    )
    started_at = datetime.datetime.now(datetime.timezone.utc)
    # RunTask is the execution role's first use: until IAM propagates the new role, RunTask
    # refuses with "ECS was unable to assume the role", so that refusal is retried, bounded.
    launch_deadline = time.monotonic() + 120.0
    while True:
        try:
            task_arn = _run_task(ctx, cluster, td["taskDefinitionArn"], subnets)
            break
        except ClientError as exc:
            if (
                "unable to assume the role" not in exc.response["Error"].get("Message", "")
                or time.monotonic() > launch_deadline
            ):
                raise
        time.sleep(2)
    task = _await_task(ctx, cluster, task_arn, {"RUNNING", "STOPPED"}, timeout_s=720)
    assert task["lastStatus"] == "RUNNING", (
        f"task never ran: stopCode={task.get('stopCode')} " f"reason={task.get('stoppedReason')}"
    )

    # --- Effect 1: ECS actually publishes the Container Insights metrics.
    family = td["family"]
    metrics = _poll_until(
        lambda: cw.list_metrics(Namespace="ECS/ContainerInsights", Dimensions=dimensions).get(
            "Metrics", []
        ),
        lambda ms: (_TASK_METRICS | _CLUSTER_METRICS) <= {m["MetricName"] for m in ms},
        timeout_s=900,
        interval_s=2,
        ctx=ctx,
        description=(
            f"the full ECS/ContainerInsights metric set for cluster {cluster}: "
            f"{sorted(_TASK_METRICS | _CLUSTER_METRICS)}"
        ),
    )
    names = {m["MetricName"] for m in metrics}
    assert _TASK_METRICS <= names, f"missing task metrics: {sorted(_TASK_METRICS - names)}"
    assert _CLUSTER_METRICS <= names, f"missing cluster metrics: {sorted(_CLUSTER_METRICS - names)}"

    # Real AWS publishes every task metric under TWO dimension sets, and the cluster
    # metrics under ClusterName alone. An emulator that publishes one flat dimension set
    # breaks every per-task-definition dashboard.
    dimsets = {tuple(sorted(d["Name"] for d in m["Dimensions"])) for m in metrics}
    assert ("ClusterName",) in dimsets, dimsets
    assert ("ClusterName", "TaskDefinitionFamily") in dimsets, dimsets
    families = {
        d["Value"] for m in metrics for d in m["Dimensions"] if d["Name"] == "TaskDefinitionFamily"
    }
    assert families == {family}, (
        f"the TaskDefinitionFamily dimension must carry exactly this run's family "
        f"{family!r}, got {sorted(families)}"
    )
    fam_dims = [
        {"Name": "ClusterName", "Value": cluster},
        {"Name": "TaskDefinitionFamily", "Value": family},
    ]

    # The reservations round-trip from the task definition into CloudWatch verbatim.
    mem_reserved = _await_metric_value(
        ctx, "MemoryReserved", fam_dims, started_at, float(_TASK_MEMORY_MB)
    )
    assert mem_reserved["Maximum"] == float(_TASK_MEMORY_MB), (
        f"MemoryReserved must equal the task definition's memory ({_TASK_MEMORY_MB} MB) "
        f"exactly, got {mem_reserved}"
    )
    assert mem_reserved["Unit"] == "Megabytes", (
        f"MemoryReserved is published in Megabytes, got {mem_reserved.get('Unit')!r}"
    )
    assert mem_reserved["SampleCount"] >= 1, mem_reserved

    cpu_reserved = _await_metric_value(
        ctx, "CpuReserved", fam_dims, started_at, float(_TASK_CPU)
    )
    assert cpu_reserved["Maximum"] == float(_TASK_CPU), (
        f"CpuReserved must equal the task definition's cpu ({_TASK_CPU} units) exactly, "
        f"got {cpu_reserved}"
    )
    assert cpu_reserved["Unit"] == "None", (
        f"the Cpu* metrics are unitless -- real AWS reports the literal unit 'None', not "
        f"Percent and not a missing key; got {cpu_reserved.get('Unit')!r}"
    )

    # Utilized is sampled in the same units and bounded by the hard reservation. Fargate reports
    # it as 0.0 even with the tmpfs ballast, so the bound, not a floor, is the invariant.
    mem_used = _await_datapoints(ctx, "MemoryUtilized", fam_dims, started_at)
    mem_used_max = max(d["Maximum"] for d in mem_used)
    assert mem_used_max <= float(_TASK_MEMORY_MB), (
        f"MemoryUtilized ({mem_used_max}) cannot exceed the reserved {_TASK_MEMORY_MB} MB, "
        f"which Fargate enforces as a hard limit"
    )
    assert all(d["Unit"] == "Megabytes" for d in mem_used), (
        f"MemoryUtilized must be published in the same unit as MemoryReserved, got "
        f"{sorted({d.get('Unit') for d in mem_used})}"
    )
    cpu_used = _await_datapoints(ctx, "CpuUtilized", fam_dims, started_at)
    assert max(d["Maximum"] for d in cpu_used) <= float(_TASK_CPU), cpu_used
    assert all(d["Unit"] == "None" for d in cpu_used), (
        f"CpuUtilized must be unitless like CpuReserved, got "
        f"{sorted({d.get('Unit') for d in cpu_used})}"
    )

    storage_reserved = _await_datapoints(ctx, "EphemeralStorageReserved", fam_dims, started_at)
    storage_units = sorted({d.get("Unit") for d in storage_reserved})
    assert all(d["Unit"] == "Gigabytes" for d in storage_reserved), (
        f"EphemeralStorageReserved is published in Gigabytes -- a different unit from the "
        f"memory family, which is the point; got {storage_units}"
    )
    assert max(d["Maximum"] for d in storage_reserved) >= 20.0, (
        f"a Fargate task reserves at least 20 GB of ephemeral storage (measured 21.47), "
        f"got {storage_reserved}"
    )

    # The cluster telemetry path counts the running task, under ClusterName alone.
    task_count = _await_metric_value(ctx, "TaskCount", dimensions, started_at, 1.0)
    assert task_count["Maximum"] == 1.0, (
        f"TaskCount must be 1 while exactly one task runs in this cluster, got {task_count}"
    )
    assert task_count["Unit"] == "Count", task_count.get("Unit")

    # --- Effect 2: the performance log group is created and written to.
    _poll_until(
        lambda: [
            g["logGroupName"]
            for g in logs.describe_log_groups(logGroupNamePrefix=perf_group).get("logGroups", [])
        ],
        lambda gs: perf_group in gs,
        timeout_s=900,
        interval_s=2,
        ctx=ctx,
        description=f"Container Insights performance log group {perf_group}",
    )
    # Real AWS writes TWO differently-named streams here: the cluster telemetry stream is
    # named after the cluster, and the task telemetry stream is FargateTelemetry-<n>.
    cluster_stream = f"ClusterTelemetry-{cluster}"
    streams = _poll_until(
        lambda: [
            s["logStreamName"]
            for s in logs.describe_log_streams(logGroupName=perf_group).get("logStreams", [])
        ],
        lambda ss: cluster_stream in ss
        and any(s.startswith("FargateTelemetry-") for s in ss),
        timeout_s=600,
        interval_s=2,
        ctx=ctx,
        description=(
            f"both performance streams in {perf_group}: {cluster_stream!r} and a "
            f"'FargateTelemetry-*' stream"
        ),
    )
    assert cluster_stream in streams, (
        f"the cluster telemetry stream must be named after the cluster, got {streams}"
    )
    fargate_streams = [s for s in streams if s.startswith("FargateTelemetry-")]
    assert fargate_streams, f"no FargateTelemetry-* stream in {streams}"

    # The task record inside that stream is the SOURCE of the metrics asserted above, so it
    # must agree with them and name this exact task.
    task_id = task_arn.rsplit("/", 1)[-1]
    task_record = _poll_until(
        lambda: _perf_record(ctx, perf_group, fargate_streams[0], "Task"),
        lambda r: r is not None and r.get("TaskId") == task_id,
        timeout_s=600,
        interval_s=2,
        ctx=ctx,
        description=f"a Type=Task performance record for task {task_id}",
    )
    assert task_record["TaskDefinitionFamily"] == family, task_record
    assert task_record["MemoryReserved"] == _TASK_MEMORY_MB, (
        f"the performance record must report the same reservation as the metric "
        f"({_TASK_MEMORY_MB}), got {task_record.get('MemoryReserved')!r}"
    )
    assert task_record["LaunchType"] == "FARGATE", task_record.get("LaunchType")
    emf_dims = [
        tuple(sorted(dim))
        for block in task_record["CloudWatchMetrics"]
        for dim in block["Dimensions"]
    ]
    assert ("ClusterName",) in emf_dims and (
        "ClusterName",
        "TaskDefinitionFamily",
    ) in emf_dims, (
        f"the embedded-metric-format record must declare the same two dimension sets the "
        f"namespace exposes, got {emf_dims}"
    )

    # --- And the task's own application logs still work alongside the insights path.
    app_stream = f"ecs/app/{task_arn.rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, app_log_group, app_stream, timeout_s=300)
    _await_log_marker(ctx, app_log_group, app_stream, marker, timeout_s=300)


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn, *gone_codes):
    """Run a teardown step fn(); return on the resource's not-found codes, raise anything else."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone_codes:
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition",
                ctx=None):
    """Return probe() once predicate holds; raise at timeout_s (capped by ctx's time left)."""
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


def _delete_perf_group(ctx, cluster, perf_group, *, attempts=6, delay=45.0):
    """Delete the Container Insights performance log group, re-deleting it while the telemetry
    agent's late flushes recreate it, after waiting for the cluster's tasks to be gone."""
    ecs = ctx.client("ecs")
    logs = ctx.client("logs")
    _poll_until(
        lambda: ecs.list_tasks(cluster=cluster).get("taskArns", []),
        lambda arns: not arns,
        timeout_s=300,
        interval_s=10,
        description=f"all tasks gone from {cluster}",
    )
    for _ in range(attempts):
        _unless_gone(lambda: logs.delete_log_group(logGroupName=perf_group), "ResourceNotFoundException")
        time.sleep(delay)
        alive = [
            g["logGroupName"]
            for g in logs.describe_log_groups(logGroupNamePrefix=perf_group).get("logGroups", [])
            if g["logGroupName"] == perf_group
        ]
        if not alive:
            return
    raise AssertionError(
        f"LEAK: performance log group {perf_group} kept being recreated after "
        f"{attempts} deletes -- it must not be left behind"
    )


def _insights_datapoints(ctx, metric_name, dimensions, started_at):
    """Datapoints for one ECS/ContainerInsights metric from the task's launch onward."""
    return (
        ctx.client("cloudwatch")
        .get_metric_statistics(
            Namespace="ECS/ContainerInsights",
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=started_at - datetime.timedelta(minutes=5),
            EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1),
            Period=60,
            Statistics=["Maximum", "Minimum", "SampleCount"],
        )
        .get("Datapoints", [])
    )


def _await_datapoints(ctx, metric_name, dimensions, started_at, timeout_s=600.0):
    """Poll until the metric has at least one datapoint; return them all."""
    return _poll_until(
        lambda: _insights_datapoints(ctx, metric_name, dimensions, started_at),
        lambda ds: bool(ds),
        timeout_s=timeout_s,
        interval_s=2,
        ctx=ctx,
        description=f"a {metric_name} datapoint for {dimensions}",
    )


def _await_metric_value(ctx, metric_name, dimensions, started_at, expected, timeout_s=600.0):
    """Poll until the metric reports `expected` as a Maximum; return that datapoint, so a slow
    first publish is not read as a wrong value."""
    datapoints = _poll_until(
        lambda: _insights_datapoints(ctx, metric_name, dimensions, started_at),
        lambda ds: any(d["Maximum"] == expected for d in ds),
        timeout_s=timeout_s,
        interval_s=2,
        ctx=ctx,
        description=f"{metric_name}=={expected} for {dimensions}",
    )
    return next(d for d in datapoints if d["Maximum"] == expected)


def _perf_record(ctx, group, stream, record_type, limit=25):
    """Newest Container Insights performance record of the given Type, or None."""
    events = (
        _safe(
            lambda: ctx.client("logs").get_log_events(
                logGroupName=group, logStreamName=stream, limit=limit, startFromHead=False
            )
        )
        or {}
    ).get("events", [])
    for event in reversed(events):
        parsed = _safe(lambda msg=event.get("message", ""): json.loads(msg))
        if isinstance(parsed, dict) and parsed.get("Type") == record_type:
            return parsed
    return None


def _public_subnet(ctx) -> str:
    """A self-owned VPC with one internet-routed subnet, so a Fargate task with
    assignPublicIp=ENABLED pulls its public image with no NAT gateway or EIP."""
    ec2 = ctx.client("ec2")
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert zones, f"no available availability zone in {ctx.region}"
    name = ctx.unique_name(_XSVC_PREFIX + "net-")

    def spec(kind):
        tags = [{"Key": "Name", "Value": name}] + _tags_kv()
        return [{"ResourceType": kind, "Tags": tags}]

    vpc = ec2.create_vpc(CidrBlock="10.42.0.0/16", TagSpecifications=spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_vpc(VpcId=vpc)))
    igw = ec2.create_internet_gateway(TagSpecifications=spec("internet-gateway"))[
        "InternetGateway"
    ]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(
        lambda: _delete_when_free(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc))
    )
    rt = ec2.create_route_table(VpcId=vpc, TagSpecifications=spec("route-table"))["RouteTable"][
        "RouteTableId"
    ]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_route_table(RouteTableId=rt)))
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.42.0.0/24", AvailabilityZone=zones[0], TagSpecifications=spec("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_subnet(SubnetId=subnet)))
    assoc = ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.disassociate_route_table(AssociationId=assoc)))
    return subnet


def _delete_when_free(fn, timeout_s=600.0):
    """Teardown step retried while a stopping task's ENI still holds the network
    (DependencyViolation); any other error, or the deadline, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(10)


def _iam_role(ctx, kind, trust_service, statements):
    """Create a role trusting trust_service with ONE inline policy; returns (name, arn).

    IAM is eventually consistent, so the inline policy is polled back before returning."""
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
        _unless_gone(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity")
        _unless_gone(lambda: iam.delete_role(RoleName=name), "NoSuchEntity")

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
        ctx=ctx,
        description=f"role {name} inline policy readable",
    )
    return name, arn


def _ensure_ecs_slr(ctx) -> None:
    """RunTask on Fargate needs AWSServiceRoleForECS (CreateService auto-creates it,
    RunTask does not). Idempotent — already-exists is success."""
    _safe(
        lambda: ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    )


def _create_cluster(ctx, settings=None) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-cluster-")
    kwargs: dict = {"clusterName": name, "tags": _ecs_tags_kv()}
    if settings:
        kwargs["settings"] = settings
    ecs.create_cluster(**kwargs)

    def _drop():
        # A DRAINING service / stopping task can block delete briefly: retry exactly those refusals.
        deadline = time.monotonic() + 80.0
        while True:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ClusterNotFoundException":
                    return
                if code not in (
                    "ClusterContainsTasksException", "ClusterContainsServicesException", "UpdateInProgressException",
                ) or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_drop)
    return name


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(_XSVC_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _unless_gone(lambda: logs.delete_log_group(logGroupName=name), "ResourceNotFoundException"))
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
        cpu=_TASK_CPU,
        memory=str(_TASK_MEMORY_MB),
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
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.stop_task(cluster=cluster, task=arn), "ClusterNotFoundException"))
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
        interval_s=2,
        ctx=ctx,
        description=f"task {task_arn} lastStatus in {sorted(statuses)}",
    )


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
        interval_s=2,
        ctx=ctx,
        description=f"awslogs stream {stream} in {group}",
    )


def _await_log_marker(ctx, group: str, stream: str, marker: str, timeout_s=300.0) -> list[str]:
    msgs = _poll_until(
        lambda: _log_messages(ctx, group, stream),
        lambda ms: any(marker in m for m in ms),
        timeout_s=timeout_s,
        interval_s=2,
        ctx=ctx,
        description=f"marker {marker!r} in {group}/{stream}",
    )
    assert any(marker in m for m in msgs), msgs
    return msgs


# ECR Public busybox: a tiny image an anonymous Fargate pull can always fetch, so a
# check about logging/networking is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


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
