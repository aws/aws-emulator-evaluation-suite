"""obs-ecs-2-account-default-insights-inherited-explicit-disabled-publishes-nothing."""

from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "obs-ecs-2-account-default-insights-inherited-explicit-disabled-publishes-nothing"

GROUP = "container-insights"

SERVICES = ["cloudwatch", "ecs", "logs"]

_INSIGHTS_NS = "ECS/ContainerInsights"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics-ECS.html
@tags(
    "axis:negative-delivery",
    "concern:metrics",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c3",
    "cap:c5", "resource:account-singleton:ecs-account-settings",
    "timing:real-time",
)
def run(ctx) -> None:
    """A bare cluster inherits an enabled containerInsights account default and publishes TaskCount;
    a sibling with explicit disabled publishes no metrics or log group until enabled.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-container-insights.html
    """
    ecs = ctx.client("ecs")

    # A principal-level containerInsights setting overrides the account default this check
    # exercises, so one found on the caller is removed for the run and its value put back after.
    explicit_self = ecs.list_account_settings(
        name="containerInsights", effectiveSettings=False
    ).get("settings", [])
    if explicit_self:
        own_value = explicit_self[0]["value"]
        ecs.delete_account_setting(name="containerInsights")
        ctx.on_cleanup(
            lambda: ecs.put_account_setting(name="containerInsights", value=own_value)
        )
    before = ecs.list_account_settings(name="containerInsights", effectiveSettings=True).get(
        "settings", []
    )
    assert len(before) == 1 and before[0].get("value"), (
        f"ListAccountSettings(effective) must resolve exactly one containerInsights value, got {before!r}"
    )
    prior_value = before[0]["value"]

    subnets, net = _own_network(ctx)
    td_arn = _register_task_def(ctx)

    # Restoration is registered before anything else.
    put = ecs.put_account_setting_default(name="containerInsights", value="enabled")["setting"]
    restored = {"done": False}

    def _restore_default():
        if not restored["done"]:
            ecs.put_account_setting_default(name="containerInsights", value=prior_value)
            restored["done"] = True

    ctx.on_cleanup(_restore_default)
    assert put.get("name") == "containerInsights" and put.get("value") == "enabled", put
    effective = ecs.list_account_settings(name="containerInsights", effectiveSettings=True)[
        "settings"
    ]
    assert [s.get("value") for s in effective] == ["enabled"], (
        f"after PutAccountSettingDefault(enabled) the effective setting reads {effective!r}"
    )

    inherit = _create_cluster(ctx, "inh-")
    control = _create_cluster(ctx, "ctl-", settings=[{"name": "containerInsights", "value": "disabled"}])
    inherit_perf = f"/aws/ecs/containerinsights/{inherit}/performance"
    control_perf = f"/aws/ecs/containerinsights/{control}/performance"
    # Registered now: CloudWatch creates these groups on the account's behalf (CONTROL's only after
    # the repair step), and a late telemetry flush can recreate one after a single delete.
    ctx.on_cleanup(lambda: _delete_perf_group(ctx, control, control_perf, raise_on_leak=True))
    ctx.on_cleanup(lambda: _delete_perf_group(ctx, inherit, inherit_perf, raise_on_leak=True))

    inherit_settings = _cluster_settings(ctx, inherit)
    assert inherit_settings.get("containerInsights") == "enabled", (
        f"a cluster created with NO settings must inherit the enabled account default, got "
        f"{inherit_settings!r}"
    )
    control_settings = _cluster_settings(ctx, control)
    assert control_settings.get("containerInsights") == "disabled", (
        f"an explicit containerInsights=disabled must override the enabled account default, got "
        f"{control_settings!r}"
    )

    # The default is only read at cluster creation, so restore it now; INHERIT must stay enabled.
    _restore_default()
    after = ecs.list_account_settings(name="containerInsights", effectiveSettings=True)["settings"]
    assert [s.get("value") for s in after] == [prior_value], (
        f"restoring the default to {prior_value!r} left the effective setting at {after!r}"
    )
    assert _cluster_settings(ctx, inherit).get("containerInsights") == "enabled", (
        "a cluster's inherited containerInsights must be captured at creation; restoring the "
        f"account default changed it to {_cluster_settings(ctx, inherit)!r}"
    )
    late = _create_cluster(ctx, "late-")
    late_settings = _cluster_settings(ctx, late)
    assert late_settings.get("containerInsights") == prior_value, (
        f"a bare cluster created after the restore must inherit {prior_value!r}, got {late_settings!r}"
    )
    _unless_gone(lambda: ecs.delete_cluster(cluster=late), "ClusterNotFoundException")

    inherit_task = _run_task(ctx, inherit, td_arn, subnets)
    control_task = _run_task(ctx, control, td_arn, subnets)
    started_at = datetime.datetime.now(datetime.timezone.utc)
    _await_running(ctx, inherit, inherit_task)
    _await_running(ctx, control, control_task)
    control_running_at = datetime.datetime.now(datetime.timezone.utc)

    inherit_dims = [{"Name": "ClusterName", "Value": inherit}]
    control_dims = [{"Name": "ClusterName", "Value": control}]

    def _control_silent(where: str) -> None:
        dps = _datapoints(ctx, "TaskCount", control_dims, started_at)
        assert dps == [], (
            f"[{where}] cluster {control} has explicit containerInsights=disabled yet published "
            f"TaskCount datapoints {dps!r}"
        )
        listed = _list_insights(ctx, control_dims)
        assert listed == [], (
            f"[{where}] {_INSIGHTS_NS} lists metrics for the disabled cluster {control}: {listed!r}"
        )
        groups = _log_groups(ctx, control_perf)
        assert groups == [], (
            f"[{where}] a performance log group exists for the disabled cluster: {groups!r}"
        )

    left = ctx.time_left()
    deadline = time.monotonic() + (600 if left is None else min(600, left))
    inherit_dp = None
    while time.monotonic() < deadline:
        found = [d for d in _datapoints(ctx, "TaskCount", inherit_dims, started_at) if d["Maximum"] >= 1.0]
        if found:
            inherit_dp = found[0]
            break
        _control_silent("while waiting for the inheriting cluster")
        time.sleep(2)
    assert inherit_dp is not None, (
        f"no TaskCount datapoint for the inheriting cluster {inherit} within 600 s of its task "
        f"running -- the inherited containerInsights=enabled published nothing"
    )
    assert inherit_dp["Maximum"] == 1.0, (
        f"exactly one task runs in {inherit}, so TaskCount must be 1, got {inherit_dp!r}"
    )
    assert inherit_dp.get("Unit") == "Count", (
        f"TaskCount is published in Count, got {inherit_dp.get('Unit')!r}"
    )

    # Contrast: once the inheriting cluster has published a TaskCount minute that began after the
    # control's task was RUNNING, that same publish cycle covered the control, which must be silent.
    covering = _poll_until(
        lambda: [
            d for d in _datapoints(ctx, "TaskCount", inherit_dims, started_at)
            if d["Timestamp"] >= control_running_at
        ],
        lambda ds: bool(ds),
        timeout_s=600,
        interval_s=2,
        description=f"a TaskCount minute for {inherit} after the control task was RUNNING",
        ctx=ctx,
    )
    _control_silent("after the inheriting cluster published a later minute")

    inherit_groups = _poll_until(
        lambda: _log_groups(ctx, inherit_perf),
        lambda gs: inherit_perf in gs,
        timeout_s=600,
        interval_s=2,
        description=f"Container Insights performance log group {inherit_perf}",
        ctx=ctx,
    )
    assert inherit_perf in inherit_groups, inherit_groups
    _control_silent("after the inheriting cluster's log group appeared")

    # Enabling the control must make it publish, so the setting was the only suppressor.
    upd = ecs.update_cluster_settings(
        cluster=control, settings=[{"name": "containerInsights", "value": "enabled"}]
    )["cluster"]
    upd_settings = {s["name"]: s["value"] for s in upd.get("settings", [])}
    assert upd_settings.get("containerInsights") == "enabled", (
        f"UpdateClusterSettings must echo the new value, got {upd.get('settings')!r}"
    )
    # Polled, not read once: on a cluster that is RUNNING tasks the read-back was observed to lag
    # the update (a bare cluster reads it back immediately).
    _poll_until(
        lambda: _cluster_settings(ctx, control),
        lambda st: st.get("containerInsights") == "enabled",
        timeout_s=180,
        interval_s=2,
        description=f"DescribeClusters to show containerInsights=enabled on {control}",
        ctx=ctx,
    )
    repaired_at = datetime.datetime.now(datetime.timezone.utc)
    second_task = _run_task(ctx, control, td_arn, subnets)
    _await_running(ctx, control, second_task)
    repaired = _poll_until(
        lambda: [
            d for d in _datapoints(ctx, "TaskCount", control_dims, repaired_at) if d["Maximum"] >= 1.0
        ],
        lambda ds: bool(ds),
        timeout_s=600,
        interval_s=2,
        description=f"TaskCount for {control} after enabling containerInsights on it",
        ctx=ctx,
    )
    assert all(d.get("Unit") == "Count" for d in repaired), repaired
    print(
        f"[measure] inherit minute after control RUNNING {covering[0]['Timestamp']}; control "
        f"TaskCount after repair {repaired!r}"
    )

    # Teardown runs inside the check; see _teardown_leg.
    _teardown_leg(
        ctx,
        tasks={inherit: [inherit_task], control: [control_task, second_task]},
        perf_groups=[(inherit, inherit_perf), (control, control_perf)],
        td_arn=td_arn,
        net=net,
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}

# ECR Public busybox: Fargate pulls it server-side and anonymously, so no execution role and no
# registry credentials are involved in a check about telemetry.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout).

    With ctx the deadline is capped by the run's remaining budget."""
    left = None if ctx is None else ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _cluster_settings(ctx, cluster) -> dict:
    found = ctx.client("ecs").describe_clusters(clusters=[cluster], include=["SETTINGS"])["clusters"]
    assert len(found) == 1, f"DescribeClusters({cluster!r}) returned {found!r}"
    return {s["name"]: s["value"] for s in found[0].get("settings", [])}


def _datapoints(ctx, metric_name, dimensions, since):
    return (
        ctx.client("cloudwatch")
        .get_metric_statistics(
            Namespace=_INSIGHTS_NS,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=since - datetime.timedelta(minutes=5),
            EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1),
            Period=60,
            Statistics=["Maximum", "SampleCount"],
        )
        .get("Datapoints", [])
    )


def _list_insights(ctx, dimensions):
    out = []
    pages = ctx.client("cloudwatch").get_paginator("list_metrics").paginate(
        Namespace=_INSIGHTS_NS, Dimensions=dimensions
    )
    for page in pages:
        out.extend(page.get("Metrics", []))
    return out


def _log_groups(ctx, name):
    """Exact-name matches for a log group (prefix query, then exact filter)."""
    out = []
    pages = ctx.client("logs").get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name)
    for page in pages:
        out.extend(g["logGroupName"] for g in page.get("logGroups", []) if g["logGroupName"] == name)
    return out


def _delete_perf_group(ctx, cluster, perf_group, *, attempts=6, quiet_s=45.0,
                       raise_on_leak: bool = False) -> bool:
    """Delete a performance log group, re-deleting it if a late telemetry flush recreates it.

    Returns True once the group has stayed absent for a quiet period."""
    logs = ctx.client("logs")
    if not _log_groups(ctx, perf_group):
        return True
    _await_cluster_tasks_stopped(ctx, cluster)
    for _ in range(attempts):
        _unless_gone(lambda: logs.delete_log_group(logGroupName=perf_group), "ResourceNotFoundException")
        time.sleep(quiet_s)
        if not _log_groups(ctx, perf_group):
            return True
    msg = f"performance log group {perf_group} kept being recreated after {attempts} deletes"
    if raise_on_leak:
        raise RuntimeError(msg)
    return False


def _await_cluster_tasks_stopped(ctx, cluster, timeout_s=300) -> None:
    ecs = ctx.client("ecs")

    def live():
        arns = ecs.list_tasks(cluster=cluster, desiredStatus="RUNNING").get("taskArns", [])
        arns += ecs.list_tasks(cluster=cluster, desiredStatus="STOPPED").get("taskArns", [])
        if not arns:
            return []
        return [
            t["taskArn"]
            for t in ecs.describe_tasks(cluster=cluster, tasks=arns[:100]).get("tasks", [])
            if t.get("lastStatus") != "STOPPED"
        ]

    _poll_until(live, lambda xs: not xs, timeout_s=timeout_s, interval_s=2,
                description=f"all tasks STOPPED in {cluster}")


def _delete_cluster(ctx, name, attempts=18, *, raise_on_leak: bool = False) -> bool:
    """Delete a cluster, retrying while stopping tasks still block it. True when it is gone."""
    ecs = ctx.client("ecs")
    for _ in range(attempts):
        found = ecs.describe_clusters(clusters=[name]).get("clusters", [])
        if not found or found[0].get("status") == "INACTIVE":
            return True
        try:
            ecs.delete_cluster(cluster=name)
            return True
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return True
            if code not in ("ClusterContainsTasksException", "ClusterContainsServicesException", "UpdateInProgressException"):
                raise
            time.sleep(10)
    if raise_on_leak:
        raise RuntimeError(f"ECS cluster {name} could not be deleted")
    return False


def _teardown_leg(ctx, *, tasks, perf_groups, td_arn, net) -> None:
    """Tear the estate down inside the check and assert it is gone.

    It takes minutes (task stops, log-group re-deletes, ENI release), longer than cleanup allows."""
    ecs = ctx.client("ecs")
    for cluster, arns in tasks.items():
        for arn in arns:
            _unless_gone(lambda c=cluster, a=arn: ecs.stop_task(cluster=c, task=a), "ClusterNotFoundException")
    for cluster in tasks:
        _await_cluster_tasks_stopped(ctx, cluster)
        assert _delete_cluster(ctx, cluster), f"cluster {cluster} could not be deleted"
    ecs.deregister_task_definition(taskDefinition=td_arn)
    for cluster, group in perf_groups:
        assert _delete_perf_group(ctx, cluster, group), (
            f"performance log group {group} kept being recreated after the cluster was deleted"
        )
    _teardown_network(ctx, net)
    assert net["deleted"], f"the check's own VPC {net['vpc']} could not be deleted: {net!r}"


def _own_network(ctx) -> list[str]:
    """A throwaway VPC with an internet gateway and two public subnets in two AZs.

    Teardown first waits for Fargate ENIs to be released: a subnet with an ENI cannot be deleted."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(_XSVC_PREFIX + "net-")

    def spec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "Name", "Value": name}] + _tags_kv()}]

    state: dict = {"vpc": None, "igw": None, "rtb": None, "subnets": [], "deleted": False}
    vpc = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=spec("vpc"))["Vpc"]["VpcId"]
    state["vpc"] = vpc
    ctx.on_cleanup(lambda: _teardown_network(ctx, state))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw = ec2.create_internet_gateway(TagSpecifications=spec("internet-gateway"))[
        "InternetGateway"
    ]["InternetGatewayId"]
    state["igw"] = igw
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rtb = ec2.create_route_table(VpcId=vpc, TagSpecifications=spec("route-table"))["RouteTable"][
        "RouteTableId"
    ]
    state["rtb"] = rtb
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert len(zones) >= 2, f"need two available AZs in {ctx.region}, got {zones!r}"
    for i, az in enumerate(zones[:2]):
        sn = ec2.create_subnet(
            VpcId=vpc,
            CidrBlock=f"10.77.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=spec("subnet"),
        )["Subnet"]["SubnetId"]
        state["subnets"].append(sn)
        ec2.associate_route_table(RouteTableId=rtb, SubnetId=sn)
    return list(state["subnets"]), state


def _teardown_network(ctx, state) -> None:
    """Delete the check's network; a leak raises after every delete is tried."""
    if state["deleted"]:
        return
    leaks: list[str] = []
    ec2 = ctx.client("ec2")
    vpc = state["vpc"]
    try:
        _poll_until(
            lambda: ec2.describe_network_interfaces(
                Filters=[{"Name": "vpc-id", "Values": [vpc]}]
            ).get("NetworkInterfaces", []),
            lambda enis: not enis,
            timeout_s=420,
            interval_s=2,
            description=f"Fargate ENIs released from {vpc}",
        )
    except AssertionError as exc:
        leaks.append(f"{exc}")
    for sn in state["subnets"]:
        _unless_gone(lambda sn=sn: ec2.delete_subnet(SubnetId=sn), "InvalidSubnetID.NotFound")
    if state["rtb"]:
        _unless_gone(lambda: ec2.delete_route_table(RouteTableId=state["rtb"]), "InvalidRouteTableID.NotFound")
    if state["igw"]:
        _unless_gone(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=state["igw"], VpcId=vpc),
            "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound",
        )
        _unless_gone(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=state["igw"]), "InvalidInternetGatewayID.NotFound"
        )
    try:
        ec2.delete_vpc(VpcId=vpc)
        state["deleted"] = True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            leaks.append(f"vpc {vpc} ({state}) not deleted: {exc}")
            raise RuntimeError("; ".join(leaks)) from exc
        state["deleted"] = True


def _ensure_ecs_slr(ctx) -> None:
    """Fargate RunTask needs AWSServiceRoleForECS; CreateService creates it, RunTask does not."""
    # InvalidInput: the role already exists ("has been taken"), which is what this needs.
    _unless_gone(
        lambda: ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com"),
        "InvalidInput",
    )


def _create_cluster(ctx, kind, settings=None) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + kind)
    kwargs: dict = {"clusterName": name, "tags": _ecs_tags_kv()}
    if settings:
        kwargs["settings"] = settings
    ecs.create_cluster(**kwargs)
    ctx.on_cleanup(lambda: _delete_cluster(ctx, name, raise_on_leak=True))
    return name


def _register_task_def(ctx) -> str:
    ecs = ctx.client("ecs")
    td = ecs.register_task_definition(
        family=ctx.unique_name(_XSVC_PREFIX + "td-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "command": ["sh", "-c", "sleep 1700"],
            }
        ],
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=_ecs_tags_kv(),
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _run_task(ctx, cluster, td_arn, subnets) -> str:
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnets, "assignPublicIp": "ENABLED"}
        },
        tags=_ecs_tags_kv(),
    )
    # Register the stop for anything RunTask did start BEFORE asserting on failures.
    for t in resp.get("tasks", []):
        ctx.on_cleanup(
            lambda arn=t["taskArn"]: _unless_gone(
                lambda: ecs.stop_task(cluster=cluster, task=arn), "ClusterNotFoundException"
            )
        )
    assert not resp.get("failures") and len(resp.get("tasks", [])) == 1, (
        f"RunTask in {cluster}: failures={resp.get('failures')!r}"
    )
    return resp["tasks"][0]["taskArn"]


def _await_running(ctx, cluster, task_arn) -> float:
    """Wait for RUNNING; return the monotonic instant it was observed."""
    ecs = ctx.client("ecs")
    task = _poll_until(
        lambda: (ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks") or [{}])[0],
        lambda t: t.get("lastStatus") in ("RUNNING", "STOPPED"),
        timeout_s=480,
        interval_s=2,
        description=f"task {task_arn} RUNNING",
        ctx=ctx,
    )
    assert task["lastStatus"] == "RUNNING", (
        f"task never ran: stopCode={task.get('stopCode')!r} reason={task.get('stoppedReason')!r}"
    )
    return time.monotonic()


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister then delete a task definition revision; a deregistered one stays INACTIVE.

    An already-deleted revision is fine; any other failure raises."""
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
