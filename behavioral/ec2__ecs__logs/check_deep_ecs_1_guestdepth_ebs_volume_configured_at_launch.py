"""deep-ecs-1-guestdepth-ebs-volume-configured-at-launch."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-ecs-1-guestdepth-ebs-volume-configured-at-launch"

GROUP = "guest-block-storage"

SERVICES = ["ec2", "ecs", "logs"]

_GIB_IN_KIB = 4 * 1024 * 1024


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A managed EBS volume supplied at RunTask is one attached 4 GiB gp3 volume, seen in the guest as a
    writable 4 GiB ext4 mount at /data (read via CloudWatch Logs), and deleted once the task stops.
    """
    subnets, sg = _network(ctx)
    log_group = _create_log_group(ctx)
    _r, exec_role = _iam_role(
        ctx, "ecs-exec", "ecs-tasks.amazonaws.com",
        [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
          "Resource": "*"}],
    )
    _r2, infra_role = _iam_role(
        ctx, "ecs-infra", "ecs.amazonaws.com",
        managed_arns=["arn:aws:iam::aws:policy/service-role/"
                      "AmazonECSInfrastructureRolePolicyForVolumes"],
    )
    cluster = _create_cluster(ctx)
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")

    probe = ctx.unique_name("sim2real-ebsprobe-")
    guest_cmd = (
        "echo BEGIN-MOUNT; grep ' /data ' /proc/mounts; echo END-MOUNT; "
        "echo BEGIN-PART; cat /proc/partitions; echo END-PART; "
        "echo BEGIN-DF; df -k /data; echo END-DF; "
        f"echo {probe} > /data/probe.txt && echo WROTE=$(cat /data/probe.txt); "
        "echo READY; sleep 900"
    )
    td = _register_task_def(
        ctx,
        [{
            "name": "app",
            "image": _PUBLIC_IMAGE,
            "essential": True,
            "command": ["sh", "-c", guest_cmd],
            "mountPoints": [{"sourceVolume": "ebs", "containerPath": "/data",
                             "readOnly": False}],
            "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
        }],
        execution_role_arn=exec_role,
        volumes=[{"name": "ebs", "configuredAtLaunch": True}],
        runtime_platform={"operatingSystemFamily": "LINUX", "cpuArchitecture": "X86_64"},
    )
    assert td["volumes"][0].get("configuredAtLaunch") is True, (
        f"task definition lost configuredAtLaunch: {td['volumes']!r}"
    )

    def _volume_configs(run_tag):
        return [{
            "name": "ebs",
            "managedEBSVolume": {
                "roleArn": infra_role,
                "sizeInGiB": 4,
                "volumeType": "gp3",
                "filesystemType": "ext4",
                # A per-run unique tag, so "exactly one volume" is a property of the query, not the account.
                "tagSpecifications": [{
                    "resourceType": "volume",
                    "tags": _ecs_tags_kv() + [{"key": "sim2real:ebs-run", "value": run_tag}],
                }],
            },
        }]

    # The fresh roles may not be assumable yet: RunTask, or the task it starts, is retried while
    # it fails on role assumption, to a deadline.
    deadline = time.monotonic() + _capped(ctx, 180.0)
    while True:
        run_tag = ctx.unique_name("sim2real-ebsrun-")
        try:
            task_arn = _run_task(ctx, cluster, td["taskDefinitionArn"], subnets, [sg],
                                 volumeConfigurations=_volume_configs(run_tag))
        except Exception as exc:  # noqa: BLE001 - re-raised unless it is the propagation refusal
            message = str(getattr(exc, "response", {}).get("Error", {}).get("Message", ""))
            if "assume" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        running = _await_task(ctx, cluster, task_arn, {"RUNNING", "STOPPED"},
                              timeout_s=_capped(ctx, 900))
        reason = str(running.get("stoppedReason") or "")
        if running.get("lastStatus") == "STOPPED" and "assume" in reason.lower() \
                and time.monotonic() < deadline:
            continue
        break
    task_id = task_arn.rsplit("/", 1)[-1]
    holder: dict = {}

    def _drop_volume():
        # After the task-stop net above has run (LIFO): ECS normally deleted it already.
        vid = holder.get("vid")
        if vid:
            _delete(lambda: ec2.delete_volume(VolumeId=vid), retry=("VolumeInUse", "IncorrectState"))

    ctx.on_cleanup(_drop_volume)

    assert running.get("lastStatus") == "RUNNING", (
        f"task never reached RUNNING: lastStatus={running.get('lastStatus')!r} "
        f"stoppedReason={running.get('stoppedReason')!r}"
    )

    vols = _volumes_tagged(ec2, run_tag)
    if vols:
        holder["vid"] = vols[0]["VolumeId"]
    assert len(vols) == 1, f"expected exactly one volume tagged {run_tag!r}, got {vols!r}"
    vol = vols[0]
    assert vol["Size"] == 4, f"volume size {vol['Size']!r} GiB, requested 4"
    assert vol["VolumeType"] == "gp3", f"volume type {vol['VolumeType']!r}, requested gp3"
    assert vol["State"] == "in-use", f"volume state {vol['State']!r} while the task is RUNNING"
    atts = vol.get("Attachments", [])
    assert len(atts) == 1 and atts[0].get("State") == "attached", (
        f"volume should have exactly one attached attachment, got {atts!r}"
    )

    stream = f"ecs/app/{task_id}"
    _await_log_stream(ctx, log_group, stream, timeout_s=420)
    msgs = _poll_until(lambda: _log_messages(ctx, log_group, stream),
                       lambda ms: "READY" in ms, timeout_s=420, interval_s=5,
                       description=f"READY in {stream}")
    mount = _between(msgs, "BEGIN-MOUNT", "END-MOUNT")
    parts = _between(msgs, "BEGIN-PART", "END-PART")
    df = _between(msgs, "BEGIN-DF", "END-DF")
    assert len(mount) == 1, f"/data should be exactly one mount in the guest, got {mount!r}"
    src, mnt, fstype = mount[0].split()[:3]
    assert mnt == "/data" and fstype == "ext4", (
        f"guest mount of /data is {mount[0]!r}, expected an ext4 filesystem at /data"
    )
    dev = src.rsplit("/", 1)[-1]
    sizes = {}
    for row in parts:
        cols = row.split()
        if len(cols) == 4 and cols[2].isdigit():
            sizes[cols[3]] = int(cols[2])
    assert sizes.get(dev) == _GIB_IN_KIB, (
        f"guest block device {dev!r} backing /data has {sizes.get(dev)!r} KiB, expected "
        f"{_GIB_IN_KIB} (4 GiB); partitions={parts!r}"
    )
    df_rows = [r.split() for r in df if r.split() and r.split()[-1] == "/data"]
    assert len(df_rows) == 1, f"no parseable df row for /data: {df!r}"
    total_kib = int(df_rows[0][1])
    assert 0.9 * _GIB_IN_KIB <= total_kib <= _GIB_IN_KIB, (
        f"df reports {total_kib} KiB for /data; a 4 GiB ext4 must be just under {_GIB_IN_KIB}"
    )
    assert f"WROTE={probe}" in msgs, f"the guest could not write+read /data: {msgs!r}"

    ecs.stop_task(cluster=cluster, task=task_arn, reason="sim2real ebs check done")
    stopped = _await_task(ctx, cluster, task_arn, {"STOPPED"}, timeout_s=600)
    assert stopped.get("lastStatus") == "STOPPED", f"task did not stop: {stopped!r}"

    vid = vol["VolumeId"]
    code, message = _poll_until(
        lambda: _volume_error(ec2, vid), lambda cm: cm[0] == "InvalidVolume.NotFound",
        timeout_s=900, interval_s=10,
        description=f"volume {vid} deleted by ECS after the task stopped")
    assert code == "InvalidVolume.NotFound", f"volume {vid} still present: {code!r} {message!r}"
    assert message == f"The volume '{vid}' does not exist.", (
        f"InvalidVolume.NotFound did not name {vid!r} as the missing volume: {message!r}"
    )
    _release_network(ctx, subnets)


def _between(msgs: list[str], start: str, end: str) -> list[str]:
    assert start in msgs and end in msgs, f"guest output lacks {start}/{end}: {msgs!r}"
    return msgs[msgs.index(start) + 1: msgs.index(end)]


def _volumes_tagged(ec2, value: str) -> list[dict]:
    out: list[dict] = []
    for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "tag:sim2real:ebs-run", "Values": [value]}]):
        out += page.get("Volumes", [])
    return out


def _volume_error(ec2, vid: str) -> tuple[str, str]:
    """The (code, message) DescribeVolumes returns for vid, or ('present:<state>', '') if it still
    exists."""
    try:
        vols = ec2.describe_volumes(VolumeIds=[vid]).get("Volumes", [])
    except Exception as exc:  # noqa: BLE001 - classify the ClientError code
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code", repr(exc)), err.get("Message", "")
    return "present:" + ",".join(v.get("State", "?") for v in vols), ""


# ECR Public busybox: a tiny multi-arch image an anonymous Fargate pull can always fetch, so a
# check about the container runtime is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _capped(ctx, budget_s: float) -> float:
    """*budget_s*, capped by the time the run has left so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, max(0.0, left - 10.0))


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
        # A just-deleted subnet can lag: DependencyViolation is retried.
        _delete(lambda: ec2.delete_vpc(VpcId=vpc_id))

    ctx.on_cleanup(_drop)
    _poll_until(lambda: _safe(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]),
                lambda s: s == "available", timeout_s=120, interval_s=3,
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
        lambda r: not r, timeout_s=300, interval_s=10,
        description="task ENIs released from this check's subnets"))


def _iam_role(ctx, kind, trust_service, statements=None, managed_arns=()):
    """Create a role trusting trust_service with an inline policy and/or managed policies.

    IAM is eventually consistent: the role and policy are polled back; trust-policy propagation
    to the assuming service is retried at first use.
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
                    lambda r: r is not None, timeout_s=60, interval_s=2,
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
        # A stopping task can block the delete briefly.
        _delete(lambda: ecs.delete_cluster(cluster=name),
                retry=("ClusterContainsTasksException", "ClusterContainsContainerInstancesException"),
                timeout_s=80.0)

    ctx.on_cleanup(_drop)
    _poll_until(lambda: _safe(lambda: ecs.describe_clusters(clusters=[name])["clusters"][0]
                              ["status"]),
                lambda s: s == "ACTIVE", timeout_s=120, interval_s=3,
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
            time.sleep(5)


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
        interval_s=5,
        description=f"log stream {stream} in {group}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
