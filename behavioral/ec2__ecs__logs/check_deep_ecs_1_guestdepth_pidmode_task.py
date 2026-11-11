"""deep-ecs-1-guestdepth-pidmode-task."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-ecs-1-guestdepth-pidmode-task"

GROUP = "guest-process-namespace"

SERVICES = ["ec2", "ecs", "logs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """With pidMode=task, a Fargate task's observer container sees the sleeper container's marker process
    in `ps`; in a twin task without pidMode it does not, still sees its own `ps`, and its PID 1 is
    its own shell.
    """
    _subnets, _sg = _network(ctx)
    log_group = _create_log_group(ctx)
    _role, exec_role = _iam_role(
        ctx,
        "ecs-exec",
        "ecs-tasks.amazonaws.com",
        [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
          "Resource": "*"}],
    )
    cluster = _create_cluster(ctx)

    marker = ctx.unique_name("sim2real-pidmark-")
    observer_cmd = (
        f"sleep {_OBSERVER_PAUSE_S}; echo BEGIN-PS; ps -o pid,args; echo END-PS; "
        f"sleep {_OBSERVER_PAUSE_S}"
    )

    def containers():
        return [
            {
                "name": "sleeper",
                "image": _PUBLIC_IMAGE,
                "essential": False,
                # `$0` of this shell is the marker, so it appears in argv and in `ps` output.
                "command": ["sh", "-c", "while :; do sleep 1; done", marker],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            },
            {
                "name": "observer",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "dependsOn": [{"containerName": "sleeper", "condition": "START"}],
                "command": ["sh", "-c", observer_cmd],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            },
        ]

    platform = {"operatingSystemFamily": "LINUX", "cpuArchitecture": "X86_64"}
    shared_td = _register_task_def(ctx, containers(), execution_role_arn=exec_role,
                                   runtime_platform=platform, pid_mode="task")
    isolated_td = _register_task_def(ctx, containers(), execution_role_arn=exec_role,
                                     runtime_platform=platform)
    assert shared_td.get("pidMode") == "task", (
        f"RegisterTaskDefinition did not keep pidMode=task: {shared_td.get('pidMode')!r}"
    )
    assert "pidMode" not in isolated_td, (
        f"the twin was registered without pidMode yet reports {isolated_td.get('pidMode')!r}"
    )

    (shared_arn, shared), (isolated_arn, isolated) = _run_assumed(
        ctx, cluster, [shared_td["taskDefinitionArn"], isolated_td["taskDefinitionArn"]], _subnets,
        [_sg], timeout_s=900)

    for label, task in (("pidMode=task", shared), ("default", isolated)):
        pv = task.get("platformVersion") or ""
        # Fargate platform 1.4.0 is the floor for pidMode=task.
        assert _version_tuple(pv) >= (1, 4, 0), (
            f"{label} task ran on Fargate platform {pv!r}; pidMode=task needs >= 1.4.0"
        )
        obs = {c["name"]: c for c in task.get("containers", [])}.get("observer", {})
        assert obs.get("exitCode") == 0, (
            f"{label} observer did not exit 0: {obs!r} stoppedReason={task.get('stoppedReason')!r}"
        )

    shared_ps = _await_listing(ctx, log_group, f"ecs/observer/{shared_arn.rsplit('/', 1)[-1]}")
    isolated_ps = _await_listing(ctx, log_group,
                                 f"ecs/observer/{isolated_arn.rsplit('/', 1)[-1]}")

    for label, rows in (("pidMode=task", shared_ps), ("default", isolated_ps)):
        assert any("ps -o pid,args" in args for _pid, args in rows), (
            f"{label} observer's listing does not even contain its own ps process: {rows!r}"
        )

    assert any(marker in args for _pid, args in shared_ps), (
        f"with pidMode=task the observer could not see the sleeper's marker {marker!r}: "
        f"{shared_ps!r}"
    )
    assert not any(marker in args for _pid, args in isolated_ps), (
        f"WITHOUT pidMode the observer still saw the sleeper's marker {marker!r}, so the "
        f"namespaces were not isolated: {isolated_ps!r}"
    )
    pid1 = [args for pid, args in isolated_ps if pid == 1]
    assert pid1 and pid1[0].startswith(f"sh -c sleep {_OBSERVER_PAUSE_S}"), (
        f"in its own PID namespace the observer's PID 1 should be its own shell, got {pid1!r} "
        f"from {isolated_ps!r}"
    )
    _release_network(ctx, _subnets)


def _version_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in v.split("."))
    except ValueError:
        return ()


def _await_listing(ctx, log_group: str, stream: str) -> list[tuple[int, str]]:
    """(pid, args) rows between BEGIN-PS and END-PS in the observer's stream, parsed per row."""
    _await_log_stream(ctx, log_group, stream, timeout_s=420)
    msgs = _poll_until(
        lambda: _log_messages(ctx, log_group, stream),
        lambda ms: "END-PS" in ms,
        ctx=ctx, timeout_s=_budget_s(ctx, 420),
        interval_s=2,
        description=f"an END-PS line in {stream}",
    )
    body = msgs[msgs.index("BEGIN-PS") + 1: msgs.index("END-PS")]
    rows: list[tuple[int, str]] = []
    for line in body:
        head, _, rest = line.strip().partition(" ")
        if head.isdigit():
            rows.append((int(head), rest.strip()))
    assert rows, f"no parseable `pid args` rows in {stream}: {msgs!r}"
    return rows


# ECR Public busybox: a tiny multi-arch image an anonymous Fargate pull can always fetch, so a
# check about the container runtime is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

#: Seconds the observer waits before and after its `ps`: the sleeper is up, and the listing ships.
_OBSERVER_PAUSE_S = 3

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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None):
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
        for _ in range(30):
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except Exception as exc:  # noqa: BLE001 - a just-deleted subnet can lag
                if getattr(exc, "response", {}).get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    return
                last = exc
                time.sleep(2)
        raise RuntimeError(f"VPC {vpc_id} was not deleted: {last!r}")

    ctx.on_cleanup(_drop)
    _poll_until(lambda: _safe(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]),
                lambda s: s == "available", ctx=ctx, timeout_s=_budget_s(ctx, 120), interval_s=2,
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
        lambda r: not r, timeout_s=_budget_s(ctx, 300), interval_s=2,
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
        last = None
        for _ in range(40):
            try:
                ecs.delete_cluster(cluster=name)
                return
            except Exception as exc:  # noqa: BLE001 - a stopping task can block delete briefly
                if getattr(exc, "response", {}).get("Error", {}).get("Code") == "ClusterNotFoundException":
                    return
                last = exc
                time.sleep(2)
        raise RuntimeError(f"cluster {name} was not deleted: {last!r}")

    ctx.on_cleanup(_drop)
    _poll_until(lambda: _safe(lambda: ecs.describe_clusters(clusters=[name])["clusters"][0]
                              ["status"]),
                lambda s: s == "ACTIVE", ctx=ctx, timeout_s=_budget_s(ctx, 120), interval_s=2,
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
        _delete(lambda: _await_task(ctx, cluster, arn, {"STOPPED"}, timeout_s=240,
                                     in_budget=False))

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
                task = _await_task(ctx, cluster, arn, {"STOPPED"}, timeout_s=timeout_s)
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


def _await_task(ctx, cluster, task_arn, statuses, timeout_s=600.0, in_budget=True):
    ecs = ctx.client("ecs")

    def probe():
        found = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return found[0] if found else {}

    return _poll_until(
        probe,
        lambda t: t.get("lastStatus") in statuses,
        ctx=ctx if in_budget else None, timeout_s=_budget_s(ctx, timeout_s) if in_budget else timeout_s,
        interval_s=2,
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
        ctx=ctx, timeout_s=_budget_s(ctx, timeout_s),
        interval_s=2,
        description=f"log stream {stream} in {group}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
