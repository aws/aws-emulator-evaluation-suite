"""deep-ecs-guest-identity-task-stats-counters-track-the-work-the-container-did."""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time

from behavioral_harness import tags

CHECK = "deep-ecs-guest-identity-task-stats-counters-track-the-work-the-container-did"

GROUP = "guest-identity"

SERVICES = ["ecs", "logs"]


_ALLOC_MIB = 160
_BURN_WALL_S = 20

#: The guest program for the `worker` container. It samples its own `${URI}/stats` and the
#: task-wide `${URI}/task/stats`, then does two things it can MEASURE from inside -- faults in
#: _ALLOC_MIB MiB of anonymous memory and holds it, and burns CPU for _BURN_WALL_S seconds of
#: wall time while timing its own CPU consumption with time.process_time() -- and samples both
#: endpoints again once a stats sample newer than the end of the burn is being served.
_GUEST = r"""
import json, os, re, time, urllib.request
base = os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
if not base:
    print("STERR ECS_CONTAINER_METADATA_URI_V4 is not set", flush=True)
    time.sleep(900)
def get(path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.loads(r.read())
def read_epoch(stats):
    m = re.match(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z", stats.get("read", ""))
    if not m:
        return 0.0
    import calendar
    whole = calendar.timegm(tuple(int(g) for g in m.groups()[:6]))
    return whole + float("0." + (m.group(7) or "0"))
def emit(tag, obj):
    print(tag + " " + json.dumps(obj, separators=(",", ":")), flush=True)
s0, ts0 = get("/stats"), get("/task/stats")
emit("ST0", {"stats": s0, "task_stats": ts0, "t": time.time()})
alloc = ALLOC_MIB * 1024 * 1024
blob = bytearray(alloc)
for i in range(0, alloc, 4096):
    blob[i] = 1
c0 = time.process_time()
end = time.time() + BURN_WALL_S
x = 0
while time.time() < end:
    x += 1
cpu_burn_s = time.process_time() - c0
t_burn = time.time()
s1 = ts1 = None
for _ in range(90):
    s1 = get("/stats")
    if read_epoch(s1) > t_burn:
        break
    time.sleep(2)
ts1 = get("/task/stats")
emit("ST1", {"stats": s1, "task_stats": ts1, "cpu_burn_s": cpu_burn_s, "t_burn": t_burn,
             "read_epoch": read_epoch(s1), "held": len(blob), "alloc": alloc})
time.sleep(900)
""".replace("ALLOC_MIB", str(_ALLOC_MIB)).replace("BURN_WALL_S", str(_BURN_WALL_S))

_CONTAINERS = {
    "worker": ("256", "512", ["python3", "-c", _GUEST]),
    "idle": ("128", "256", ["python3", "-c", "import time; time.sleep(900)"]),
}

_TASK_RUNNING_TIMEOUT_S = 600
_LOG_TIMEOUT_S = 480


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The v4 /stats and /task/stats counters are live and per container: the worker's CPU and memory
    grow by at least what its own process measured, and the idle sibling's do not.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4-fargate-response.html
    """
    ecs = ctx.client("ecs")
    net = _build_network(ctx, "tst")
    try:
        _body(ctx, ecs, net)
    finally:
        _settle(ctx, net)


def _body(ctx, ecs, net) -> None:
    log_group = _create_log_group(ctx)
    exec_role = _iam_role(ctx, "tst-exec", [
        {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
        {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"], "Resource": "*"}])
    cluster_arn = _create_cluster(ctx, net)
    family = ctx.unique_name("sim2real-deg-tst-")
    td = _register_task_def(ctx, family, [
        {
            "name": name,
            "image": _target_image(ctx, "python"),
            "essential": name == "worker",
            "cpu": int(cpu),
            "memory": int(mem),
            "command": cmd,
            "logConfiguration": _awslogs(log_group, ctx.region),
        }
        for name, (cpu, mem, cmd) in _CONTAINERS.items()
    ], exec_role, cpu="512", memory="1024")

    task_arn, _running = _start_task(ctx, cluster_arn, td["taskDefinitionArn"], net, "RUNNING",
                                     _TASK_RUNNING_TIMEOUT_S)
    task_id = task_arn.rsplit("/", 1)[-1]

    stream = f"ecs/worker/{task_id}"
    lines = _poll(lambda: _log_messages(ctx, log_group, stream),
                  lambda ms: any(m.startswith(("ST1 ", "STERR ")) for m in ms),
                  _LOG_TIMEOUT_S, what=f"the stats probe's second sample in {stream}")
    assert not [m for m in lines if m.startswith("STERR ")], (
        f"the worker could not reach its stats endpoint: {lines!r}"
    )
    first, second = _tagged(lines, "ST0 "), _tagged(lines, "ST1 ")

    task = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    assert task["lastStatus"] == "RUNNING", (
        f"the task left RUNNING during the measurement: {task['lastStatus']!r} "
        f"stoppedReason={task.get('stoppedReason')!r}"
    )
    runtime = {c["name"]: c.get("runtimeId") for c in task["containers"]}
    assert set(runtime) == set(_CONTAINERS) and all(runtime.values()), (
        f"DescribeTasks runtimeIds {runtime!r}"
    )

    s0, s1 = first["stats"], second["stats"]
    cpu_burn_ns = float(second["cpu_burn_s"]) * 1e9
    assert cpu_burn_ns > 0, f"the guest measured no CPU consumption of its own: {second!r}"
    assert second["read_epoch"] > second["t_burn"], (
        f"the endpoint never served a sample newer than the end of the burn "
        f"(read={s1.get('read')!r}, burn ended at epoch {second['t_burn']!r})"
    )
    assert s1.get("read") != s0.get("read"), (
        f"/stats served the same sample twice (read={s0.get('read')!r}): a frozen counter"
    )

    cpu0 = _cpu_total(s0, "worker /stats first sample")
    cpu1 = _cpu_total(s1, "worker /stats second sample")
    # A cgroup's counter includes every process in it, so it cannot be below the process's own.
    assert cpu1 - cpu0 >= 0.9 * cpu_burn_ns, (
        f"the worker's cgroup total_usage advanced by {cpu1 - cpu0!r} ns across a burn in which "
        f"its own process measured {cpu_burn_ns!r} ns of CPU; the cgroup counter includes that "
        f"process and cannot be lower (first={cpu0!r}, second={cpu1!r})"
    )
    held = int(second["held"])
    assert held == int(second["alloc"]) == _ALLOC_MIB * 1024 * 1024, f"held {held!r} bytes"
    mem1 = _mem_usage(s1, "worker /stats second sample")
    assert mem1 >= held, (
        f"the worker holds {held!r} bytes of faulted-in memory but its memory_stats.usage is "
        f"{mem1!r}"
    )

    # /task/stats is keyed by the runtimeIds DescribeTasks reports; the idle sibling is the control.
    ts0, ts1 = first["task_stats"], second["task_stats"]
    want_ids = set(runtime.values())
    for label, ts in (("first", ts0), ("second", ts1)):
        assert isinstance(ts, dict) and set(ts) == want_ids, (
            f"/task/stats ({label} sample) is keyed by {sorted(ts) if isinstance(ts, dict) else ts!r}; "
            f"DescribeTasks says the task's containers are {runtime!r}"
        )
    w_id, i_id = runtime["worker"], runtime["idle"]
    w_mem = _mem_usage(ts1[w_id], "worker entry of /task/stats")
    i_mem = _mem_usage(ts1[i_id], "idle entry of /task/stats")
    assert w_mem >= held, (
        f"/task/stats reports the worker at {w_mem!r} bytes while it holds {held!r}"
    )
    assert i_mem < held, (
        f"/task/stats reports the IDLE sibling at {i_mem!r} bytes -- at least the worker's "
        f"{held!r}-byte allocation, so the counter is not attributed per container"
    )
    w_cpu = _cpu_total(ts1[w_id], "worker, task stats 2") - _cpu_total(ts0[w_id], "worker, task stats 1")
    i_cpu = _cpu_total(ts1[i_id], "idle, task stats 2") - _cpu_total(ts0[i_id], "idle, task stats 1")
    assert w_cpu >= 0.9 * cpu_burn_ns, (
        f"/task/stats shows the worker's CPU advancing {w_cpu!r} ns; its process burned "
        f"{cpu_burn_ns!r} ns"
    )
    assert 0 <= i_cpu < 0.25 * w_cpu, (
        f"/task/stats shows the idle sibling's CPU advancing {i_cpu!r} ns against the worker's "
        f"{w_cpu!r} ns; a sleeping process cannot account for a quarter of a busy loop"
    )


def _cpu_total(stats: dict, what: str) -> float:
    try:
        return float(stats["cpu_stats"]["cpu_usage"]["total_usage"])
    except (KeyError, TypeError) as exc:
        raise AssertionError(f"{what} has no cpu_stats.cpu_usage.total_usage "
                             f"(keys {sorted(stats) if isinstance(stats, dict) else stats!r})") from exc


def _mem_usage(stats: dict, what: str) -> int:
    try:
        return int(stats["memory_stats"]["usage"])
    except (KeyError, TypeError) as exc:
        raise AssertionError(f"{what} has no memory_stats.usage "
                             f"(memory_stats={stats.get('memory_stats') if isinstance(stats, dict) else stats!r})") from exc


def _tagged(lines: list[str], prefix: str) -> dict:
    hits = [m[len(prefix):] for m in lines if m.startswith(prefix)]
    assert hits, f"no {prefix.strip()} line in the guest output {[m[:200] for m in lines]!r}"
    return json.loads(hits[-1])


# Cleanups are registered right after each create so LIFO order tears down dependents first.

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK[:200]}


def _ec2_tags(name: str) -> list[dict]:
    return [{"Key": "Name", "Value": name}] + [
        {"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags() -> list[dict]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - best-effort teardown / probe
        return None


def _poll(probe, predicate, timeout_s, interval_s=2.0, what="condition"):
    """Bounded retry that RAISES on timeout. Never a bare sleep standing in for a wait."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _teardown(fn, *not_found: str):
    """A delete where failure raises; only its own not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in not_found:
                return
            raise

    return run_undo


def _retry_delete(fn, attempts=4, interval_s=5.0):
    """Delete with retries: an ENI or a stopping task can hold a dependency for a while.

    Raises the last error once `attempts` is exhausted with the dependency still unresolved."""
    last_exc = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code.endswith("NotFound") or code in ("ClusterNotFoundException",):
                return
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _usable_zone(ec2) -> str:
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, "no available availability zone in this region"
    return zones[0]


def _build_network(ctx, label: str) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"sim2real-deg-{label}-")
    net: dict = {"name": name, "subnet_cidr": "10.86.1.0/24", "tasks": []}
    vpc = ec2.create_vpc(CidrBlock="10.86.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _ec2_tags(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    net["vpc"] = vpc
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _ec2_tags(name)}])[
        "InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc))
        _retry_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rts = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"]
    assert len(rts) == 1, f"a fresh VPC must have exactly one route table; got {rts!r}"
    ec2.create_route(RouteTableId=rts[0]["RouteTableId"], DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw)

    net["az"] = _usable_zone(ec2)
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=net["subnet_cidr"],
                               AvailabilityZone=net["az"], TagSpecifications=[
                                   {"ResourceType": "subnet", "Tags": _ec2_tags(name)}])[
        "Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    net["subnet"] = subnet

    sg = ec2.create_security_group(
        GroupName=name, Description="sim2real deep-ecs-guest-identity task SG", VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _ec2_tags(name)}])["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg)))
    net["sg"] = sg
    return net


def _drain_enis(ctx, subnet: str, timeout_s: float) -> None:
    ec2 = ctx.client("ec2")
    _swallow(lambda: _poll(
        lambda: ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet]}])["NetworkInterfaces"],
        lambda enis: not enis, timeout_s, 10, what=f"subnet {subnet} releasing its task ENIs"))


def _settle(ctx, net: dict) -> None:
    """Stop tasks and wait for their ENIs to release, from the body's `finally`.

    Fargate tasks outlast the cleanup time bound; never raises, so it cannot mask a failure."""
    ecs = ctx.client("ecs")
    tasks, cluster = list(net.get("tasks", [])), net.get("cluster")
    for t in tasks:
        _swallow(lambda t=t: ecs.stop_task(cluster=cluster, task=t, reason="sim2real teardown"))
    if tasks:
        _swallow(lambda: _poll(
            lambda: [x["lastStatus"] for x in ecs.describe_tasks(
                cluster=cluster, tasks=tasks)["tasks"]],
            lambda ss: len(ss) == len(tasks) and all(x == "STOPPED" for x in ss), 300, 5,
            what="every task this check started reaching STOPPED"))
    if net.get("subnet"):
        _drain_enis(ctx, net["subnet"], 300)


def _iam_role(ctx, kind: str, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-deg-{kind}-")
    arn = iam.create_role(
        RoleName=name, Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
             "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()])["Role"]["Arn"]

    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    _poll(lambda: _swallow(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
          lambda r: r is not None, 60, 2, what=f"role {name} inline policy readable")
    return arn


#: Bound for a fresh execution role to become usable by ECS.
_IAM_PROPAGATION_S = 120.0


def _deadline(ctx, budget_s):
    """A monotonic deadline `budget_s` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (budget_s if left is None else min(budget_s, max(0.0, left - 5)))


def _role_not_yet_usable(task):
    """A start failure from the execution role not yet usable: unassumable or a grant denied."""
    reason = task.get("stoppedReason") or ""
    return task.get("stopCode") == "TaskFailedToStart" and (
        "unable to assume" in reason.lower() or "is not authorized to perform" in reason)


def _start_task(ctx, cluster, td_arn, net, status, timeout_s):
    """RunTask, rerun while the task fails to start on the fresh role; return (arn, task)."""
    ecs = ctx.client("ecs")
    deadline = _deadline(ctx, _IAM_PROPAGATION_S)
    while True:
        arn = _run_task(ctx, cluster, td_arn, net)
        task = _poll(lambda: (ecs.describe_tasks(cluster=cluster, tasks=[arn]).get("tasks")
                              or [{}])[0],
                     lambda t: t.get("lastStatus") in (status, "STOPPED"), timeout_s,
                     what=f"task {arn} reaching {status}")
        if not _role_not_yet_usable(task) or time.monotonic() >= deadline:
            return arn, _await_task(ctx, cluster, arn, status, timeout_s)
        time.sleep(2)


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-deg-lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=name),
                             "ResourceNotFoundException"))
    return name


def _awslogs(group: str, region: str) -> dict:
    return {"logDriver": "awslogs", "options": {
        "awslogs-group": group, "awslogs-region": region, "awslogs-stream-prefix": "ecs"}}


def _create_cluster(ctx, net: dict) -> str:
    ecs = ctx.client("ecs")
    arn = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-deg-cl-"),
                             tags=_ecs_tags())["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ecs.delete_cluster(cluster=arn)))
    net["cluster"] = arn
    return arn


def _register_task_def(ctx, family, containers, exec_role, task_role=None, cpu="256",
                       memory="512") -> dict:
    ecs = ctx.client("ecs")
    kwargs = dict(family=family, containerDefinitions=containers,
                  requiresCompatibilities=["FARGATE"], networkMode="awsvpc", cpu=cpu,
                  memory=memory, executionRoleArn=exec_role, tags=_ecs_tags())
    if task_role:
        kwargs["taskRoleArn"] = task_role
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return td


def _run_task(ctx, cluster, td_arn, net, sgs=None, overrides=None) -> str:
    ecs = ctx.client("ecs")
    _swallow(lambda: ctx.client("iam").create_service_linked_role(
        AWSServiceName="ecs.amazonaws.com"))
    kwargs = dict(cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
                  tags=_ecs_tags(), networkConfiguration={"awsvpcConfiguration": {
                      "subnets": [net["subnet"]], "securityGroups": sgs or [net["sg"]],
                      "assignPublicIp": "ENABLED"}})
    if overrides:
        kwargs["overrides"] = overrides
    deadline = _deadline(ctx, _IAM_PROPAGATION_S)
    while True:  # a just-created role may not be assumable by ECS yet
        try:
            resp = ecs.run_task(**kwargs)
            break
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            message = str(exc).lower()
            # RunTask can reject a just-created role two ways: synchronously as
            # InvalidParameterException, or (also synchronously) as ClientException once ECS
            # has accepted the role shape but still cannot assume it.
            role_not_ready = (
                (code == "InvalidParameterException" and "role" in message)
                or (code == "ClientException" and "unable to assume the role" in message))
            if not role_not_ready or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    assert resp["failures"] == [], f"RunTask failures: {resp['failures']!r}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.stop_task(cluster=cluster, task=arn)))
    net["tasks"].append(arn)
    return arn


def _await_task(ctx, cluster, task_arn, status, timeout_s) -> dict:
    ecs = ctx.client("ecs")

    def probe():
        found = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return found[0] if found else {}

    task = _poll(probe, lambda t: t.get("lastStatus") in (status, "STOPPED"), timeout_s,
                 what=f"task {task_arn} reaching {status}")
    assert task["lastStatus"] == status, (
        f"task {task_arn} is {task['lastStatus']!r}, expected {status!r}: stopCode="
        f"{task.get('stopCode')!r} stoppedReason={task.get('stoppedReason')!r} containers="
        f"{[(c['name'], c.get('exitCode'), c.get('reason')) for c in task.get('containers', [])]!r}"
    )
    return task


def _eni_details(task: dict) -> dict:
    atts = [a for a in task.get("attachments", []) if a["type"] == "ElasticNetworkInterface"]
    assert len(atts) == 1, f"an awsvpc task has exactly one ENI attachment; got {atts!r}"
    return {d["name"]: d["value"] for d in atts[0]["details"]}


def _log_messages(ctx, group: str, stream: str) -> list[str]:
    """Every event in the stream, paginated forward from the head ([] until it exists)."""
    logs = ctx.client("logs")
    msgs: list[str] = []
    token = None
    while True:
        kwargs: dict = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kwargs["nextToken"] = token
        page = _swallow(lambda: logs.get_log_events(**kwargs))
        if page is None:
            return msgs
        events = page.get("events", [])
        msgs += [e.get("message", "") for e in events]
        nxt = page.get("nextForwardToken")
        if not events or nxt == token:
            return msgs
        token = nxt


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


# ===== target-sourced container image (self-contained) =====
#: Images the tasks run: the reference, its linux/amd64 image ID (the config digest), and the file
#: the runner pre-seeds it as with `docker save`. The check never pulls from a registry.
_SEED_IMAGES = {
    "python": (
        "public.ecr.aws/docker/library/python:3.12-alpine",
        "sha256:38fd5a425aa93b06d367e2e47e2da6a9bc0cabdaf5788fb1707d143fd1416e97",
        "python-3.12-alpine-38fd5a42.tar",
    ),
}
_SEED_DIR = pathlib.Path.home() / ".cache" / "sim2real" / "images"
_LAYER_PART_BYTES = 8 * 1024 * 1024
_PUSHED: dict[tuple[int, str], tuple[object, str]] = {}


def _seeded_image(key: str) -> tuple[bytes, list[bytes]]:
    """The pre-seeded image's config and gzip layers, verified against its pinned image ID.

    A runner without the archive, or with one holding another image, is a runner fault:
    ``tool_missing``, never a finding about the target.
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


def _target_image(ctx, key: str = "python") -> str:
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
# ===== end target-sourced container image =====


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
