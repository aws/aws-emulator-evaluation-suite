"""awslogs-datetime-format-starts-an-event-at-any-line-containing-a-timestamp."""
from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time

from behavioral_harness import tags

CHECK = "awslogs-datetime-format-starts-an-event-at-any-line-containing-a-timestamp"
GROUP = "log-workload-producers"
SERVICES = ["ecs", "logs"]

_MANAGED_TAGS = {"sim2real": CHECK}
_TASK_TIMEOUT_S = 600
_LOG_TIMEOUT_S = 180

#: Five stdout lines: two opening with a `%Y-%m-%d %H:%M:%S` timestamp, one carrying a timestamp
#: MID-line, two carrying none. The mid-line timestamp also starts an event: the strftime-derived
#: pattern is matched unanchored.
_TS1, _TS2 = "2026-10-01 12:00:01", "2026-10-01 12:00:02"
_PRINT = (f'printf "{_TS1} first %s\\n  trace a\\n  seen at {_TS2} mid-line\\n'
          f'{_TS2} second %s\\n  trace b\\n" "$NONCE" "$NONCE"; ')


def _script(linger_s: int) -> str:
    return f"{_PRINT}sleep {linger_s}; exit 0"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """`awslogs-datetime-format` starts an event at every line containing a timestamp, mid-line
    included, folding the rest: five lines become three events. A sibling container in the same
    task printing the same bytes with no option is the control and delivers five events.
    """
    ecs = ctx.client("ecs")
    nonce = ctx.unique_name("nonce-")
    net = _build_network(ctx, "dt")
    try:
        group = _create_log_group(ctx)
        exec_role = _iam_role(ctx, "exec", [{
            "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*"},
            {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"], "Resource": "*"}])
        cluster = _create_cluster(ctx, net)
        folded_opts = _awslogs(group, ctx.region)
        folded_opts["options"]["awslogs-datetime-format"] = "%Y-%m-%d %H:%M:%S"
        containers = [
            {"name": "folded", "image": _target_image(ctx, "busybox"), "essential": False,
             "entryPoint": ["sh", "-c"], "command": [_script(1)],
             "environment": [{"name": "NONCE", "value": nonce}],
             "logConfiguration": folded_opts},
            # Starts once "folded" has exited, so the essential container never stops the task
            # (and its sibling) early.
            {"name": "plain", "image": _target_image(ctx, "busybox"), "essential": True,
             "dependsOn": [{"containerName": "folded", "condition": "COMPLETE"}],
             "entryPoint": ["sh", "-c"], "command": [_script(1)],
             "environment": [{"name": "NONCE", "value": nonce}],
             "logConfiguration": _awslogs(group, ctx.region)},
        ]
        td = _register_task_def(ctx, ctx.unique_name("sim2real-dt-"), containers, exec_role)
        live_opts = {c["name"]: c["logConfiguration"]["options"] for c in td["containerDefinitions"]}
        assert live_opts["folded"].get("awslogs-datetime-format") == "%Y-%m-%d %H:%M:%S", (
            f"RegisterTaskDefinition echoed folded options {live_opts['folded']!r}"
        )
        task_arn, task = _run_until_launched(ctx, cluster, td["taskDefinitionArn"], net)
        task_id = task_arn.rsplit("/", 1)[-1]
        exits = {c["name"]: c.get("exitCode") for c in task["containers"]}
        assert exits == {"folded": 0, "plain": 0}, (
            f"container exit codes {exits!r}, expected both 0; stoppedReason "
            f"{task.get('stoppedReason')!r}"
        )

        plain = _poll(lambda: _log_messages(ctx, group, f"ecs/plain/{task_id}"),
                      lambda m: len(m) >= 5, _budget_s(ctx, _LOG_TIMEOUT_S),
                      what="the plain stream's 5 events", ctx=ctx)
        assert plain == [f"{_TS1} first {nonce}", "  trace a", f"  seen at {_TS2} mid-line",
                         f"{_TS2} second {nonce}", "  trace b"], (
            f"the control container (no pattern) delivered {plain!r}, expected one event per line"
        )
        folded = _poll(lambda: _log_messages(ctx, group, f"ecs/folded/{task_id}"),
                       lambda m: len(m) >= 3, _budget_s(ctx, _LOG_TIMEOUT_S),
                       what="the folded stream's events", ctx=ctx)
        stripped = [m.rstrip("\n") for m in folded]
        assert stripped == [f"{_TS1} first {nonce}\n  trace a", f"  seen at {_TS2} mid-line",
                            f"{_TS2} second {nonce}\n  trace b"], (
            f"with awslogs-datetime-format '%Y-%m-%d %H:%M:%S' the same five lines arrived as "
            f"{folded!r}, expected exactly three events: one opened by each line containing a "
            f"timestamp (the mid-line one included), the untimestamped lines folded into them"
        )
    finally:
        _settle(ctx, net)


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, timeout_s, interval_s=1.0, what="condition", ctx=None):
    """Bounded retry that RAISES on timeout. Never a bare sleep standing in for a wait."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _retry_delete(fn, attempts=4, interval_s=5.0):
    """Delete with retries: an ENI or a stopping task can hold a dependency for a while."""
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code.endswith("NotFound") or code in ("ClusterNotFoundException",):
                return
            time.sleep(interval_s)


def _usable_zone(ec2) -> str:
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, "no available availability zone in this region"
    return zones[0]


def _build_network(ctx, label: str) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"sim2real-awsl-{label}-")
    net: dict = {"name": name, "tasks": []}
    vpc = ec2.create_vpc(CidrBlock="10.87.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _ec2_tags(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    net["vpc"] = vpc
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc])
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

    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.87.1.0/24",
                               AvailabilityZone=_usable_zone(ec2), TagSpecifications=[
                                   {"ResourceType": "subnet", "Tags": _ec2_tags(name)}])[
        "Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    net["subnet"] = subnet

    sg = ec2.create_security_group(
        GroupName=name, Description="sim2real awslogs task SG (egress only)", VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _ec2_tags(name)}])["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg)))
    net["sg"] = sg
    return net


def _settle(ctx, net: dict) -> None:
    """IN-BAND teardown of the slow half: stop every task and wait for the subnet's ENIs to be
    released, because the engine bounds registered cleanups to 60 s and a Fargate ENI takes longer.
    Never raises: it must not mask the failure the body found."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    tasks, cluster = list(net.get("tasks", [])), net.get("cluster")
    for t in tasks:
        _swallow(lambda t=t: ecs.stop_task(cluster=cluster, task=t, reason="sim2real teardown"))
    if tasks:
        _swallow(lambda: _poll(
            lambda: [x["lastStatus"] for x in ecs.describe_tasks(
                cluster=cluster, tasks=tasks)["tasks"]],
            lambda ss: len(ss) == len(tasks) and all(x == "STOPPED" for x in ss), 300, 2,
            what="every task this check started reaching STOPPED"))
    if net.get("subnet"):
        _swallow(lambda: _poll(
            lambda: ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [net["subnet"]]}])["NetworkInterfaces"],
            lambda enis: not enis, 300, 2, what="subnet releasing its task ENIs"))


def _iam_role(ctx, kind: str, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-awsl-{kind}-")
    arn = iam.create_role(
        RoleName=name, Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
             "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()])["Role"]["Arn"]

    def _drop():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _swallow(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    _poll(lambda: _swallow(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
          lambda r: r is not None, 60, 2, what=f"role {name} inline policy readable")
    # IAM propagation to the assuming service has no observable condition; a task whose launch
    # races it is relaunched by _run_until_launched.
    return arn


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-awsl-lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _awslogs(group: str, region: str) -> dict:
    return {"logDriver": "awslogs", "options": {
        "awslogs-group": group, "awslogs-region": region, "awslogs-stream-prefix": "ecs"}}


def _create_cluster(ctx, net: dict) -> str:
    ecs = ctx.client("ecs")
    arn = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-awsl-cl-"),
                             tags=_ecs_tags())["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ecs.delete_cluster(cluster=arn)))
    net["cluster"] = arn
    return arn


def _register_task_def(ctx, family, containers, exec_role, cpu="256", memory="512") -> dict:
    ecs = ctx.client("ecs")
    td = ecs.register_task_definition(
        family=family, containerDefinitions=containers, requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc", cpu=cpu, memory=memory, executionRoleArn=exec_role,
        tags=_ecs_tags())["taskDefinition"]
    arn = td["taskDefinitionArn"]
    # LIFO: deregister runs first, then the delete that requires an INACTIVE revision.
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[arn])))
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.deregister_task_definition(taskDefinition=arn)))
    return td


def _run_task(ctx, cluster, td_arn, net) -> str:
    ecs = ctx.client("ecs")
    kwargs = dict(cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
                  tags=_ecs_tags(), networkConfiguration={"awsvpcConfiguration": {
                      "subnets": [net["subnet"]], "securityGroups": [net["sg"]],
                      "assignPublicIp": "ENABLED"}})
    resp = None
    for _ in range(60):  # bounded retry: a just-created role may not be assumable by ECS yet
        try:
            resp = ecs.run_task(**kwargs)
            break
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code not in ("InvalidParameterException", "ClientException") or (
                    "role" not in str(exc).lower()):
                raise
            time.sleep(2)
    assert resp is not None, "RunTask kept rejecting the freshly created roles"
    assert resp["failures"] == [], f"RunTask failures: {resp['failures']!r}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.stop_task(cluster=cluster, task=arn)))
    net["tasks"].append(arn)
    return arn


def _run_until_launched(ctx, cluster, td_arn, net) -> tuple[str, dict]:
    """Run the task to STOPPED, relaunching while it fails to start before any container ran
    (a just-created execution role not yet usable by ECS); returns (task_arn, stopped task)."""
    for attempt in range(6):
        task_arn = _run_task(ctx, cluster, td_arn, net)
        task = _await_task(ctx, cluster, task_arn, "STOPPED", _budget_s(ctx, _TASK_TIMEOUT_S))
        never_ran = all(c.get("exitCode") is None for c in task.get("containers", []))
        if not (task.get("stopCode") == "TaskFailedToStart" and never_ran) or attempt == 5:
            return task_arn, task
        time.sleep(2)
    raise AssertionError("unreachable")


def _await_task(ctx, cluster, task_arn, status, timeout_s) -> dict:
    ecs = ctx.client("ecs")

    def probe():
        found = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return found[0] if found else {}

    task = _poll(probe, lambda t: t.get("lastStatus") in (status, "STOPPED"), timeout_s,
                 what=f"task {task_arn} reaching {status}", ctx=ctx)
    assert task["lastStatus"] == status, (
        f"task {task_arn} is {task['lastStatus']!r}, expected {status!r}: stopCode="
        f"{task.get('stopCode')!r} stoppedReason={task.get('stoppedReason')!r} containers="
        f"{[(c['name'], c.get('exitCode'), c.get('reason')) for c in task.get('containers', [])]!r}"
    )
    return task


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


# ===== target-sourced container image (self-contained) =====
#: Images the tasks run: the reference, its linux/amd64 image ID (the config digest), and the
#: archive it is pre-seeded as with `docker save`. The check never pulls from a registry.
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

    A missing or mismatched archive raises ``tool_missing``, never a finding about the target.
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
# ===== end target-sourced container image =====


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
