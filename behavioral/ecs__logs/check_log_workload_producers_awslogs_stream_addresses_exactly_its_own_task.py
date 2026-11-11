"""log-workload-producers-awslogs-stream-addresses-exactly-its-own-task."""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-workload-producers-awslogs-stream-addresses-exactly-its-own-task"

GROUP = "container-logs-delivery"

SERVICES = ["ecs", "logs"]


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c3",
    "cap:c5",
)
def run(ctx) -> None:
    """Two tasks from one task definition, sharing a log group and prefix, each log to exactly
    <prefix>/<container>/<task-id> with only their own marker and metadata-endpoint task ARN and
    never the sibling's; the stream name is minted by the log driver, not returned by any ECS call.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    net = _network(ctx)
    group = _log_group(ctx)
    role = _exec_role(ctx, ["logs:CreateLogStream", "logs:PutLogEvents", "ecr:GetAuthorizationToken",
                            "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer",
                            "ecr:BatchGetImage"])
    cluster = _cluster(ctx)
    prefix = ctx.unique_name("pfx-")
    container_name = "producer"
    script = (
        'echo "MARK=$MARKER"; '
        "wget -qO- \"$ECS_CONTAINER_METADATA_URI_V4/task\" | grep -o '\"TaskARN\":\"[^\"]*\"'; "
        "echo END"
    )
    td = _task_def(ctx, [{
        "name": container_name, "image": _target_image(ctx, "busybox"), "essential": True,
        "command": ["sh", "-c", script],
        "logConfiguration": _awslogs(group, ctx.region, prefix),
    }], role)

    markers = [ctx.unique_name("mark-a-"), ctx.unique_name("mark-b-")]
    overrides = [{"containerOverrides": [
        {"name": container_name, "environment": [{"name": "MARKER", "value": m}]}]}
        for m in markers]
    deadline = _deadline(ctx, _IAM_PROPAGATION_S)
    arns = [_run_task(ctx, cluster, td, net, overrides=o) for o in overrides]
    assert arns[0] != arns[1], f"RunTask returned the same task twice: {arns!r}"
    tasks = [_await_stopped(ctx, cluster, a) for a in arns]
    # A task that failed to start on the fresh role wrote no stream; it is rerun.
    while True:
        if not any(_role_not_yet_usable(t) for t in tasks) or time.monotonic() >= deadline:
            break
        time.sleep(2)
        tasks = [_await_stopped(ctx, cluster, _run_task(ctx, cluster, td, net, overrides=o))
                 if _role_not_yet_usable(t) else t for t, o in zip(tasks, overrides)]

    expected = {}
    for task, marker in zip(tasks, markers):
        c = task["containers"][0]
        assert c.get("exitCode") == 0, (
            f"producer did not exit 0: exitCode={c.get('exitCode')!r} "
            f"stopCode={task.get('stopCode')!r} reason={task.get('stoppedReason')!r}"
        )
        arn = task["taskArn"]
        # Parse the ARN structurally: arn:aws:ecs:<region>:<account>:task/<cluster>/<id>.
        head, resource = arn.split(":", 5)[:5], arn.split(":", 5)[5]
        assert head[2:5] == ["ecs", ctx.region, account], f"unexpected task ARN head {arn!r}"
        kind, arn_cluster, task_id = resource.split("/")
        assert (kind, arn_cluster) == ("task", cluster), f"task ARN resource {resource!r}"
        assert c["name"] == container_name, f"DescribeTasks container name {c['name']!r}"
        expected[f"{prefix}/{c['name']}/{task_id}"] = (marker, arn, task_id)

    # The prefix is unique to this run, so "exactly these streams" is a property of the query.
    streams = _poll_until(
        lambda: _streams(ctx, group, prefix + "/"),
        lambda s: s == sorted(expected),
        timeout_s=300,
        description=f"exactly the two task streams under {prefix}/",
    )
    for stream in streams:
        parts = stream.split("/")
        marker, arn, task_id = expected[stream]
        assert parts == [prefix, container_name, task_id], (
            f"stream {stream!r} does not decompose into (prefix, container, task id) = "
            f"{(prefix, container_name, task_id)!r}"
        )
        want = [f"MARK={marker}", f'"TaskARN":"{arn}"', "END"]
        msgs = _poll_until(
            lambda: [e["message"] for e in _events(ctx, group, stream)],
            lambda m: "END" in m,
            timeout_s=300,
            description=f"END line in {stream}",
        )
        assert msgs == want, f"stream {stream!r} holds {msgs!r}, expected exactly {want!r}"
        other = [m for m in markers if m != marker][0]
        assert not any(other in m for m in msgs), (
            f"sibling task's marker {other!r} leaked into {stream!r}: {msgs!r}"
        )

    # The log-stream ARN the logs API reports addresses the same group and stream name.
    logs = ctx.client("logs")
    for stream in streams:
        desc = logs.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream)["logStreams"]
        assert [d["logStreamName"] for d in desc] == [stream], desc
        assert desc[0]["arn"] == (
            f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}:log-stream:{stream}"
        ), f"log stream ARN {desc[0]['arn']!r}"


# ===== self-contained prerequisites =====
# Own VPC (never the ambient default VPC): one VPC, an internet gateway, a public route
# table and two subnets in derived AZs. assignPublicIp=ENABLED lets Fargate pull the
# ECR image through the IGW, so no NAT gateway or EIP is ever created.
_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _TAGS.items()]


def _swallow(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown
        pass


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _network(ctx):
    """(subnet_ids, sg_id) in a VPC this check creates and tears down."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(_PREFIX + "vpc-")

    def spec(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name}, *_tags_kv()]}]

    vpc = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=spec("vpc"))["Vpc"]["VpcId"]
    made = {"vpc": vpc, "subnets": [], "igw": None, "rtb": None, "sg": None}

    def _drop():
        # Fargate releases a task's ENI asynchronously after STOPPED; wait for that to
        # happen (an observable condition) before the subnets can be deleted.
        _leaks: list = []
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "vpc-id", "Values": [vpc]}]
            )["NetworkInterfaces"]
            if not enis:
                break
            time.sleep(10)
        else:
            _leaks.append((f"ENIs still present in {vpc} after 600s", None))
        for sn in made["subnets"]:
            _swallow(lambda sn=sn: ec2.delete_subnet(SubnetId=sn))
        if made["rtb"]:
            _swallow(lambda: ec2.delete_route_table(RouteTableId=made["rtb"]))
        if made["igw"]:
            _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=made["igw"], VpcId=vpc))
            _swallow(lambda: ec2.delete_internet_gateway(InternetGatewayId=made["igw"]))
        if made["sg"]:
            _swallow(lambda: ec2.delete_security_group(GroupId=made["sg"]))
        try:
            ec2.delete_vpc(VpcId=vpc)
        except Exception as err:  # noqa: BLE001
            teardown_code = (getattr(err, "response", None) or {}).get("Error", {}).get("Code", "")
            if teardown_code not in ("InvalidVpcID.NotFound",):
                _leaks.append((f"vpc {vpc} not deleted: {err}", err))
        if _leaks:
            raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                (e for _, e in _leaks if e is not None), None
            )

    ctx.on_cleanup(_drop)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw = ec2.create_internet_gateway(TagSpecifications=spec("internet-gateway"))
    made["igw"] = igw["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=made["igw"], VpcId=vpc)
    made["rtb"] = ec2.create_route_table(VpcId=vpc, TagSpecifications=spec("route-table"))[
        "RouteTable"
    ]["RouteTableId"]
    ec2.create_route(
        RouteTableId=made["rtb"], DestinationCidrBlock="0.0.0.0/0", GatewayId=made["igw"]
    )
    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    )
    assert len(azs) >= 2, f"need two available AZs in {ctx.region}, found {azs!r}"
    for i, az in enumerate(azs[:2]):
        sn = ec2.create_subnet(
            VpcId=vpc, CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=spec("subnet"),
        )["Subnet"]["SubnetId"]
        made["subnets"].append(sn)
        ec2.associate_route_table(RouteTableId=made["rtb"], SubnetId=sn)
    made["sg"] = ec2.create_security_group(
        GroupName=name, Description="sim2real ecs log producer egress", VpcId=vpc,
        TagSpecifications=spec("security-group"),
    )["GroupId"]
    return list(made["subnets"]), made["sg"]


def _exec_role(ctx, actions):
    """Task execution role trusting ecs-tasks with ONE inline logs policy; returns ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_PREFIX + "exec-")[:64]
    arn = iam.create_role(
        RoleName=name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _drop():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="logs"))
        _swallow(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_drop)
    iam.put_role_policy(
        RoleName=name, PolicyName="logs",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": list(actions), "Resource": "*"}]}),
    )
    # IAM exposes no "policy is effective" condition: _run_task retries a not-yet-assumable
    # role and run() reruns a task that failed to start on it.
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


def _log_group(ctx):
    logs = ctx.client("logs")
    name = ctx.unique_name(_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_TAGS))
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_PREFIX + "cl-")
    ecs.create_cluster(clusterName=name, tags=[{"key": k, "value": v} for k, v in _TAGS.items()])

    def _drop():
        for _ in range(12):
            try:
                ecs.delete_cluster(cluster=name)
                return
            except Exception:  # noqa: BLE001 - tasks still stopping
                time.sleep(10)
        raise RuntimeError(f"ecs cluster {name} not deleted")

    ctx.on_cleanup(_drop)
    return name


def _awslogs(group, region, prefix, **extra):
    opts = {"awslogs-group": group, "awslogs-region": region, "awslogs-stream-prefix": prefix}
    opts.update(extra)
    return {"logDriver": "awslogs", "options": opts}


def _task_def(ctx, containers, exec_role=None):
    ecs = ctx.client("ecs")
    kw = dict(
        family=ctx.unique_name(_PREFIX + "td-"),
        containerDefinitions=containers,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc", cpu="256", memory="512",
    )
    if exec_role:
        kw["executionRoleArn"] = exec_role
    arn = ecs.register_task_definition(**kw)["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _ensure_ecs_slr(ctx):
    """Fargate RunTask needs AWSServiceRoleForECS; creating it is idempotent (exists = ok)."""
    _swallow(lambda: ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com"))


def _run_task(ctx, cluster, td_arn, net, overrides=None, timeout_s=120):
    """RunTask, retrying only while a just-created execution role is not yet assumable."""
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    subnets, sg = net
    kw = dict(
        cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnets, "securityGroups": [sg], "assignPublicIp": "ENABLED"}},
    )
    if overrides:
        kw["overrides"] = overrides
    deadline = _deadline(ctx, timeout_s)
    while True:
        try:
            resp = ecs.run_task(**kw)
        except ClientError as err:
            msg = err.response.get("Error", {}).get("Message", "")
            if "unable to assume the role" not in msg.lower() or time.monotonic() > deadline:
                raise
            time.sleep(2)
            continue
        if resp.get("tasks"):
            arn = resp["tasks"][0]["taskArn"]
            ctx.on_cleanup(lambda: _swallow(lambda: ecs.stop_task(cluster=cluster, task=arn)))
            return arn
        assert time.monotonic() < deadline, f"RunTask never placed a task: {resp.get('failures')!r}"
        time.sleep(2)


def _await_stopped(ctx, cluster, task_arn, timeout_s=600):
    ecs = ctx.client("ecs")

    def probe():
        ts = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return ts[0] if ts else {}

    return _poll_until(probe, lambda t: t.get("lastStatus") == "STOPPED", timeout_s=timeout_s,
                       description=f"task {task_arn} STOPPED")


def _streams(ctx, group, prefix=None):
    logs = ctx.client("logs")
    kw = {"logGroupName": group}
    if prefix:
        kw["logStreamNamePrefix"] = prefix
    out = []
    for page in logs.get_paginator("describe_log_streams").paginate(**kw):
        out.extend(s["logStreamName"] for s in page["logStreams"])
    return sorted(out)


def _events(ctx, group, stream):
    """Every event in the stream, oldest first, following nextForwardToken to the end."""
    logs = ctx.client("logs")
    out, token = [], None
    while True:
        kw = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kw["nextToken"] = token
        r = logs.get_log_events(**kw)
        out.extend(r["events"])
        if r.get("nextForwardToken") == token:
            return out
        token = r.get("nextForwardToken")


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
