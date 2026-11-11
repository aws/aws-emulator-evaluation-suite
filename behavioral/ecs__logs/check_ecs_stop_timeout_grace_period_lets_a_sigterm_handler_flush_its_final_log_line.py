"""ecs-stop-timeout-grace-period-lets-a-sigterm-handler-flush-its-final-log-line."""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-stop-timeout-grace-period-lets-a-sigterm-handler-flush-its-final-log-line"

GROUP = "task-lifecycle"

SERVICES = ["ecs", "logs"]

#: The handler's work. Chosen so the margin is a multiple, never a second or two: 10 s of work
#: comfortably fits inside the 60 s grace period and comfortably overruns the 2 s one.
_HANDLER_SECONDS = 10
_GRACEFUL_STOP_TIMEOUT = 60
_IMPATIENT_STOP_TIMEOUT = 2


# timing:real-time — workflow: 2 s https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html
@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With stopTimeout=60 a 10 s SIGTERM handler logs its shutdown line and exits 0; with
    stopTimeout=2 the same handler, stopped back to back, is SIGKILLed (137) before logging it,
    so stopTimeout is a real grace period.
    """
    _vpc_id, subnets = _default_vpc(ctx, min_subnets=1)
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
    ecs = ctx.client("ecs")

    marker = "sim2real-stoptimeout-" + ctx.unique_name("")[:10]
    family = ctx.unique_name(_XSVC_PREFIX + "td-stop-")
    # The trap sleeps, THEN prints, THEN exits 0 from inside the handler. So the shutdown line can
    # only exist if the handler was allowed to run to completion.
    command = [
        "sh",
        "-c",
        (
            f'trap "sleep {_HANDLER_SECONDS}; echo {marker}-flushed; exit 0" TERM; '
            f"echo {marker}-started; "
            "while true; do sleep 1; done"
        ),
    ]

    def _revision(stop_timeout: int):
        return _register_task_def(
            ctx,
            [
                {
                    "name": "app",
                    "image": _target_image(ctx, "busybox"),
                    "essential": True,
                    "stopTimeout": stop_timeout,
                    "command": command,
                    "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
                }
            ],
            execution_role_arn=exec_role,
            family=family,
        )

    graceful_td = _revision(_GRACEFUL_STOP_TIMEOUT)
    impatient_td = _revision(_IMPATIENT_STOP_TIMEOUT)
    graceful_registered_timeout = graceful_td["containerDefinitions"][0]["stopTimeout"]
    impatient_registered_timeout = impatient_td["containerDefinitions"][0]["stopTimeout"]
    assert graceful_registered_timeout == _GRACEFUL_STOP_TIMEOUT, (
        f"RegisterTaskDefinition should echo stopTimeout={_GRACEFUL_STOP_TIMEOUT}, "
        f"got {graceful_registered_timeout!r}"
    )
    assert impatient_registered_timeout == _IMPATIENT_STOP_TIMEOUT, (
        f"RegisterTaskDefinition should echo stopTimeout={_IMPATIENT_STOP_TIMEOUT}, "
        f"got {impatient_registered_timeout!r}"
    )

    graceful_arn = _run_task(ctx, cluster, graceful_td["taskDefinitionArn"], subnets)
    impatient_arn = _run_task(ctx, cluster, impatient_td["taskDefinitionArn"], subnets)
    graceful_stream = f"ecs/app/{graceful_arn.rsplit('/', 1)[-1]}"
    impatient_stream = f"ecs/app/{impatient_arn.rsplit('/', 1)[-1]}"

    _await_task(ctx, cluster, graceful_arn, {"RUNNING"}, timeout_s=900)
    _await_task(ctx, cluster, impatient_arn, {"RUNNING"}, timeout_s=900)

    # Both handlers are provably INSTALLED before either task is signalled: the started line is
    # printed after `trap`, so its arrival means the shell reached the loop.
    _await_log_stream(ctx, log_group, graceful_stream, timeout_s=420)
    _await_log_stream(ctx, log_group, impatient_stream, timeout_s=420)
    graceful_started = _await_marker(ctx, log_group, graceful_stream, f"{marker}-started")
    impatient_started = _await_marker(ctx, log_group, impatient_stream, f"{marker}-started")
    assert any(f"{marker}-started" in m for m in graceful_started), graceful_started
    assert any(f"{marker}-started" in m for m in impatient_started), (
        f"the stopTimeout={_IMPATIENT_STOP_TIMEOUT} task never ran at all, so its missing shutdown "
        f"line would prove nothing: {impatient_started!r}"
    )

    # One SIGTERM each, back to back — no propagation delta between the two sides.
    ecs.stop_task(cluster=cluster, task=graceful_arn, reason="sim2real stopTimeout differential")
    ecs.stop_task(cluster=cluster, task=impatient_arn, reason="sim2real stopTimeout differential")

    graceful_task = _await_task(ctx, cluster, graceful_arn, {"STOPPED"}, timeout_s=900)
    impatient_task = _await_task(ctx, cluster, impatient_arn, {"STOPPED"}, timeout_s=900)
    graceful_container = graceful_task["containers"][0]
    impatient_container = impatient_task["containers"][0]

    # The barrier, not a sleep: once this line is in the group, the impatient stream has had at
    # least as long to deliver by the same driver.
    graceful_msgs = _await_marker(ctx, log_group, graceful_stream, f"{marker}-flushed")
    assert any(f"{marker}-flushed" in m for m in graceful_msgs), (
        f"stopTimeout={_GRACEFUL_STOP_TIMEOUT} did not let a {_HANDLER_SECONDS}s SIGTERM handler "
        f"finish: {graceful_msgs!r} stopCode={graceful_task.get('stopCode')!r} "
        f"reason={graceful_container.get('reason')!r}"
    )
    assert graceful_container.get("exitCode") == 0, (
        f"the graceful container should exit 0 from its own handler, not be killed: "
        f"{graceful_container!r} stopCode={graceful_task.get('stopCode')!r}"
    )

    # Three further reads of the impatient stream, so one lucky poll cannot carry the absence.
    impatient_msgs: list[str] = []
    for _ in range(3):
        impatient_msgs = _log_messages(ctx, log_group, impatient_stream)
        assert not any(f"{marker}-flushed" in m for m in impatient_msgs), (
            f"stopTimeout={_IMPATIENT_STOP_TIMEOUT} should have SIGKILLed the handler mid-sleep, "
            f"but its shutdown line appeared: {impatient_msgs!r}"
        )
        time.sleep(10)
    assert any(f"{marker}-started" in m for m in impatient_msgs), (
        f"the impatient stream stopped delivering, so its emptiness is about the log path rather "
        f"than about stopTimeout: {impatient_msgs!r}"
    )
    assert impatient_container.get("exitCode") == 137, (
        f"the impatient container was expected to be SIGKILLed (128+9=137) at its "
        f"{_IMPATIENT_STOP_TIMEOUT}s deadline: {impatient_container!r} "
        f"stopCode={impatient_task.get('stopCode')!r}"
    )


def _await_marker(ctx, log_group: str, stream: str, marker: str) -> list[str]:
    return _poll_until(
        lambda: _log_messages(ctx, log_group, stream),
        lambda ms: any(marker in m for m in ms),
        timeout_s=420,
        interval_s=5,
        description=f"marker {marker!r} in {stream}",
    )


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


def _default_vpc(ctx, min_subnets=1):
    """(vpc_id, subnet_ids) from the shared network, one subnet per AZ.

    Its subnets route to an internet gateway, so a Fargate task with assignPublicIp=ENABLED
    pulls its image without a NAT gateway or EIP."""
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


def _iam_role(ctx, kind, trust_service, statements):
    """A role trusting trust_service with ONE inline policy, polled back; returns (name, arn).

    Trust-policy propagation to ECS is covered by `_run_task`'s bounded retry, not a sleep here."""
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
):
    ecs = ctx.client("ecs")
    kwargs: dict = dict(
        family=family or ctx.unique_name(_XSVC_PREFIX + "td-"),
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
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return td


def _run_task(ctx, cluster, td_arn, subnets, sg_ids=None) -> str:
    """RunTask, retrying (bounded) only ClientException "ECS was unable to assume the role...",
    which RunTask raises while a just-created execution role's trust policy propagates."""
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    awsvpc: dict = {"subnets": subnets, "assignPublicIp": "ENABLED"}
    if sg_ids:
        awsvpc["securityGroups"] = sg_ids

    def _attempt():
        try:
            return ecs.run_task(
                cluster=cluster,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration={"awsvpcConfiguration": awsvpc},
            )
        except ClientError as e:
            if "unable to assume the role" in str(e):
                return None
            raise

    resp = _poll_until(
        _attempt,
        lambda r: r is not None,
        timeout_s=90,
        interval_s=5,
        description=f"RunTask succeeds once the fresh execution role is assumable ({td_arn})",
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


def _stream_names(ctx, group: str) -> list[str]:
    """Every stream in the group, PAGINATED — the membership assertion above is only sound if
    another suite's leftovers cannot push ours off page one."""
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
