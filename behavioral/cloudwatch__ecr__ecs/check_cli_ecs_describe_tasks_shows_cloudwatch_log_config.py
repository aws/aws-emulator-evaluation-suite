"""cli-ecs-describe-tasks-shows-cloudwatch-log-config."""
from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import shutil
import subprocess
import tarfile
import time
import uuid

from behavioral_harness import tags

CHECK = "cli-ecs-describe-tasks-shows-cloudwatch-log-config"
GROUP = "cli-pipeline"
SERVICES = ["cloudwatch", "ecr", "ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws CLI describe-task-definition reports the exact awslogs driver options we
    registered, and the CloudWatch Logs group they point at actually receives the
    container's stdout — not just that the API echoed back the config we sent."""
    if not _aws_cli_available(ctx):
        raise AssertionError("aws CLI not present on PATH in the child-process env")

    logs = ctx.client("logs")
    ecs = ctx.client("ecs")
    log_group = ctx.unique_name("/sim2real/ecs-")
    logs.create_log_group(logGroupName=log_group, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    cluster_arn = _create_ecs_cluster(ctx)
    role_arn = _create_ecs_execution_role(ctx)
    net = _default_network(ctx)

    stream_prefix = "sim2real"
    marker = f"sim2real-log-marker-{uuid.uuid4().hex[:12]}"
    family = ctx.unique_name("sim2real-logtaskdef-")
    task_def = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": _target_image(ctx, "busybox"),
                "essential": True,
                "command": ["sh", "-c", f"echo {marker} && exit 0"],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": stream_prefix,
                    },
                },
            }
        ],
        tags=_ecs_tags_kv(),
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def["taskDefinitionArn"]))

    described = _run_aws(
        ctx,
        "ecs",
        "describe-task-definition",
        "--task-definition",
        task_def["taskDefinitionArn"],
        timeout_s=30.0,
    )
    cli_opts = described["taskDefinition"]["containerDefinitions"][0]["logConfiguration"]["options"]
    assert cli_opts["awslogs-group"] == log_group, (
        f"CLI describe-task-definition awslogs-group mismatch: expected {log_group!r}, got {cli_opts['awslogs-group']!r}"
    )
    assert cli_opts["awslogs-region"] == ctx.region, (
        f"CLI describe-task-definition awslogs-region mismatch: expected {ctx.region!r}, got {cli_opts['awslogs-region']!r}"
    )
    assert cli_opts["awslogs-stream-prefix"] == stream_prefix, (
        f"CLI describe-task-definition awslogs-stream-prefix mismatch: expected {stream_prefix!r}, "
        f"got {cli_opts['awslogs-stream-prefix']!r}"
    )

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [net["subnet_id"]],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }
    run_out = _run_task_with_role_retry(
        ctx,
        cluster=cluster_arn,
        taskDefinition=task_def["taskDefinitionArn"],
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        count=1,
    )
    assert run_out["tasks"], f"run_task returned no tasks: {run_out}"
    task_arn = run_out["tasks"][0]["taskArn"]
    task_id = task_arn.rsplit("/", 1)[-1]

    final = _poll_task_until_stopped(ctx, cluster_arn, task_arn, timeout_s=180.0)
    exit_code = final["containers"][0].get("exitCode")
    assert exit_code == 0, (
        f"container did not exit 0: exitCode={exit_code} reason={final['containers'][0].get('reason')} "
        f"stoppedReason={final.get('stoppedReason')}"
    )

    stream_name = f"{stream_prefix}/app/{task_id}"
    events = _poll_log_events(ctx, log_group, stream_name, marker, timeout_s=90.0)
    assert any(marker in e["message"] for e in events), f"marker not found in log stream {stream_name}: {events}"


# ===== helpers =====
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _aws_cli_available(ctx) -> bool:
    return shutil.which("aws", path=ctx.subprocess_env().get("PATH")) is not None


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx, ["aws", "--output", "json", *args], env_extra={"AWS_PAGER": ""}, timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _create_ecs_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    arn = ecs.create_cluster(clusterName=name, tags=_ecs_tags_kv())["cluster"]["clusterArn"]

    def _drop():
        # A just-stopped task can leave the cluster's internal task ledger settling for a
        # few seconds after describe_tasks already reports STOPPED; delete_cluster can
        # transiently raise ClusterContainsTasksException in that window. Retry that code.
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + 30
        while True:
            try:
                ecs.delete_cluster(cluster=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ClusterNotFoundException":
                    return
                if code != "ClusterContainsTasksException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_drop)
    return arn


def _create_ecs_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role_arn


def _default_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    subnets = [s for s in subnets if s.get("AvailableIpAddressCount", 0) > 0]
    if not subnets:
        raise AssertionError("shared network has no available subnets with free IPs")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {"vpc_id": vpc_id, "subnet_id": subnets[0]["SubnetId"], "sg_id": sgs[0]["GroupId"]}


def _run_task_with_role_retry(ctx, *, timeout_s: float = 60.0, **kwargs) -> dict:
    """ecs.run_task can fail with ClientException("...unable to assume the role...") for a
    short window right after the execution role's trust policy / attached policy is created,
    before IAM propagation completes. Retry until it succeeds or the deadline passes."""
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ecs.run_task(**kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "assume the role" in msg or "AccessDenied" in msg:
                last_err = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"run_task never succeeded within {timeout_s}s (IAM propagation?): {last_err}")


def _poll_task_until_stopped(ctx, cluster_arn: str, task_arn: str, timeout_s: float = 240.0) -> dict:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
        if desc:
            last = desc[0]
            if last["lastStatus"] == "STOPPED":
                return last
        time.sleep(5)
    raise AssertionError(f"task never reached STOPPED within {timeout_s}s, last={last}")


def _poll_log_events(ctx, log_group: str, stream_name: str, marker: str, timeout_s: float = 90.0) -> list:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.get_log_events(logGroupName=log_group, logStreamName=stream_name, startFromHead=True)
            events = resp.get("events", [])
            if any(marker in e["message"] for e in events):
                return events
        except Exception:
            pass
        time.sleep(5)
    raise AssertionError(f"log stream {stream_name} in {log_group} never showed marker within {timeout_s}s")


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
