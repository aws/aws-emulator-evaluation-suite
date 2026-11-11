"""cli-ecs-run-task-without-log-configuration-no-cloudwatch-logs."""
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

CHECK = "cli-ecs-run-task-without-log-configuration-no-cloudwatch-logs"
GROUP = "cli-pipeline"
SERVICES = ["cloudwatch", "ecr", "ecs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A task run via `aws ecs run-task` whose definition omits logConfiguration exits 0 but leaves
    no stream or marker in the log group, while a sibling with an awslogs driver to the same group
    delivers its marker."""
    if not _aws_cli_available(ctx):
        raise AssertionError("aws CLI not present on PATH in the child-process env")

    ecs = ctx.client("ecs")
    logs = ctx.client("logs")

    log_group = ctx.unique_name("/sim2real/ecs-nolog-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    cluster_arn = _create_ecs_cluster(ctx)
    role_arn = _create_ecs_execution_role(ctx)
    net = _check_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [net["subnet_id"]],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }

    marker_no_log = f"sim2real-nolog-{uuid.uuid4().hex[:12]}"
    marker_with_log = f"sim2real-withlog-{uuid.uuid4().hex[:12]}"
    stream_prefix = "sim2real"

    family_no_log = ctx.unique_name("sim2real-nolog-taskdef-")
    td_no_log = ecs.register_task_definition(
        family=family_no_log,
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
                "command": ["sh", "-c", f"echo {marker_no_log} && exit 0"],
            }
        ],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_no_log["taskDefinitionArn"]))

    family_with_log = ctx.unique_name("sim2real-withlog-taskdef-")
    td_with_log = ecs.register_task_definition(
        family=family_with_log,
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
                "command": ["sh", "-c", f"echo {marker_with_log} && exit 0"],
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
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_with_log["taskDefinitionArn"]))

    run_no_log = _run_aws_with_role_retry(
        ctx,
        "ecs",
        "run-task",
        "--cluster",
        cluster_arn,
        "--task-definition",
        td_no_log["taskDefinitionArn"],
        "--launch-type",
        "FARGATE",
        "--network-configuration",
        json.dumps(net_cfg),
        "--count",
        "1",
    )
    assert run_no_log.get("tasks"), f"aws ecs run-task returned no tasks: {run_no_log}"
    task_no_log_arn = run_no_log["tasks"][0]["taskArn"]

    # Both tasks run at once; neither depends on the other.
    run_with_log = ecs.run_task(
        cluster=cluster_arn, taskDefinition=td_with_log["taskDefinitionArn"], launchType="FARGATE",
        networkConfiguration=net_cfg, count=1,
    )
    assert run_with_log.get("tasks"), f"run_task returned no tasks: {run_with_log}"
    task_with_log_arn = run_with_log["tasks"][0]["taskArn"]
    task_with_log_id = task_with_log_arn.rsplit("/", 1)[-1]
    final_no_log = _poll_task_until_stopped(ctx, cluster_arn, task_no_log_arn, timeout_s=180.0)
    assert final_no_log["containers"][0]["exitCode"] == 0, "no-log-config task should still run and exit cleanly"
    final_with_log = _poll_task_until_stopped(ctx, cluster_arn, task_with_log_arn, timeout_s=180.0)
    assert final_with_log["containers"][0]["exitCode"] == 0, "with-log-config positive control should also run and exit cleanly"

    # Positive control: the log-configured sibling's marker is delivered to the log group.
    with_log_stream = f"{stream_prefix}/app/{task_with_log_id}"
    with_log_events = _poll_log_events(ctx, log_group, with_log_stream, marker_with_log, timeout_s=90.0)
    assert any(marker_with_log in e["message"] for e in with_log_events), (
        f"positive control marker {marker_with_log!r} not found in {with_log_stream}: {with_log_events}"
    )

    all_streams = logs.describe_log_streams(logGroupName=log_group)["logStreams"]
    no_log_task_id = task_no_log_arn.rsplit("/", 1)[-1]
    assert not any(no_log_task_id in s["logStreamName"] for s in all_streams), (
        f"a log stream referencing the no-log-config task appeared: {all_streams}"
    )
    for stream in all_streams:
        events = logs.get_log_events(logGroupName=log_group, logStreamName=stream["logStreamName"], startFromHead=True)["events"]
        assert not any(marker_no_log in e["message"] for e in events), (
            f"the no-log-config task's marker leaked into stream {stream['logStreamName']}"
        )


_POLL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _run_aws_with_role_retry(ctx, *args: str, timeout_s: float = 60.0, retry_budget_s: float = 60.0) -> dict:
    """CLI calls that assume an ECS execution/task role right after it was created can fail
    with ClientException("...unable to assume the role...") for a short window before IAM
    propagation completes. Retry until it succeeds."""
    retry_budget_s = _budget_s(ctx, retry_budget_s)
    deadline = time.monotonic() + retry_budget_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return _run_aws(ctx, *args, timeout_s=timeout_s)
        except AssertionError as exc:
            msg = str(exc)
            if "assume the role" in msg or "AccessDenied" in msg:
                last_exc = exc
                time.sleep(_POLL_S)
                continue
            raise
    if _budget_spent(ctx):
        raise TimeoutError("CLI call succeeding after IAM propagation: the run budget ended first; not graded")
    raise AssertionError(f"CLI call never succeeded within {retry_budget_s:.0f}s (IAM propagation?): {last_exc}")


def _create_ecs_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=arn))
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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


def _check_network(ctx):
    net = _create_network(ctx, n_subnets=1)
    return net


def _create_network(ctx, n_subnets: int = 1) -> dict:
    """A VPC this check owns: public subnets behind an internet gateway (Fargate pulls the image
    over a public IP) and a security group with only the default allow-all egress rule. One
    cleanup tears the whole network down in dependency order, retrying while ECS still holds
    task ENIs in it."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-net-")

    def tag(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]}]

    net: dict = {"subnet_ids": []}
    net["vpc_id"] = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=tag("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_network(ctx, net))
    ec2.get_waiter("vpc_available").wait(VpcIds=[net["vpc_id"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    net["igw_id"] = ec2.create_internet_gateway(TagSpecifications=tag("internet-gateway"))[
        "InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    net["igw_attached"] = True
    net["rt_id"] = ec2.create_route_table(VpcId=net["vpc_id"], TagSpecifications=tag("route-table"))[
        "RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=net["rt_id"], DestinationCidrBlock="0.0.0.0/0", GatewayId=net["igw_id"])
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"]]
    if len(zones) < n_subnets:
        raise AssertionError(f"need {n_subnets} availability zones, the region offers {zones}")
    for i, zone in enumerate(sorted(zones)[:n_subnets]):
        subnet_id = ec2.create_subnet(
            VpcId=net["vpc_id"], CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=zone, TagSpecifications=tag("subnet")
        )["Subnet"]["SubnetId"]
        net["subnet_ids"].append(subnet_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        ec2.associate_route_table(RouteTableId=net["rt_id"], SubnetId=subnet_id)
    net["subnet_id"] = net["subnet_ids"][0]
    net["sg_id"] = ec2.create_security_group(
        GroupName=name, Description="sim2real check network", VpcId=net["vpc_id"], TagSpecifications=tag("security-group")
    )["GroupId"]
    return net


def _delete_network(ctx, net: dict, timeout_s: float = 900.0) -> None:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s

    def retrying(fn, **kwargs):
        while True:
            try:
                fn(**kwargs)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code.endswith(".NotFound") or code == "Gateway.NotAttached":
                    return
                if code != "DependencyViolation" or time.monotonic() > deadline:
                    raise
            time.sleep(3)

    if net.get("sg_id"):
        retrying(ec2.delete_security_group, GroupId=net["sg_id"])
    for subnet_id in net["subnet_ids"]:
        retrying(ec2.delete_subnet, SubnetId=subnet_id)
    if net.get("rt_id"):
        retrying(ec2.delete_route_table, RouteTableId=net["rt_id"])
    if net.get("igw_attached"):
        retrying(ec2.detach_internet_gateway, InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    if net.get("igw_id"):
        retrying(ec2.delete_internet_gateway, InternetGatewayId=net["igw_id"])
    retrying(ec2.delete_vpc, VpcId=net["vpc_id"])


def _poll_task_until_stopped(ctx, cluster_arn: str, task_arn: str, timeout_s: float = 240.0) -> dict:
    ecs = ctx.client("ecs")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
        if desc:
            last = desc[0]
            if last["lastStatus"] == "STOPPED":
                return last
        time.sleep(_POLL_S)
    if _budget_spent(ctx):
        raise TimeoutError(f"task {task_arn} reaching STOPPED: the run budget ended first; not graded")
    raise AssertionError(f"task never reached STOPPED within {timeout_s:.0f}s, last={last}")


def _poll_log_events(ctx, log_group: str, stream_name: str, marker: str, timeout_s: float = 90.0) -> list:
    logs = ctx.client("logs")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.get_log_events(logGroupName=log_group, logStreamName=stream_name, startFromHead=True)
            events = resp.get("events", [])
            if any(marker in e["message"] for e in events):
                return events
        except Exception:
            pass
        time.sleep(_POLL_S)
    if _budget_spent(ctx):
        raise TimeoutError(f"log stream {stream_name} in {log_group} showing the marker: "
                           "the run budget ended first; not graded")
    raise AssertionError(f"log stream {stream_name} in {log_group} never showed marker within {timeout_s:.0f}s")


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
#: `docker save` archive it is pre-seeded as. The check never pulls from a registry.
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

    A missing or mismatched archive raises RequiredToolMissing, not a finding about the target.
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
