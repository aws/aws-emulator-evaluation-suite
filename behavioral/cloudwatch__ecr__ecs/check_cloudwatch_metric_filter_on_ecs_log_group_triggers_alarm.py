"""cloudwatch-metric-filter-on-ecs-log-group-triggers-alarm."""
from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudwatch-metric-filter-on-ecs-log-group-triggers-alarm"
GROUP = "metrics-delivery"
SERVICES = ["cloudwatch", "ecr", "ecs"]

EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CloudWatch Logs metric filter on an ECS task's log group turns real
    container log lines into a custom metric, and an alarm on that metric
    transitions to ALARM once matching lines are ingested."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    subnets, sg = _fargate_network(ctx)
    role_arn = _create_execution_role(ctx)
    cluster = _create_cluster(ctx, insights=False)

    log_group = ctx.unique_name("/sim2real/ecs/")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    task_def_arn, _ = _register_task_def(
        ctx,
        role_arn,
        command=["sh", "-c", 'while true; do echo "ERROR marker line"; sleep 5; done'],
        log_group=log_group,
    )
    # The filter and the alarm exist before the task starts, so its first lines already count.
    namespace = "Sim2RealEcsLogMetrics"
    metric_name = ctx.unique_name("ErrorMarkerCount")
    filter_name = ctx.unique_name("sim2real-filter-")
    logs.put_metric_filter(
        logGroupName=log_group,
        filterName=filter_name,
        filterPattern='"ERROR marker line"',
        metricTransformations=[
            {"metricName": metric_name, "metricNamespace": namespace, "metricValue": "1", "defaultValue": 0}
        ],
    )
    ctx.on_cleanup(lambda: logs.delete_metric_filter(logGroupName=log_group, filterName=filter_name))

    alarm_name = ctx.unique_name("sim2real-alarm-logfilter-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    service = _create_service(ctx, cluster, task_def_arn, subnets, [sg], desired_count=1)
    _wait_for_running_tasks(ctx, cluster, service, 1, timeout_s=_budget_s(ctx, 300))

    points = _poll_metric_datapoints(
        ctx, namespace, metric_name, [], timeout_s=_budget_s(ctx, 300), interval_s=2, stat="Sum"
    )
    if not points and _budget_spent(ctx):
        raise TimeoutError(f"a {namespace}/{metric_name} datapoint from the ECS task logs: the run budget ended "
                           "first; not graded")
    assert points, f"metric filter never produced a {namespace}/{metric_name} datapoint from ECS task logs"
    assert any(p["Sum"] >= 1 for p in points), (
        f"expected a datapoint with Sum >= 1 (each matching log line adds 1 to {metric_name}), got {points}"
    )

    state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=_budget_s(ctx, 300),
        interval_s=2,
    )
    if state != "ALARM" and _budget_spent(ctx):
        raise TimeoutError(f"alarm {alarm_name} reaching ALARM: the run budget ended first; not graded")
    assert state == "ALARM", f"alarm never transitioned to ALARM from ingested ECS log lines (state={state})"

    history = cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="StateUpdate")["AlarmHistoryItems"]
    summaries = [h["HistorySummary"] for h in history]
    assert any("ALARM" in s for s in summaries), f"alarm history has no ALARM transition: {summaries}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _fargate_network(ctx):
    net = _create_network(ctx, n_subnets=1)
    return net["subnet_ids"], net["sg_id"]


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


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=EXEC_POLICY_ARN))
    return role["Arn"]


def _create_cluster(ctx, insights: bool = False) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(
        clusterName=name,
        settings=[{"name": "containerInsights", "value": "enabled" if insights else "disabled"}],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    return name


def _register_task_def(
    ctx,
    execution_role_arn: str,
    command: list[str],
    cpu: str = "256",
    memory: str = "512",
    log_group: str | None = None,
) -> tuple[str, str]:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-taskdef-")
    container: dict[str, Any] = {
        "name": "app",
        "image": _target_image(ctx, "busybox"),
        "essential": True,
        "command": command,
    }
    if log_group:
        container["logConfiguration"] = {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group,
                "awslogs-region": ctx.region,
                "awslogs-stream-prefix": "sim2real",
            },
        }
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu=cpu,
        memory=memory,
        executionRoleArn=execution_role_arn,
        containerDefinitions=[container],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn, family


def _create_service(
    ctx, cluster: str, task_def_arn: str, subnets: list[str], sgs: list[str], desired_count: int = 1
) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-svc-")
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets, "securityGroups": sgs, "assignPublicIp": "ENABLED"}
    }
    last_err = None
    for _ in range(10):
        try:
            ecs.create_service(
                cluster=cluster,
                serviceName=name,
                taskDefinition=task_def_arn,
                desiredCount=desired_count,
                launchType="FARGATE",
                networkConfiguration=net_cfg,
                tags=[{"key": "sim2real", "value": "true"}],
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidParameterException", "ClientException"):
                time.sleep(5)
                continue
            raise
    else:
        raise last_err

    def _cleanup() -> None:
        ecs.update_service(cluster=cluster, service=name, desiredCount=0)
        _poll_until(
            lambda: len(ecs.list_tasks(cluster=cluster, serviceName=name)["taskArns"]),
            lambda n: n == 0,
            timeout_s=180,
            interval_s=2,
        )
        ecs.delete_service(cluster=cluster, service=name, force=True)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_for_running_tasks(ctx, cluster: str, service: str, count: int, timeout_s: float = 300.0) -> None:
    ecs = ctx.client("ecs")
    running = _poll_until(
        lambda: ecs.describe_services(cluster=cluster, services=[service])["services"][0]["runningCount"],
        lambda n: n >= count,
        timeout_s=timeout_s,
        interval_s=2,
    )
    if running < count:
        if _budget_spent(ctx):
            raise TimeoutError(f"service {service} reaching {count} running tasks: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"service never reached {count} running tasks (got {running})")


def _poll_metric_datapoints(
    ctx,
    namespace: str,
    metric_name: str,
    dimensions: list[dict[str, str]],
    timeout_s: float = 600.0,
    interval_s: float = 30.0,
    stat: str = "Average",
) -> list[dict[str, Any]]:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=20)
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=[stat],
        )
        points = resp.get("Datapoints", [])
        if points:
            return points
        time.sleep(interval_s)
    return []


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


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
