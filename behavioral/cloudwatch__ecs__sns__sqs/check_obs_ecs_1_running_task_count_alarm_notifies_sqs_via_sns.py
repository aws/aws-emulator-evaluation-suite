"""obs-ecs-1-running-task-count-alarm-notifies-sqs-via-sns."""
from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "obs-ecs-1-running-task-count-alarm-notifies-sqs-via-sns"
GROUP = "alarm-notification"
SERVICES = ["cloudwatch", "ecs", "sns", "sqs"]

_VPC_CIDR = "10.97.0.0/16"
_SUBNET_CIDR = "10.97.1.0/24"


# timing:real-time — metric: 120 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "concern:metrics",
    "concern:eventing",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """Scaling a Fargate service from one task to zero drives a RunningTaskCount < 1 alarm OK->ALARM;
    the transition is in alarm history and its SNS action delivers a message naming it to SQS.
    """
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    subnet, sg = _public_network(ctx, ec2)

    cluster = ctx.unique_name("sim2real-xsvc-rtc-")
    ecs.create_cluster(clusterName=cluster,
                       settings=[{"name": "containerInsights", "value": "enabled"}],
                       tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _retry_cluster_delete(ecs, cluster))

    td = ecs.register_task_definition(
        executionRoleArn=_image_pull_role(ctx),
        family=ctx.unique_name("sim2real-xsvc-rtc-td-"), networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"], cpu="256", memory="512",
        containerDefinitions=[{"name": "app", "image": _target_image(ctx, "busybox"), "essential": True,
                               "command": ["sh", "-c", "sleep 3600"]}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_task_definition(ecs, td))

    service = ctx.unique_name("sim2real-xsvc-rtc-svc-")
    services: list[str] = []
    ctx.on_cleanup(lambda: _teardown_services(ec2, ecs, cluster, services, subnet, raise_on_leak=True))
    ecs.create_service(
        cluster=cluster, serviceName=service, taskDefinition=td, desiredCount=1,
        launchType="FARGATE", tags=[{"key": "sim2real", "value": CHECK}],
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": [subnet], "securityGroups": [sg], "assignPublicIp": "ENABLED"}})
    services.append(service)

    queue_name = ctx.unique_name("sim2real-xsvc-rtc-q-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-rtc-t-"),
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": queue_arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]})})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: _unsubscribe(sns, sub_arn))

    _poll_until(ctx, lambda: _svc(ecs, cluster, service)["runningCount"], lambda n: n == 1,
                timeout_s=420.0, interval_s=2.0, description=f"{service} reaching runningCount=1")

    # The alarm must first be OK on REAL data (RunningTaskCount=1), or a breaching-missing-data
    # ALARM would be indistinguishable from the scale-in. So wait for the datapoint first.
    _poll_until(ctx, lambda: [d for d in _series(cw, cluster, service) if d["Maximum"] >= 1.0],
                lambda dps: len(dps) >= 2, timeout_s=900.0, interval_s=2.0,
                description=f"two minutes of ECS/ContainerInsights RunningTaskCount>=1 for {service}")

    alarm = ctx.unique_name("sim2real-xsvc-rtc-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm, AlarmDescription=f"sim2real {CHECK}", Namespace="ECS/ContainerInsights",
        MetricName="RunningTaskCount", Statistic="Maximum", Period=60,
        EvaluationPeriods=2, DatapointsToAlarm=2, Threshold=1.0,
        ComparisonOperator="LessThanThreshold", TreatMissingData="breaching",
        Dimensions=[{"Name": "ClusterName", "Value": cluster},
                    {"Name": "ServiceName", "Value": service}],
        AlarmActions=[topic_arn], Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))
    _poll_until(ctx, lambda: _alarm(cw, alarm)["StateValue"], lambda s: s == "OK",
                timeout_s=420.0, interval_s=2.0,
                description=f"alarm {alarm} evaluating OK while {service} runs one task")

    scaled_at = datetime.now(timezone.utc)
    ecs.update_service(cluster=cluster, service=service, desiredCount=0)
    _poll_until(ctx, lambda: _svc(ecs, cluster, service)["runningCount"], lambda n: n == 0,
                timeout_s=300.0, interval_s=2.0, description=f"{service} scaling in to 0 tasks")

    def _alarm_transitions() -> list[dict]:
        out = []
        for page in cw.get_paginator("describe_alarm_history").paginate(
                AlarmName=alarm, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"):
            for item in page["AlarmHistoryItems"]:
                data = json.loads(item["HistoryData"])
                if data.get("newState", {}).get("stateValue") == "ALARM":
                    out.append({"ts": item["Timestamp"], "data": data})
        return out

    history = _poll_until(ctx, _alarm_transitions, lambda h: len(h) >= 1, timeout_s=900.0,
                          interval_s=2.0,
                          description=f"an ALARM transition of {alarm} in DescribeAlarmHistory")
    transition = history[-1]
    assert transition["ts"] >= scaled_at - timedelta(seconds=5), (
        f"the latest ALARM transition at {transition['ts']!r} predates the scale-in at "
        f"{scaled_at!r}; full ALARM history {history!r}")
    old = transition["data"].get("oldState", {}).get("stateValue")
    assert old == "OK", f"the ALARM transition came from {old!r}; expected OK"
    assert _alarm(cw, alarm)["StateValue"] == "ALARM", "alarm left ALARM while the service runs 0 tasks"

    def _drain() -> list[dict]:
        msgs = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=10).get("Messages", [])
        out = []
        for m in msgs:
            envelope = json.loads(m["Body"])
            payload = json.loads(envelope["Message"])
            out.append({"envelope": envelope, "payload": payload})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        return out

    # SNS is at-least-once, so a duplicate is legal; what is asserted is that the queue (private
    # to this check) received the notification and nothing that is not about this alarm.
    received: list[dict] = []
    _poll_until(ctx, lambda: received.extend(_drain()) or received, lambda r: len(r) >= 1,
                timeout_s=300.0, interval_s=1.0,
                description=f"an SNS notification for {alarm} arriving in {queue_name}")
    foreign = [r["payload"].get("AlarmName") for r in received if r["payload"].get("AlarmName") != alarm]
    assert not foreign, f"queue received notifications for other alarms {foreign!r}"
    envelope, payload = received[-1]["envelope"], received[-1]["payload"]
    assert envelope.get("Type") == "Notification", f"SNS envelope type {envelope.get('Type')!r}"
    assert envelope.get("TopicArn") == topic_arn, f"envelope TopicArn {envelope.get('TopicArn')!r}"
    assert payload.get("AlarmName") == alarm, f"notification names alarm {payload.get('AlarmName')!r}"
    assert payload.get("NewStateValue") == "ALARM", f"NewStateValue {payload.get('NewStateValue')!r}"
    assert payload.get("OldStateValue") == "OK", f"OldStateValue {payload.get('OldStateValue')!r}"
    trigger = payload.get("Trigger") or {}
    assert (trigger.get("MetricName"), trigger.get("Namespace")) == (
        "RunningTaskCount", "ECS/ContainerInsights"), f"Trigger {trigger!r}"
    dims = {d.get("name") or d.get("Name"): d.get("value") or d.get("Value")
            for d in trigger.get("Dimensions", [])}
    assert dims == {"ClusterName": cluster, "ServiceName": service}, f"Trigger dimensions {dims!r}"

    _teardown_services(ec2, ecs, cluster, services, subnet)


def _series(cw, cluster: str, service: str) -> list[dict]:
    now = datetime.now(timezone.utc)
    return cw.get_metric_statistics(
        Namespace="ECS/ContainerInsights", MetricName="RunningTaskCount",
        Dimensions=[{"Name": "ClusterName", "Value": cluster},
                    {"Name": "ServiceName", "Value": service}],
        StartTime=now - timedelta(minutes=20), EndTime=now + timedelta(minutes=1),
        Period=60, Statistics=["Maximum"])["Datapoints"]


def _alarm(cw, name: str) -> dict:
    return cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"][0]


def _svc(ecs, cluster: str, service: str) -> dict:
    return ecs.describe_services(cluster=cluster, services=[service])["services"][0]


def _unsubscribe(sns, arn: str) -> None:
    try:
        sns.unsubscribe(SubscriptionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


def _teardown_services(ec2, ecs, cluster: str, services: list[str], subnet: str, *,
                       raise_on_leak: bool = False) -> None:
    for svc in list(services):
        try:
            ecs.delete_service(cluster=cluster, service=svc, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {"ServiceNotFoundException",
                                                      "ServiceNotActiveException"}:
                raise
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        tasks = ecs.list_tasks(cluster=cluster, desiredStatus="RUNNING")["taskArns"]
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet]}])["NetworkInterfaces"]
        if not tasks and not enis:
            return
        time.sleep(2.0)
    msg = f"tasks/ENIs still present in {cluster}/{subnet} after 300s"
    if raise_on_leak:
        raise RuntimeError(msg)
    print(msg)


def _retry_cluster_delete(ecs, cluster: str) -> None:
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if time.monotonic() > deadline:
                raise RuntimeError(f"ECS cluster {cluster}: {code}") from exc
            time.sleep(2.0)


def _delete_task_definition(ecs, td: str) -> None:
    try:
        ecs.deregister_task_definition(taskDefinition=td)
    except ClientError:
        pass
    ecs.delete_task_definitions(taskDefinitions=[td])


def _tags(value: str, name: str) -> list[dict]:
    return [{"Key": "sim2real", "Value": value}, {"Key": "Name", "Value": name}]


def _public_network(ctx, ec2) -> tuple[str, str]:
    """A VPC of our own with an IGW, so Fargate can pull the public image. No default VPC."""
    name = ctx.unique_name("sim2real-xsvc-rtc-net-")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, f"no available availability zone in {ctx.region}"
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags(CHECK, name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc)))
    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _tags(CHECK, name)}])[
        "InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_dependency(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))
    main_rt = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc]},
        {"Name": "association.main", "Values": ["true"]}])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=main_rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=zones[0],
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags(CHECK, name)}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet)))
    sg = ec2.create_security_group(GroupName=name, Description="sim2real running task count, no ingress",
                                   VpcId=vpc, TagSpecifications=[
                                       {"ResourceType": "security-group",
                                        "Tags": _tags(CHECK, name)}])["GroupId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_security_group(GroupId=sg)))
    return subnet, sg


def _retry_dependency(fn, budget_s: float = 60.0) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll to a condition; the deadline is capped by the run's remaining budget."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


# ===== target-sourced container image (self-contained) =====
#: Images the tasks run: the reference, its linux/amd64 image ID (the config digest), and the file
#: it is pre-seeded as with `docker save`. The check never pulls from a registry.
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

    A missing archive, or one holding another image, is an environment fault (``tool_missing``),
    never a finding about the target.
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


def _image_pull_role(ctx) -> str:
    """An ECS task execution role that may pull the seeded image and write its logs.

    A private ECR image needs an execution role to pull it on Fargate. A task launched before the
    role propagates fails its pull and the service relaunches it, so the runningCount poll absorbs it.
    """
    hit = _PUSHED.get((id(ctx), "execution-role"))
    if hit and hit[0] is ctx:
        return hit[1]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-imgpull-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="image-pull", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [
            "ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "logs:CreateLogStream",
            "logs:PutLogEvents"], "Resource": "*"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="image-pull"))
    _PUSHED[(id(ctx), "execution-role")] = (ctx, arn)
    return arn
# ===== end target-sourced container image =====


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
