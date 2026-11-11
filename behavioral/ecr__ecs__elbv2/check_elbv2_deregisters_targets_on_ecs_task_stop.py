"""elbv2-deregisters-targets-on-ecs-task-stop."""
from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "elbv2-deregisters-targets-on-ecs-task-stop"
GROUP = "target-registration"
SERVICES = ["ecr", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scaling an ECS service's desired count to zero stops its task, and the ALB
    target group automatically deregisters the corresponding target -- with no
    replacement task, the target group converges to empty."""
    net = _create_network(ctx)
    cluster = _create_cluster(ctx)
    task_def_arn = _register_task_def(ctx)
    alb = _create_alb_and_tg(ctx, net["vpc_id"], net["subnet_ids"], net["sg_id"])
    ecs = ctx.client("ecs")
    service = _create_service(
        ctx, cluster, task_def_arn, net["subnet_ids"], net["sg_id"],
        tg_arn=alb["tg_arn"], desired_count=1,
    )

    _wait_running_count(ctx, cluster, service, 1, timeout_s=360)
    _wait_target_count(ctx, alb["tg_arn"], 1, timeout_s=180)

    # Break exactly one thing: stop the service (no replacement task will be launched).
    ecs.update_service(cluster=cluster, service=service, desiredCount=0)
    _wait_running_count(ctx, cluster, service, 0, timeout_s=180)

    remaining = _wait_target_count(ctx, alb["tg_arn"], 0, timeout_s=240)
    assert remaining == [], f"expected target group to converge to 0 targets, still has {remaining!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *,
                timeout_s: float = 120.0, interval_s: float = 5.0, description: str = "condition",
                ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


def _tag_spec(ctx, resource_type: str, kind: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{kind}-")}]}


def _create_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tag_spec(ctx, "internet-gateway", "igw")]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.99.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", f"subnet{i}")],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tag_spec(ctx, "route-table", "rt")]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for sid in subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(lambda assoc_id=assoc_id: ec2.disassociate_route_table(AssociationId=assoc_id))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-"), Description="sim2real ecs-elbv2 test sg", VpcId=vpc_id,
        TagSpecifications=[_tag_spec(ctx, "security-group", "sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "10.99.0.0/16"}]}],
    )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    return name


def _register_task_def(ctx, container_name: str = "app", container_port: int = 80) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-td-")
    resp = ecs.register_task_definition(
        executionRoleArn=_image_pull_role(ctx),
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[{
            "name": container_name,
            "image": _target_image(ctx, "busybox"),
            "command": ["sh", "-c", "mkdir -p /www && echo OK > /www/index.html && httpd -f -p 80 -h /www"],
            "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
            "essential": True,
            "healthCheck": {
                "command": ["CMD-SHELL", "wget -q -O- http://localhost:80/ | grep -q OK || exit 1"],
                "interval": 15, "timeout": 5, "retries": 3, "startPeriod": 10,
            },
        }],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _create_alb_and_tg(ctx, vpc_id: str, subnet_ids: list, sg_id: str, port: int = 80) -> dict:
    elbv2 = ctx.client("elbv2")
    alb_name = ctx.unique_name("sim2real-alb-")[:32].strip("-")
    alb_arn = elbv2.create_load_balancer(
        Name=alb_name, Subnets=subnet_ids, SecurityGroups=[sg_id], Type="application", Scheme="internet-facing",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))

    tg_name = ctx.unique_name("sim2real-tg-")[:32].strip("-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType="ip",
        HealthCheckProtocol="HTTP", HealthCheckPath="/", HealthCheckIntervalSeconds=10,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2, Matcher={"HttpCode": "200"},
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    elbv2.modify_target_group_attributes(
        TargetGroupArn=tg_arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "0"}],
    )

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return {"alb_arn": alb_arn, "tg_arn": tg_arn, "listener_arn": listener_arn}


def _create_service(ctx, cluster: str, task_def_arn: str, subnet_ids: list, sg_id: str, *,
                     tg_arn: "str | None" = None, container_name: str = "app",
                     container_port: int = 80, desired_count: int = 1) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-svc-")
    kwargs: dict[str, Any] = dict(
        cluster=cluster,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED",
        }},
    )
    if tg_arn:
        kwargs["loadBalancers"] = [{
            "targetGroupArn": tg_arn, "containerName": container_name, "containerPort": container_port,
        }]
        kwargs["healthCheckGracePeriodSeconds"] = 120
    ecs.create_service(**kwargs)
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=name, force=True))
    return name


def _wait_running_count(ctx, cluster: str, service: str, count: int, timeout_s: float = 360.0):
    ecs = ctx.client("ecs")

    def probe():
        d = ecs.describe_services(cluster=cluster, services=[service])["services"][0]
        return d["runningCount"]

    return _poll_until(probe, lambda rc: rc == count, timeout_s=_budget_s(ctx, timeout_s), interval_s=1,
                        description=f"service {service} runningCount=={count}", ctx=ctx)


def _wait_target_count(ctx, tg_arn: str, count: int, timeout_s: float = 180.0):
    elbv2 = ctx.client("elbv2")

    def probe():
        return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]

    return _poll_until(probe, lambda ths: len(ths) == count, timeout_s=_budget_s(ctx, timeout_s), interval_s=1,
                        description=f"target group {tg_arn} target count=={count}", ctx=ctx)


# Resources in the VPC delete asynchronously and leave their ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded, shared by all of one check's network deletes) for the ENIs to go, retry, then raise
# naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


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
#: local `docker save` archive it is loaded from. The check never pulls from a registry.
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

    A missing or mismatched archive is a local setup fault, never a finding about the target.
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

    A private ECR image needs an execution role to pull it on Fargate. IAM exposes no "role is
    assumable" condition; the service scheduler retries a task whose role is not yet usable, and
    the running-count poll waits for that.
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
