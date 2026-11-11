"""alb-listener-rule-forwards-to-correct-target-group."""
from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags

CHECK = "alb-listener-rule-forwards-to-correct-target-group"
GROUP = "target-group-routing"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Two header-matching listener rules forward to two distinct ECS services via their own
    target groups, and a request matching neither rule gets the default fixed-response."""
    vpc_id, subnets = _check_vpc_and_subnets(ctx)
    subnet_ids = [s["SubnetId"] for s in subnets]

    alb_sg = _create_sg(ctx, vpc_id, "alb ingress")
    _authorize_ingress_cidr(ctx, alb_sg, 80, ctx.ingress_cidrs())
    task_sg = _create_sg(ctx, vpc_id, "task ingress from alb")
    _authorize_ingress_sg(ctx, task_sg, 80, alb_sg)

    alb_arn, dns = _create_alb(ctx, subnet_ids, alb_sg)
    tg_a = _create_target_group(ctx, vpc_id, 80, "/")
    tg_b = _create_target_group(ctx, vpc_id, 80, "/")
    listener_arn = _create_listener(
        ctx, alb_arn,
        [{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "404", "ContentType": "text/plain", "MessageBody": "no route"}}],
    )
    elbv2 = ctx.client("elbv2")
    elbv2.create_rule(
        ListenerArn=listener_arn, Priority=10,
        Conditions=[{"Field": "http-header", "HttpHeaderConfig": {"HttpHeaderName": "X-Group", "Values": ["a"]}}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_a}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    elbv2.create_rule(
        ListenerArn=listener_arn, Priority=20,
        Conditions=[{"Field": "http-header", "HttpHeaderConfig": {"HttpHeaderName": "X-Group", "Values": ["b"]}}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_b}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    exec_role_arn = _create_exec_role(ctx)
    log_group = _create_log_group(ctx)
    cluster = _create_cluster(ctx)

    task_def_a = _register_task_def(
        ctx, _target_image(ctx, "nginx"), 80, exec_role_arn, log_group,
        command=["/bin/sh", "-c", "echo -n GROUP_A > /usr/share/nginx/html/index.html && exec nginx -g 'daemon off;'"],
    )
    task_def_b = _register_task_def(
        ctx, _target_image(ctx, "nginx"), 80, exec_role_arn, log_group,
        command=["/bin/sh", "-c", "echo -n GROUP_B > /usr/share/nginx/html/index.html && exec nginx -g 'daemon off;'"],
    )
    service_a = _create_service(ctx, cluster, task_def_a, subnet_ids, [task_sg], desired_count=1, target_group_arn=tg_a)
    service_b = _create_service(ctx, cluster, task_def_b, subnet_ids, [task_sg], desired_count=1, target_group_arn=tg_b)

    _wait_running_count(ctx, cluster, service_a, 1)
    _wait_running_count(ctx, cluster, service_b, 1)
    _wait_target_states(ctx, tg_a, timeout_s=240.0, interval_s=2.0, predicate=lambda s: len(s) >= 1 and s[0]["state"] == "healthy")
    _wait_target_states(ctx, tg_b, timeout_s=240.0, interval_s=2.0, predicate=lambda s: len(s) >= 1 and s[0]["state"] == "healthy")
    _wait_lb_active(ctx, alb_arn)

    status_a, body_a = _poll_until(
        lambda: _http_get(ctx, f"http://{dns}/", headers={"X-Group": "a"}), lambda r: r[0] is not None, timeout_s=_budget_s(ctx, 120.0),
        interval_s=2.0, ctx=ctx,
    )
    assert status_a == 200 and body_a == "GROUP_A"

    status_b, body_b = _http_get(ctx, f"http://{dns}/", headers={"X-Group": "b"})
    assert status_b == 200 and body_b == "GROUP_B"

    status_default, _body_default = _http_get(ctx, f"http://{dns}/")
    assert status_default == 404


def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _http_get(ctx, url, headers=None, timeout=5.0):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, headers={**(headers or {}), **_route})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError:
        return None, None


def _check_vpc_and_subnets(ctx):
    net = _create_network(ctx, n_subnets=2)
    return net["vpc_id"], [{"SubnetId": s} for s in net["subnet_ids"]]


def _create_network(ctx, n_subnets: int = 1) -> dict:
    """A VPC this check owns: public subnets behind an internet gateway (Fargate pulls the image
    over a public IP) and a default-egress-only security group. One cleanup tears it down in
    dependency order, retrying while ECS still holds task ENIs in it."""
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


def _create_sg(ctx, vpc_id, description):
    ec2 = ctx.client("ec2")
    name = f"sim2real-sg-{_short_id()}"
    group_id = ec2.create_security_group(
        GroupName=name, Description=description, VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_when_released(ec2, group_id))
    return group_id


def _delete_sg_when_released(ec2, group_id, timeout_s=600.0):
    """Task and load balancer ENIs hold the group for a while after their owners are deleted."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=group_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(3)


def _authorize_ingress_cidr(ctx, group_id, port, cidrs):
    ec2 = ctx.client("ec2")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": c} for c in cidrs]}],
    )


def _authorize_ingress_sg(ctx, group_id, port, source_group_id):
    ec2 = ctx.client("ec2")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "UserIdGroupPairs": [{"GroupId": source_group_id}]}],
    )


def _create_exec_role(ctx):
    iam = ctx.client("iam")
    role_name = f"sim2real-ecsexec-{_short_id()}"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)

    def _cleanup():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_log_group(ctx):
    logs = ctx.client("logs")
    name = f"/ecs/sim2real-{_short_id()}"
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    return name


def _register_task_def(ctx, image, container_port, exec_role_arn, log_group, command=None):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-task-")
    container = {
        "name": "app",
        "image": image,
        "essential": True,
        "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group,
                "awslogs-region": ctx.region,
                "awslogs-stream-prefix": "app",
            },
        },
    }
    if command:
        container["command"] = command
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[container],
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _create_service(ctx, cluster, task_def_arn, subnets, sg_ids, desired_count=1, target_group_arn=None, container_name="app", container_port=80):
    ecs = ctx.client("ecs")
    service_name = ctx.unique_name("sim2real-svc-")
    kwargs = dict(
        cluster=cluster,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnets, "securityGroups": sg_ids, "assignPublicIp": "ENABLED"}
        },
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    if target_group_arn:
        kwargs["loadBalancers"] = [{"targetGroupArn": target_group_arn, "containerName": container_name, "containerPort": container_port}]
        kwargs["healthCheckGracePeriodSeconds"] = 90
    ecs.create_service(**kwargs)

    def _cleanup():
        ecs.delete_service(cluster=cluster, service=service_name, force=True)
        ecs.get_waiter("services_inactive").wait(
            cluster=cluster, services=[service_name], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    ctx.on_cleanup(_cleanup)
    return service_name


def _wait_running_count(ctx, cluster, service_name, want, timeout_s=420.0, interval_s=2.0):
    ecs = ctx.client("ecs")

    def probe():
        d = ecs.describe_services(cluster=cluster, services=[service_name])["services"][0]
        return d["runningCount"]

    return _poll_until(probe, lambda v: v >= want, timeout_s=_budget_s(ctx, timeout_s), interval_s=interval_s, ctx=ctx)


def _create_alb(ctx, subnets, sg_id):
    elbv2 = ctx.client("elbv2")
    name = f"sim2real-alb-{_short_id()}"
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnets, SecurityGroups=[sg_id], Scheme="internet-facing", Type="application", IpAddressType="ipv4",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    lb = resp["LoadBalancers"][0]
    alb_arn, dns = lb["LoadBalancerArn"], lb["DNSName"]
    def _cleanup():
        elbv2.delete_load_balancer(LoadBalancerArn=alb_arn)
        elbv2.get_waiter("load_balancers_deleted").wait(
            LoadBalancerArns=[alb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    ctx.on_cleanup(_cleanup)
    return alb_arn, dns


def _create_target_group(ctx, vpc_id, port=80, health_path="/"):
    elbv2 = ctx.client("elbv2")
    name = f"sim2real-tg-{_short_id()}"
    tg_arn = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType="ip",
        HealthCheckProtocol="HTTP", HealthCheckPath=health_path,
        HealthCheckIntervalSeconds=5, HealthyThresholdCount=2, UnhealthyThresholdCount=2,
        HealthCheckTimeoutSeconds=4,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    # Deregistering a target waits out this delay before ECS can stop the task at teardown.
    elbv2.modify_target_group_attributes(
        TargetGroupArn=tg_arn, Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "0"}]
    )
    return tg_arn


def _create_listener(ctx, alb_arn, default_actions, port=80):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn, Protocol="HTTP", Port=port, DefaultActions=default_actions,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _wait_target_states(ctx, tg_arn, timeout_s=300.0, interval_s=2.0, predicate=lambda states: True):
    elbv2 = ctx.client("elbv2")

    def probe():
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
        return [
            {"id": d["Target"]["Id"], "port": d["Target"]["Port"], "state": d["TargetHealth"]["State"], "reason": d["TargetHealth"].get("Reason")}
            for d in resp["TargetHealthDescriptions"]
        ]

    return _poll_until(probe, predicate, timeout_s=_budget_s(ctx, timeout_s), interval_s=interval_s, ctx=ctx)


def _wait_lb_active(ctx, alb_arn, timeout_s=180.0, interval_s=2.0):
    elbv2 = ctx.client("elbv2")

    def probe():
        return elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"]

    return _poll_until(probe, lambda c: c == "active", timeout_s=_budget_s(ctx, timeout_s), interval_s=interval_s,
                       ctx=ctx)


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
#: it is pre-seeded as with `docker save`. The check never pulls from a registry.
_SEED_IMAGES = {
    "nginx": (
        "public.ecr.aws/docker/library/nginx:1.30",
        "sha256:2cbc7a3757186de8dbcf1e19d4fc591e1e27789cdc526e51c933ae02f5f1f0b0",
        "nginx-1.30.tar",
    ),
}
_SEED_DIR = pathlib.Path.home() / ".cache" / "sim2real" / "images"
_LAYER_PART_BYTES = 8 * 1024 * 1024
_PUSHED: dict[tuple[int, str], tuple[object, str]] = {}


def _seeded_image(key: str) -> tuple[bytes, list[bytes]]:
    """The pre-seeded image's config and gzip layers, verified against its pinned image ID.

    A missing archive, or one holding another image, is ``tool_missing``, not a target finding.
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


def _target_image(ctx, key: str = "nginx") -> str:
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
