"""ecs-capacity-provider-scales-asg-and-places-task."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import pathlib
import tarfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-capacity-provider-scales-asg-and-places-task"

GROUP = "container-capacity-provider"

SERVICES = ["autoscaling", "ec2", "ecs"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A queued ECS task makes ECS managed scaling raise the ASG's desired capacity.

    Desired capacity goes 0 -> >=1, an instance launches and registers into this cluster, and the
    queued task is placed on it and RUNNING; baselines rule out pre-existing capacity.
    """
    ecs = ctx.client("ecs")

    vpc_id, subnets = _default_vpc(ctx, min_subnets=1)
    subnets = subnets[:2]
    sg_id = _default_sg(ctx, vpc_id)
    cluster = _create_cluster(ctx)

    role_name, _role_arn = _iam_role(
        ctx, "ecs-inst", "ec2.amazonaws.com", _ECS_INSTANCE_STATEMENTS
    )
    profile = _instance_profile(ctx, role_name)
    ami = _ssm_ami(
        ctx, "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"
    )
    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n"
    lt_name = _launch_template(
        ctx, ami, user_data, instance_profile=profile, sg_ids=[sg_id]
    )

    # min 0 / max 1 / desired 0: the check must PROVE ECS moved it, and the blast radius
    # is a single t3.micro that the ASG teardown force-terminates.
    asg_name = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=1, desired=0)
    group = _describe_asg(ctx, asg_name)
    assert group["DesiredCapacity"] == 0, group["DesiredCapacity"]
    assert group["Instances"] == [], group["Instances"]
    asg_arn = group["AutoScalingGroupARN"]

    cp_name = ctx.unique_name(_XSVC_PREFIX + "cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {
                "status": "ENABLED",
                "targetCapacity": 100,
                "minimumScalingStepSize": 1,
                "maximumScalingStepSize": 1,
                "instanceWarmupPeriod": 60,
            },
            "managedTerminationProtection": "DISABLED",
        },
        tags=_ecs_tags_kv(),
    )

    def _drop_cp():
        for _ in range(10):
            try:
                ecs.delete_capacity_provider(capacityProvider=cp_name)
                return
            except Exception:  # noqa: BLE001 - still attached / draining
                time.sleep(15)

    ctx.on_cleanup(_drop_cp)

    ecs.put_cluster_capacity_providers(
        cluster=cluster,
        capacityProviders=[cp_name],
        defaultCapacityProviderStrategy=[
            {"capacityProvider": cp_name, "weight": 1, "base": 0}
        ],
    )
    # Detach before the capacity provider itself is deleted (registered earlier => runs later).
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.put_cluster_capacity_providers(
                cluster=cluster,
                capacityProviders=[],
                defaultCapacityProviderStrategy=[],
            )
        )
    )
    _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster], include=["ATTACHMENTS"])[
            "clusters"
        ][0],
        lambda c: (
            c.get("attachmentsStatus") in ("UPDATE_COMPLETE", None)
            and cp_name in (c.get("capacityProviders") or [])
        ),
        timeout_s=300,
        interval_s=10,
        description=f"capacity provider {cp_name} attached to {cluster}",
    )

    _ensure_ecs_slr(ctx)
    marker = "sim2real-cp-task-" + ctx.unique_name("")[:8]
    td = _register_ec2_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": _target_image(ctx, "busybox"),
                "essential": True,
                "cpu": 128,
                "memory": 128,
                "command": ["sh", "-c", f"echo {marker}; sleep 600"],
            }
        ],
    )
    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=td["taskDefinitionArn"],
        count=1,
        capacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
    )
    assert not resp.get("failures"), f"RunTask failures: {resp.get('failures')}"
    task_arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: ecs.stop_task(cluster=cluster, task=task_arn))
    )

    # --- Effect 1 (ECS -> Auto Scaling): desired capacity is raised off zero.
    scaled = _poll_until(
        lambda: _describe_asg(ctx, asg_name),
        lambda g: g["DesiredCapacity"] >= 1,
        timeout_s=900,
        interval_s=15,
        description="ECS managed scaling raised the ASG desired capacity above 0",
    )
    assert scaled["DesiredCapacity"] == 1, scaled["DesiredCapacity"]
    assert scaled["MaxSize"] == 1, scaled["MaxSize"]

    # --- Effect 2 (Auto Scaling -> EC2): an instance really launched.
    instances = _poll_until(
        lambda: _describe_asg(ctx, asg_name)["Instances"],
        lambda ins: len(ins) >= 1,
        timeout_s=600,
        interval_s=15,
        description="the ASG launched an instance for the new desired capacity",
    )
    instance_ids = {i["InstanceId"] for i in instances}
    reservations = ctx.client("ec2").describe_instances(
        InstanceIds=sorted(instance_ids)
    )["Reservations"]
    states = {
        i["InstanceId"]: i["State"]["Name"]
        for r in reservations
        for i in r["Instances"]
    }
    assert states and all(s in ("pending", "running") for s in states.values()), (
        f"unexpected instance states: {states}"
    )

    # --- Effect 3 (EC2 -> ECS): the instance registered into THIS cluster.
    ci_arns = _poll_until(
        lambda: ecs.list_container_instances(cluster=cluster).get(
            "containerInstanceArns", []
        ),
        lambda arns: len(arns) >= 1,
        timeout_s=900,
        interval_s=15,
        description=f"an instance registered as a container instance in {cluster}",
    )
    container_instances = ecs.describe_container_instances(
        cluster=cluster, containerInstances=ci_arns
    )["containerInstances"]
    registered = {c["ec2InstanceId"] for c in container_instances}
    assert registered & instance_ids, (
        f"container instances {registered} are not the ASG's instances {instance_ids}"
    )
    assert any(c["status"] == "ACTIVE" for c in container_instances), (
        container_instances
    )
    described = ecs.describe_clusters(clusters=[cluster])["clusters"][0]
    assert described["registeredContainerInstancesCount"] >= 1, described

    # --- Effect 4: the task that triggered the scale-out is actually placed and running.
    placed = _poll_until(
        lambda: (
            ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks") or [{}]
        )[0],
        lambda t: t.get("lastStatus") in ("RUNNING", "STOPPED"),
        timeout_s=600,
        interval_s=15,
        description=f"task {task_arn} placed on the new capacity",
    )
    assert placed["lastStatus"] == "RUNNING", (
        f"task never ran on the scaled-out capacity: stopCode={placed.get('stopCode')} "
        f"reason={placed.get('stoppedReason')}"
    )
    assert placed.get("containerInstanceArn") in ci_arns, (
        f"task placed on {placed.get('containerInstanceArn')}, not on the ASG's "
        f"container instances {ci_arns}"
    )
    assert placed.get("capacityProviderName") == cp_name, placed.get(
        "capacityProviderName"
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


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _default_vpc(ctx, min_subnets=1):
    """(vpc_id, subnet_ids) from the shared network, one subnet per AZ.

    Its subnets already route to an internet gateway, so no NAT gateway or EIP is created."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get(
        "Vpcs", []
    )
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


def _default_sg(ctx, vpc_id: str) -> str:
    """The default security group of vpc_id (nothing to create, nothing to leak)."""
    sgs = (
        ctx.client("ec2")
        .describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        )
        .get("SecurityGroups", [])
    )
    if not sgs:
        raise AssertionError(f"VPC {vpc_id} has no default security group")
    return sgs[0]["GroupId"]


def _iam_role(ctx, kind, trust_service, statements):
    """Create a role trusting trust_service with one inline policy; returns (name, arn).

    IAM is eventually consistent, so both are polled back; EC2/ECS propagation is retried
    downstream, where the "not visible yet" error first surfaces."""
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


def _instance_profile(ctx, role_name: str) -> str:
    """An instance profile wrapping role_name (an EC2 instance assumes a role only through one),
    polled back because the profile->role association is eventually consistent."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_XSVC_PREFIX + "ip-")
    iam.create_instance_profile(
        InstanceProfileName=name, Path="/sim2real/", Tags=_tags_kv()
    )

    def _drop():
        _swallow(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=name, RoleName=role_name
            )
        )
        _swallow(lambda: iam.delete_instance_profile(InstanceProfileName=name))

    ctx.on_cleanup(_drop)
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=role_name)
    _poll_until(
        lambda: _safe(lambda: iam.get_instance_profile(InstanceProfileName=name)),
        lambda r: bool((r or {}).get("InstanceProfile", {}).get("Roles")),
        timeout_s=90,
        interval_s=3,
        description=f"instance profile {name} carries its role",
    )
    return name


def _ssm_ami(ctx, parameter: str) -> str:
    """An AMI id from an AWS-published SSM public parameter, so the check never carries a
    hard-coded, region-bound, perpetually-stale AMI id."""
    value = ctx.client("ssm").get_parameter(Name=parameter)["Parameter"]["Value"]
    if value.startswith("{"):
        value = json.loads(value)["image_id"]
    assert value.startswith("ami-"), f"{parameter} did not resolve to an AMI: {value!r}"
    return value


def _launch_template(
    ctx,
    image_id,
    user_data,
    *,
    instance_type="t3.micro",
    instance_profile=None,
    sg_ids=None,
):
    """A launch template tagging both the instance and its volume at launch, so an
    interrupted teardown still leaves attributable resources."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(_XSVC_PREFIX + "lt-")
    data: dict = {
        "ImageId": image_id,
        "InstanceType": instance_type,
        "UserData": base64.b64encode(user_data.encode("utf-8")).decode("ascii"),
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": _tags_kv()},
            {"ResourceType": "volume", "Tags": _tags_kv()},
        ],
    }
    if instance_profile:
        data["IamInstanceProfile"] = {"Name": instance_profile}
    if sg_ids:
        data["SecurityGroupIds"] = list(sg_ids)
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData=data,
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )

    def _drop():
        for _ in range(6):
            try:
                ec2.delete_launch_template(LaunchTemplateName=name)
                return
            except Exception:  # noqa: BLE001 - still referenced by a deleting ASG
                time.sleep(10)

    ctx.on_cleanup(_drop)
    return name


def _create_asg(
    ctx,
    lt_name,
    subnets,
    *,
    min_size=0,
    max_size=1,
    desired=0,
    target_group_arns=None,
    health_check_type=None,
    grace=None,
):
    """An ASG whose teardown force-deletes and waits for it to disappear, so its instances are gone
    before the earlier-registered template, SG and profile teardowns run. A just-created profile
    not yet visible to EC2 fails create with "Invalid IAM Instance Profile name", so that is retried."""
    asg = ctx.client("autoscaling")
    name = ctx.unique_name(_XSVC_PREFIX + "asg-")
    kwargs: dict = dict(
        AutoScalingGroupName=name,
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        VPCZoneIdentifier=",".join(subnets),
        Tags=[
            {"Key": k, "Value": v, "PropagateAtLaunch": True}
            for k, v in _MANAGED_TAGS.items()
        ],
    )
    if target_group_arns:
        kwargs["TargetGroupARNs"] = list(target_group_arns)
    if health_check_type:
        kwargs["HealthCheckType"] = health_check_type
    if grace is not None:
        kwargs["HealthCheckGracePeriod"] = grace

    def _try_create() -> bool:
        try:
            asg.create_auto_scaling_group(**kwargs)
            return True
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "ValidationError" and "IAM Instance Profile" in err.get(
                "Message", ""
            ):
                return False
            raise

    _poll_until(
        _try_create,
        lambda ok: ok is True,
        timeout_s=90,
        interval_s=10,
        description=f"auto scaling group {name} accepts launch template {lt_name}'s instance profile",
    )

    def _drop():
        _swallow(
            lambda: asg.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, DesiredCapacity=0
            )
        )
        _swallow(
            lambda: asg.delete_auto_scaling_group(
                AutoScalingGroupName=name, ForceDelete=True
            )
        )
        for _ in range(60):
            found = _safe(
                lambda: asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])
            )
            if not (found or {}).get("AutoScalingGroups"):
                return
            time.sleep(10)

    ctx.on_cleanup(_drop)
    return name


def _describe_asg(ctx, name) -> dict:
    groups = (
        ctx.client("autoscaling")
        .describe_auto_scaling_groups(AutoScalingGroupNames=[name])
        .get("AutoScalingGroups", [])
    )
    assert groups, f"auto scaling group {name} not found"
    return groups[0]


def _ensure_ecs_slr(ctx) -> None:
    """RunTask on Fargate needs AWSServiceRoleForECS (CreateService auto-creates it,
    RunTask does not). Idempotent — already-exists is success."""
    _swallow(
        lambda: ctx.client("iam").create_service_linked_role(
            AWSServiceName="ecs.amazonaws.com"
        )
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


def _register_ec2_task_def(ctx, container_defs, *, execution_role_arn=None):
    """An EC2-launch-type task definition (bridge networking) -- the shape a capacity
    provider actually has to place onto a registered container instance."""
    ecs = ctx.client("ecs")
    kwargs: dict = dict(
        family=ctx.unique_name(_XSVC_PREFIX + "td-ec2-"),
        containerDefinitions=container_defs,
        requiresCompatibilities=["EC2"],
        networkMode="bridge",
        tags=_ecs_tags_kv(),
    )
    if execution_role_arn:
        kwargs["executionRoleArn"] = execution_role_arn
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(
        lambda: _retire_task_definition(ecs, arn)
    )
    return td


_ECS_INSTANCE_STATEMENTS = [
    {
        "Effect": "Allow",
        "Action": [
            "ecs:DeregisterContainerInstance",
            "ecs:RegisterContainerInstance",
            "ecs:Submit*",
            "ecs:DiscoverPollEndpoint",
            "ecs:Poll",
            "ecs:StartTelemetrySession",
            "ecs:UpdateContainerInstancesState",
            "ecr:GetAuthorizationToken",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
        ],
        "Resource": "*",
    }
]


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

    A missing or mismatched archive is an environment fault (``tool_missing``), not a finding.
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
