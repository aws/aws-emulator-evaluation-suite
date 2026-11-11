"""ecs-cloud-map-registered-task-is-discoverable-by-its-private-ip-and-drops-out-when-stopped."""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time

from behavioral_harness import tags

CHECK = "ecs-cloud-map-registered-task-is-discoverable-by-its-private-ip-and-drops-out-when-stopped"

GROUP = "service-discovery"

SERVICES = ["ecs", "servicediscovery"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """ECS registers a task's ENI IPv4 into Cloud Map as a HEALTHY instance, visible through
    DiscoverInstances, and deregisters it on scale-to-zero while the Cloud Map service remains.
    """
    ecs = ctx.client("ecs")
    sd = ctx.client("servicediscovery")
    vpc_id, subnets = _default_vpc(ctx, min_subnets=2)
    subnets = subnets[:2]
    namespace = _private_dns_namespace(ctx, vpc_id)
    cm = _cloudmap_service(ctx, namespace["Id"], "A")
    cluster = _create_cluster(ctx)

    td = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": _target_image(ctx, "busybox"),
                "essential": True,
                "command": ["sh", "-c", "sleep 3600"],
            }
        ],
        execution_role_arn=_image_pull_role(ctx),
    )
    svc = _create_fargate_service(
        ctx,
        cluster,
        td["taskDefinitionArn"],
        subnets,
        desired_count=1,
        service_registries=[{"registryArn": cm["Arn"]}],
    )
    service = svc["serviceName"]

    tasks = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 1,
        timeout_s=600,
        interval_s=2,
        description=f"service {service} has 1 RUNNING task",
    )
    attachments = tasks[0].get("attachments")
    task_ip = _task_private_ip(tasks[0])
    assert task_ip, (
        f"the RUNNING task has no privateIPv4Address attachment: {attachments!r}"
    )

    # DiscoverInstances, not DNS: a private namespace is unresolvable from outside the VPC. The
    # absence gets the same budget as the presence so "not yet propagated" never reads as "revoked".
    budget_s = 420
    instances = _poll_until(
        lambda: _discovered(ctx, namespace["Name"], cm["Name"]),
        lambda ins: len(ins) == 1,
        timeout_s=budget_s,
        interval_s=2,
        description=f"one instance discoverable in {namespace['Name']}/{cm['Name']}",
    )
    assert len(instances) == 1, (
        f"expected exactly one discovered instance, got {instances!r}"
    )
    advertised = instances[0].get("Attributes", {}).get("AWS_INSTANCE_IPV4")
    assert advertised == task_ip, (
        f"Cloud Map advertises {advertised!r} but the task's ENI address is {task_ip!r} — the "
        f"registration is not of THIS task (attributes {instances[0].get('Attributes')!r})"
    )
    assert instances[0].get("HealthStatus") == "HEALTHY", (
        f"the ECS-registered instance is not HEALTHY in Cloud Map: {instances[0]!r}"
    )

    ecs.update_service(cluster=cluster, service=service, desiredCount=0)
    _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 0,
        timeout_s=600,
        interval_s=2,
        description=f"service {service} drained to zero RUNNING tasks",
    )
    after = _poll_until(
        lambda: _discovered(ctx, namespace["Name"], cm["Name"]),
        lambda ins: ins == [],
        timeout_s=budget_s,
        interval_s=2,
        description=f"no instances discoverable in {namespace['Name']}/{cm['Name']}",
    )
    assert after == [], (
        f"the instance was not deregistered after scale-to-zero: {after!r} (it advertised "
        f"{advertised!r} for a task that no longer exists)"
    )
    # ...and the Cloud Map service itself is still there, so the absence is a deregistration and
    # not the service having been deleted underneath the query.
    still_there = sd.get_service(Id=cm["Id"])["Service"]
    assert still_there["Id"] == cm["Id"], still_there


def _discovered(ctx, namespace_name: str, service_name: str) -> list[dict]:
    """DiscoverInstances (the Cloud Map discovery endpoint), unfiltered on health so a wrong
    HealthStatus fails an assertion instead of reading like non-registration."""
    return ctx.client("servicediscovery").discover_instances(
        NamespaceName=namespace_name, ServiceName=service_name
    )["Instances"]



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
    """(vpc_id, subnet_ids) from the run's shared network, one subnet per AZ.

    Its subnets route to an internet gateway, so no NAT gateway or EIP is needed."""
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
    network_mode="awsvpc",
    requires_compatibilities=("FARGATE",),
):
    """Register one revision. cpu/memory are task-level and must be OMITTED (not None) for a
    non-Fargate revision, where the size lives on the container definition instead."""
    ecs = ctx.client("ecs")
    kwargs: dict = dict(
        family=family or ctx.unique_name(_XSVC_PREFIX + "td-"),
        containerDefinitions=container_defs,
        requiresCompatibilities=list(requires_compatibilities),
        networkMode=network_mode,
        tags=_ecs_tags_kv(),
    )
    if cpu:
        kwargs["cpu"] = cpu
    if memory:
        kwargs["memory"] = memory
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
    ctx.on_cleanup(
        lambda: _retire_task_definition(ecs, arn)
    )
    return td


def _run_task(ctx, cluster, td_arn, subnets, sg_ids=None) -> str:
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    awsvpc: dict = {"subnets": subnets, "assignPublicIp": "ENABLED"}
    if sg_ids:
        awsvpc["securityGroups"] = sg_ids
    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={"awsvpcConfiguration": awsvpc},
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


def _task_private_ip(task: dict) -> str | None:
    """The awsvpc ENI's private IPv4 — the address an ELBv2 'ip' target group registers."""
    for att in task.get("attachments", []):
        if att.get("type") == "ElasticNetworkInterface":
            for detail in att.get("details", []):
                if detail.get("name") == "privateIPv4Address":
                    return detail.get("value")
    return None


def _await_operation(ctx, operation_id: str, *, timeout_s=600.0) -> dict:
    """Poll a Cloud Map operation to a terminal status and return it.

    A new namespace can be unusable by CreateService (NamespaceNotFoundException) until then."""
    sd = ctx.client("servicediscovery")
    op = _poll_until(
        lambda: sd.get_operation(OperationId=operation_id)["Operation"],
        lambda o: o.get("Status") in ("SUCCESS", "FAIL"),
        timeout_s=timeout_s,
        interval_s=5,
        description=f"cloud map operation {operation_id} terminal",
    )
    assert op["Status"] == "SUCCESS", (
        f"cloud map operation {operation_id} failed: {op!r}"
    )
    return op


def _namespace_service_ids(ctx, ns_id: str) -> list[str]:
    """Every Cloud Map service in the namespace, PAGINATED and filtered server-side."""
    sd = ctx.client("servicediscovery")
    ids: list[str] = []
    token = None
    while True:
        kwargs: dict = {
            "Filters": [{"Name": "NAMESPACE_ID", "Values": [ns_id], "Condition": "EQ"}]
        }
        if token:
            kwargs["NextToken"] = token
        page = sd.list_services(**kwargs)
        ids += [s["Id"] for s in page.get("Services", [])]
        token = page.get("NextToken")
        if not token:
            return ids


def _delete_cloudmap_service(ctx, service_id: str) -> None:
    """Deregister every instance, then delete the service. Best-effort (teardown path).

    DeleteService returns ResourceInUse while any instance is still registered, and an
    ECS-registered instance is deregistered by ECS asynchronously after the ECS service drains —
    so this both waits for that and finishes the job if ECS has not."""
    sd = ctx.client("servicediscovery")
    for _ in range(30):
        insts = _safe(
            lambda: sd.list_instances(ServiceId=service_id).get("Instances", [])
        )
        for inst in insts or []:
            _swallow(
                lambda i=inst: sd.deregister_instance(
                    ServiceId=service_id, InstanceId=i["Id"]
                )
            )
        if _safe(lambda: sd.delete_service(Id=service_id)) is not None:
            return
        time.sleep(10)


def _private_dns_namespace(ctx, vpc_id: str) -> dict:
    """A private DNS namespace, polled through get_operation to SUCCESS. -> {Id, Arn, Name}.

    Teardown drains its Cloud Map services first: DeleteNamespace is rejected while any remain."""
    sd = ctx.client("servicediscovery")
    name = ctx.unique_name(_XSVC_PREFIX + "ns-") + ".sim2real"
    op_id = sd.create_private_dns_namespace(
        Name=name,
        Vpc=vpc_id,
        Description="sim2real-xsvc ecs service discovery",
        Tags=_tags_kv(),
    )["OperationId"]

    def _drop():
        ns = _safe(lambda: sd.get_namespace(Id=ns_id))
        if ns is None:
            return
        for _ in range(30):
            ids = _safe(lambda: _namespace_service_ids(ctx, ns_id))
            if not ids:
                break
            for sid in ids:
                _swallow(lambda s=sid: _delete_cloudmap_service(ctx, s))
            time.sleep(10)
        del_op = _safe(lambda: sd.delete_namespace(Id=ns_id))
        if del_op is None:
            raise RuntimeError(f"cloud map namespace {ns_id} ({name}) could not be deleted")
        _swallow(lambda: _await_operation(ctx, del_op["OperationId"], timeout_s=600))

    op = _await_operation(ctx, op_id, timeout_s=900)
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(_drop)
    ns = sd.get_namespace(Id=ns_id)["Namespace"]
    return {"Id": ns_id, "Arn": ns["Arn"], "Name": ns["Name"]}


def _create_fargate_service(
    ctx,
    cluster,
    td_arn,
    subnets,
    *,
    desired_count=1,
    sg_ids=None,
    load_balancers=None,
    health_check_grace_period_seconds=None,
    service_connect=None,
    service_registries=None,
    deployment_configuration=None,
):
    """A Fargate service; teardown DRAINS it (desiredCount=0 -> delete force -> wait for
    INACTIVE) before the cluster teardown registered earlier can run, because an ACTIVE
    service blocks cluster deletion."""
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-svc-")
    awsvpc: dict = {"subnets": subnets, "assignPublicIp": "ENABLED"}
    if sg_ids:
        awsvpc["securityGroups"] = sg_ids
    kwargs: dict = dict(
        cluster=cluster,
        serviceName=name,
        taskDefinition=td_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": awsvpc},
        tags=_ecs_tags_kv(),
    )
    if load_balancers:
        kwargs["loadBalancers"] = load_balancers
    if health_check_grace_period_seconds is not None:
        kwargs["healthCheckGracePeriodSeconds"] = health_check_grace_period_seconds
    if service_connect is not None:
        kwargs["serviceConnectConfiguration"] = service_connect
    if service_registries is not None:
        kwargs["serviceRegistries"] = service_registries
    if deployment_configuration is not None:
        kwargs["deploymentConfiguration"] = deployment_configuration
    svc = ecs.create_service(**kwargs)["service"]

    def _drop():
        _swallow(
            lambda: ecs.update_service(cluster=cluster, service=name, desiredCount=0)
        )
        _swallow(lambda: ecs.delete_service(cluster=cluster, service=name, force=True))
        _swallow(
            lambda: _poll_until(
                lambda: (
                    ecs.describe_services(cluster=cluster, services=[name]).get(
                        "services"
                    )
                    or [{}]
                )[0].get("status", "INACTIVE"),
                lambda st: st == "INACTIVE",
                timeout_s=420,
                interval_s=5,
                description=f"service {name} drained to INACTIVE",
            )
        )

    ctx.on_cleanup(_drop)
    return svc


def _service_task_arns(ctx, cluster, service) -> list[str]:
    """Every RUNNING-desired task arn for the service, PAGINATED."""
    ecs = ctx.client("ecs")
    arns: list[str] = []
    token = None
    while True:
        kwargs: dict = {
            "cluster": cluster,
            "serviceName": service,
            "desiredStatus": "RUNNING",
        }
        if token:
            kwargs["nextToken"] = token
        page = ecs.list_tasks(**kwargs)
        arns += page.get("taskArns", [])
        token = page.get("nextToken")
        if not token:
            return arns


def _running_service_tasks(ctx, cluster, service) -> list[dict]:
    """DescribeTasks for the service's RUNNING-desired tasks; raises if one already
    STOPPED so an image-pull/logging failure surfaces instead of a timeout."""
    ecs = ctx.client("ecs")
    arns = _service_task_arns(ctx, cluster, service)
    if not arns:
        return []
    tasks = ecs.describe_tasks(cluster=cluster, tasks=arns).get("tasks", [])
    for t in tasks:
        if t.get("lastStatus") == "STOPPED":
            raise AssertionError(
                f"service task stopped: stopCode={t.get('stopCode')} "
                f"reason={t.get('stoppedReason')} "
                f"containers={[(c.get('name'), c.get('exitCode'), c.get('reason')) for c in t.get('containers', [])]}"
            )
    return [t for t in tasks if t.get("lastStatus") == "RUNNING"]


def _primary_deployment(ctx, cluster, service) -> dict:
    svc = ctx.client("ecs").describe_services(cluster=cluster, services=[service])[
        "services"
    ][0]
    for d in svc.get("deployments", []):
        if d.get("status") == "PRIMARY":
            return d
    return {}


def _cloudmap_service(ctx, ns_id: str, record_type: str, *, ttl: int = 15) -> dict:
    """A Cloud Map service in ns_id with one DNS record of record_type. -> the Service dict.

    HealthCheckCustomConfig lets ECS report the instance's health; teardown deregisters instances
    first because DeleteService is rejected while any remain."""
    sd = ctx.client("servicediscovery")
    name = "cm" + ctx.unique_name("")[:12]
    svc = sd.create_service(
        Name=name,
        NamespaceId=ns_id,
        Description="sim2real-xsvc ecs service discovery",
        DnsConfig={"DnsRecords": [{"Type": record_type, "TTL": ttl}]},
        HealthCheckCustomConfig={"FailureThreshold": 1},
        Tags=_tags_kv(),
    )["Service"]
    ctx.on_cleanup(lambda: _delete_cloudmap_service(ctx, svc["Id"]))
    return svc


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


def _image_pull_role(ctx) -> str:
    """An ECS task execution role that may pull the seeded image and write its logs.

    A private ECR image needs an execution role to pull it on Fargate. The service scheduler
    relaunches a task that fails to start while the fresh role propagates.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
