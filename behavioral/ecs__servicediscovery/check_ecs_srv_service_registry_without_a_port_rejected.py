"""ecs-srv-service-registry-without-a-port-rejected."""

from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-srv-service-registry-without-a-port-rejected"

GROUP = "overly-permissive"

SERVICES = ["ecs", "servicediscovery"]

_SRV_NO_PORT_MESSAGE = (
    "When specifying a value for serviceRegistries that is configured to use a type 'SRV' DNS "
    "record, you must also enter a value for either 'port' or the 'containerName' and "
    "'containerPort' combination, but not both. Registry: {registry_arn}"
)


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """ECS rejects an SRV service registry with no port (InvalidParameterException, exact message),
    leaves no service or Cloud Map instance behind, and accepts the same call once the port is set.
    """
    ecs = ctx.client("ecs")
    vpc_id, subnets = _default_vpc(ctx, min_subnets=2)
    subnets = subnets[:2]
    namespace = _private_dns_namespace(ctx, vpc_id)
    cm = _cloudmap_service(ctx, namespace["Id"], "SRV")
    cluster = _create_cluster(ctx)

    td = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "command": ["sh", "-c", "sleep 3600"],
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
            }
        ],
    )
    netcfg = {"awsvpcConfiguration": {"subnets": subnets, "assignPublicIp": "ENABLED"}}

    # --- Break exactly one thing: the SRV registry is given no port and no containerName/Port.
    # The teardown is registered BEFORE the call that should fail: if ECS wrongly ACCEPTS it the
    # service exists, and the assertion two lines later would otherwise abort while it still runs.
    rejected_name = ctx.unique_name(_XSVC_PREFIX + "ecs-svc-rej-")

    ctx.on_cleanup(lambda: _drain_service(ecs, cluster, rejected_name))
    code, message = _error(
        lambda: ecs.create_service(
            cluster=cluster,
            serviceName=rejected_name,
            taskDefinition=td["taskDefinitionArn"],
            desiredCount=1,
            launchType="FARGATE",
            networkConfiguration=netcfg,
            serviceRegistries=[{"registryArn": cm["Arn"]}],
            tags=_ecs_tags_kv(),
        )
    )
    expected = _SRV_NO_PORT_MESSAGE.format(registry_arn=cm["Arn"])
    assert (code, message) == ("InvalidParameterException", expected), (
        f"expected InvalidParameterException for an SRV service registry with no port, "
        f"got {code!r} {message!r}"
    )

    # --- The effect is absent: no ECS service, and nothing registered in Cloud Map.
    assert _cluster_service_arns(ctx, cluster) == [], (
        f"the rejected CreateService left a service behind in {cluster}: "
        f"{_cluster_service_arns(ctx, cluster)!r}"
    )
    assert _discovered(ctx, namespace["Name"], cm["Name"]) == [], (
        f"the rejected CreateService registered an instance in Cloud Map anyway: "
        f"{_discovered(ctx, namespace['Name'], cm['Name'])!r}"
    )

    # --- The positive control: the SAME registry, the SAME call, one field added.
    svc = _create_fargate_service(
        ctx,
        cluster,
        td["taskDefinitionArn"],
        subnets,
        desired_count=1,
        service_registries=[
            {"registryArn": cm["Arn"], "containerName": "app", "containerPort": 80}
        ],
    )
    service = svc["serviceName"]
    tasks = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, service),
        lambda ts: len(ts) == 1,
        timeout_s=600,
        interval_s=10,
        description=f"control service {service} has 1 RUNNING task",
    )
    task_ip = _task_private_ip(tasks[0])
    assert task_ip, (
        f"the control task has no privateIPv4Address: {tasks[0].get('attachments')!r}"
    )

    instances = _poll_until(
        lambda: _discovered(ctx, namespace["Name"], cm["Name"]),
        lambda ins: len(ins) == 1,
        timeout_s=420,
        interval_s=5,
        description=f"the control task discoverable in {namespace['Name']}/{cm['Name']}",
    )
    attrs = instances[0].get("Attributes", {})
    assert attrs.get("AWS_INSTANCE_IPV4") == task_ip, (
        f"the control registered {attrs.get('AWS_INSTANCE_IPV4')!r} but the task's ENI address is "
        f"{task_ip!r}, so the control did not actually register THIS task: {attrs!r}"
    )
    assert attrs.get("AWS_INSTANCE_PORT") == "80", (
        f"the SRV registration carries no port, which is the very field whose absence was rejected: "
        f"{attrs!r}"
    )


def _cluster_service_arns(ctx, cluster) -> list[str]:
    """Every service in the cluster, PAGINATED — the emptiness assertion is only sound if another
    suite's leftovers cannot push ours onto a second page."""
    ecs = ctx.client("ecs")
    arns: list[str] = []
    token = None
    while True:
        kwargs: dict = {"cluster": cluster}
        if token:
            kwargs["nextToken"] = token
        page = ecs.list_services(**kwargs)
        arns += page.get("serviceArns", [])
        token = page.get("nextToken")
        if not token:
            return arns


def _discovered(ctx, namespace_name: str, service_name: str) -> list[dict]:
    """DiscoverInstances — the Cloud Map DISCOVERY data plane, a distinct endpoint from the
    servicediscovery control plane."""
    return ctx.client("servicediscovery").discover_instances(
        NamespaceName=namespace_name, ServiceName=service_name
    )["Instances"]


# ===== shared helpers =====
# ECR Public busybox: a tiny multi-arch image an anonymous Fargate pull can always fetch, so a
# check about the container runtime is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _tolerate(fn, ok=(), retry=(), timeout_s=0.0):
    """Return fn()'s result, or None on an error code in ok; retry a code in retry every 2 s
    until timeout_s, then raise it. Any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ok:
                return None
            if code not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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

    The container archetype deliberately reuses the shared network and NEVER builds a
    NAT gateway or EIP: network subnets already have an internet-gateway route, so a
    Fargate task with assignPublicIp=ENABLED can pull its image with zero billable
    networking left behind if teardown is interrupted."""
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
    _tolerate(
        lambda: ctx.client("iam").create_service_linked_role(
            AWSServiceName="ecs.amazonaws.com"
        ),
        ok=("InvalidInput",),
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
        _tolerate(
            lambda: ecs.delete_cluster(cluster=name),
            ok=("ClusterNotFoundException",),
            retry=(
                "ClusterContainsServicesException",
                "ClusterContainsTasksException",
                "UpdateInProgressException",
            ),
            timeout_s=120,
        )

    ctx.on_cleanup(_drop)
    return name


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(_XSVC_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(
        lambda: _tolerate(
            lambda: logs.delete_log_group(logGroupName=name),
            ok=("ResourceNotFoundException",),
        )
    )
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
    ctx.on_cleanup(
        lambda: _tolerate(
            lambda: ecs.stop_task(cluster=cluster, task=arn),
            ok=("ClusterNotFoundException",),
        )
    )
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
    """Poll a Cloud Map operation to a TERMINAL status and return it.

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

    def _deregister_then_delete():
        for inst in sd.list_instances(ServiceId=service_id).get("Instances", []):
            _tolerate(
                lambda i=inst: sd.deregister_instance(
                    ServiceId=service_id, InstanceId=i["Id"]
                ),
                ok=("InstanceNotFound", "ServiceNotFound", "DuplicateRequest"),
            )
        sd.delete_service(Id=service_id)

    _tolerate(
        _deregister_then_delete,
        ok=("ServiceNotFound",),
        retry=("ResourceInUse",),
        timeout_s=90,
    )


def _private_dns_namespace(ctx, vpc_id: str) -> dict:
    """A PRIVATE DNS namespace, polled through get_operation to SUCCESS. -> {Id, Arn, Name}.

    Teardown drains its Cloud Map services first: DeleteNamespace is rejected while any remain."""
    sd = ctx.client("servicediscovery")
    name = ctx.unique_name(_XSVC_PREFIX + "ns-") + ".sim2real"
    op_id = sd.create_private_dns_namespace(
        Name=name,
        Vpc=vpc_id,
        Description="sim2real-xsvc ecs service discovery",
        Tags=_tags_kv(),
    )["OperationId"]

    def _drain_then_delete():
        for sid in _namespace_service_ids(ctx, ns_id):
            _delete_cloudmap_service(ctx, sid)
        return sd.delete_namespace(Id=ns_id)

    def _drop():
        del_op = _tolerate(
            _drain_then_delete,
            ok=("NamespaceNotFound",),
            retry=("ResourceInUse",),
            timeout_s=60,
        )
        if del_op is not None:
            _await_operation(ctx, del_op["OperationId"], timeout_s=240)

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
        _drain_service(ecs, cluster, name)
        _poll_until(
            lambda: (
                ecs.describe_services(cluster=cluster, services=[name]).get(
                    "services"
                )
                or [{}]
            )[0].get("status", "INACTIVE"),
            lambda st: st == "INACTIVE",
            timeout_s=300,
            interval_s=2,
            description=f"service {name} drained to INACTIVE",
        )

    ctx.on_cleanup(_drop)
    return svc


def _drain_service(ecs, cluster, name) -> None:
    """Scale the service to zero and force-delete it; an already-deleted service is fine."""
    gone = ("ServiceNotFoundException", "ServiceNotActiveException", "ClusterNotFoundException")
    _tolerate(lambda: ecs.update_service(cluster=cluster, service=name, desiredCount=0), ok=gone)
    _tolerate(lambda: ecs.delete_service(cluster=cluster, service=name, force=True), ok=gone)


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
    """A Cloud Map service in ns_id with ONE DNS record of record_type. -> the Service dict.

    HealthCheckCustomConfig is what lets ECS report the registered instance's health, so without it
    a DiscoverInstances health assertion would grade Cloud Map's default rather than ECS's report.
    Teardown deregisters every instance first: DeleteService is rejected while any remain, and the
    ECS-registered one is removed asynchronously after the ECS service drains."""
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


def _error(fn) -> tuple[str, str]:
    """(code, message) of the AWS error raised by fn(). Raises if fn SUCCEEDS.

    A falsy sentinel on success would turn the strongest possible signal — a target accepting
    input real AWS rejects — into an error-code mismatch that reads like a naming difference, so
    the unexpected success is raised instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(
        f"the call was expected to be REJECTED but it succeeded: {result!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
