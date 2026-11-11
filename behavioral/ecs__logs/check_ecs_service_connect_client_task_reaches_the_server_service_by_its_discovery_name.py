"""ecs-service-connect-client-task-reaches-the-server-service-by-its-discovery-name."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "ecs-service-connect-client-task-reaches-the-server-service-by-its-discovery-name"
)

GROUP = "service-connect"

SERVICES = ["ecs", "logs"]

_DISCOVERY_NAME = "scsrv"
_PORT_NAME = "scsrv-8080"
_PORT = 8080


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Service Connect client task reaches the server service by its discoveryName and gets a
    200 whose body carries the server's per-run marker, and the server logged its own start line,
    so the response travelled the ECS-injected mesh from our server rather than anything else.
    """
    vpc_id, subnets = _default_vpc(ctx, min_subnets=2)
    subnets = subnets[:2]
    sg_id = _intra_vpc_sg(ctx, vpc_id)
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
            }
        ],
    )
    namespace = _private_dns_namespace(ctx, vpc_id)
    cluster = _create_cluster(ctx)

    marker = "sim2real-sc-" + ctx.unique_name("")[:10]
    server_td = _register_task_def(
        ctx,
        [
            {
                "name": "server",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "portMappings": [
                    {
                        "containerPort": _PORT,
                        "protocol": "tcp",
                        "name": _PORT_NAME,
                        "appProtocol": "http",
                    }
                ],
                "command": _httpd_command(marker),
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=exec_role,
    )
    client_td = _register_task_def(
        ctx,
        [
            {
                "name": "client",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "command": _client_probe_command(marker),
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=exec_role,
    )

    server_svc = _create_fargate_service(
        ctx,
        cluster,
        server_td["taskDefinitionArn"],
        subnets,
        desired_count=1,
        sg_ids=[sg_id],
        service_connect={
            "enabled": True,
            "namespace": namespace["Arn"],
            "services": [
                {
                    "portName": _PORT_NAME,
                    "discoveryName": _DISCOVERY_NAME,
                    "clientAliases": [{"port": _PORT, "dnsName": _DISCOVERY_NAME}],
                }
            ],
        },
    )
    server = server_svc["serviceName"]
    _poll_until(
        lambda: _running_service_tasks(ctx, cluster, server),
        lambda ts: len(ts) == 1,
        timeout_s=600,
        interval_s=10,
        description=f"server service {server} has 1 RUNNING task",
    )
    server_deployment = _poll_until(
        lambda: _primary_deployment(ctx, cluster, server),
        lambda d: d.get("rolloutState") == "COMPLETED",
        timeout_s=600,
        interval_s=10,
        description=f"server service {server} primary deployment COMPLETED",
    )

    # The server must be at steady state BEFORE the client exists, or a client failure would be a
    # statement about start-up ordering rather than about the mesh.
    assert server_deployment.get("rolloutState") == "COMPLETED", (
        f"the server service never reached steady state, so the client result is meaningless: "
        f"{server_deployment!r}"
    )

    client_svc = _create_fargate_service(
        ctx,
        cluster,
        client_td["taskDefinitionArn"],
        subnets,
        desired_count=1,
        sg_ids=[sg_id],
        # Client-only: enabled, same namespace, NO services block — it publishes nothing and
        # consumes the server's clientAlias.
        service_connect={"enabled": True, "namespace": namespace["Arn"]},
    )
    client = client_svc["serviceName"]
    client_tasks = _poll_until(
        lambda: _running_service_tasks(ctx, cluster, client),
        lambda ts: len(ts) == 1,
        timeout_s=600,
        interval_s=10,
        description=f"client service {client} has 1 RUNNING task",
    )
    client_stream = f"ecs/client/{client_tasks[0]['taskArn'].rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, log_group, client_stream, timeout_s=420)
    msgs = _poll_until(
        lambda: _log_messages(ctx, log_group, client_stream),
        lambda ms: any(
            f"{marker}-STATUS=" in m or f"{marker}-UNREACHABLE" in m for m in ms
        ),
        timeout_s=600,
        interval_s=10,
        description=f"the client's verdict line in {client_stream}",
    )
    combined = "\n".join(msgs)
    status = _parse_status(msgs, marker)
    body = _parse_body(msgs, marker)

    assert status == 200, (
        f"the client could not reach the server through Service Connect at "
        f"http://{_DISCOVERY_NAME}:{_PORT}/: status={status!r} body={body!r} log={combined!r}"
    )
    assert marker in body, (
        f"the client got a 200 but not from our server — the response body carries no run marker: "
        f"body={body!r}"
    )
    assert f"{marker}-UNREACHABLE" not in combined, (
        f"the client reported the name unresolvable or the connection refused: {combined!r}"
    )
    # The same run also proves the server itself served rather than the proxy answering: the
    # server's own start line is in its own stream.
    server_tasks = _running_service_tasks(ctx, cluster, server)
    assert len(server_tasks) == 1, server_tasks
    server_stream = f"ecs/server/{server_tasks[0]['taskArn'].rsplit('/', 1)[-1]}"
    server_msgs = _poll_until(
        lambda: _log_messages(ctx, log_group, server_stream),
        lambda ms: any(f"{marker} httpd-start" in m for m in ms),
        timeout_s=420,
        interval_s=5,
        description=f"the server's httpd start line in {server_stream}",
    )
    assert any(f"{marker} httpd-start" in m for m in server_msgs), server_msgs


def _httpd_command(marker: str) -> list[str]:
    """busybox httpd serving GET / -> "<marker> <hostname>" on the mesh port, in the foreground."""
    return [
        "sh",
        "-c",
        (
            "mkdir -p /www && "
            f'echo "{marker} $(hostname)" > /www/index.html && '
            f'echo "{marker} httpd-start $(hostname)" && '
            f"exec httpd -f -v -p {_PORT} -h /www"
        ),
    ]


def _client_probe_command(marker: str) -> list[str]:
    """Probe http://<discoveryName>:<port>/ until it answers, print status and body, then linger.

    Lingering keeps one stream: an exited task is restarted by the service. Exhausted retries
    print UNREACHABLE, so a mesh that never came up fails with the transport error attached."""
    url = f"http://{_DISCOVERY_NAME}:{_PORT}/"
    script = (
        "i=0; hdr=''; "
        "while [ $i -lt 40 ]; do "
        f"  hdr=$(wget -S -O /tmp/body {url} 2>&1); rc=$?; "
        "  if [ $rc -eq 0 ]; then "
        r'    st=$(echo "$hdr" | sed -n "s#^ *HTTP/1\.[01] \([0-9][0-9][0-9]\).*#\1#p" | head -1); '
        f'    echo "{marker}-STATUS=$st"; '
        f'    echo "{marker}-BODY=$(cat /tmp/body)"; '
        "    break; "
        "  fi; "
        "  i=$((i+1)); sleep 5; "
        "done; "
        f'[ $i -ge 40 ] && echo "{marker}-UNREACHABLE=$hdr"; '
        "while true; do sleep 30; done"
    )
    return ["sh", "-c", script]


def _parse_status(msgs: list[str], marker: str) -> int | None:
    """The status code the client parsed out of the response headers, as an int.

    Structural, not a substring match on '200': a body containing '200' must not be able to
    satisfy an assertion about the status line."""
    pat = re.compile(re.escape(f"{marker}-STATUS=") + r"(\d+)")
    for m in msgs:
        hit = pat.search(m)
        if hit:
            return int(hit.group(1))
    return None


def _parse_body(msgs: list[str], marker: str) -> str:
    prefix = f"{marker}-BODY="
    for m in msgs:
        idx = m.find(prefix)
        if idx >= 0:
            return m[idx + len(prefix) :]
    return ""


# ===== helpers =====
# ECR Public busybox: a tiny multi-arch image an anonymous Fargate pull can always fetch, so a
# check about the container runtime is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


#: Error codes saying the resource does not exist: already deleted, or not created yet.
_GONE = ("ClusterNotFoundException", "ResourceNotFoundException", "NoSuchEntity",
         "ServiceNotActiveException")
#: Error codes of a delete refused while a dependency (a stopping task, a detaching ENI, a
#: registered Cloud Map instance) is released.
_IN_USE = ("ClusterContainsTasksException", "ClusterContainsServicesException",
           "ResourceInUseException", "DependencyViolation", "ResourceInUse")
_RELEASE_S = 120.0


def _unless_gone(fn, retry_s: float = 0.0):
    """fn(), or None when the target answers that the resource does not exist; within retry_s an
    in-use refusal is retried every 2 s; every other error raises."""
    deadline = time.monotonic() + retry_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith("NotFound") or code in _GONE:
                return None
            if code not in _IN_USE or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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

    Its subnets route to an internet gateway, so a Fargate task with assignPublicIp=ENABLED
    pulls its image without a NAT gateway or EIP."""
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


def _iam_role(ctx, kind, trust_service, statements):
    """A role trusting trust_service with ONE inline policy, polled back; returns (name, arn).

    No extra settle: the namespace, cluster and task definitions created before the first task
    assumes this role give propagation more slack than a fixed sleep would."""
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
        _unless_gone(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _unless_gone(lambda: iam.delete_role(RoleName=name))

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
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:  # InvalidInput: the account already holds the role
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_cluster(ctx, settings=None) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-cluster-")
    kwargs: dict = {"clusterName": name, "tags": _ecs_tags_kv()}
    if settings:
        kwargs["settings"] = settings
    ecs.create_cluster(**kwargs)

    # A DRAINING service or a stopping task blocks the delete for a while: retried while in use.
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.delete_cluster(cluster=name), _RELEASE_S))
    return name


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(_XSVC_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _unless_gone(lambda: logs.delete_log_group(logGroupName=name)))
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
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.stop_task(cluster=cluster, task=arn)))
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
        kwargs: dict = {
            "logGroupName": group,
            "logStreamName": stream,
            "startFromHead": True,
        }
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
            for s in logs.describe_log_streams(
                logGroupName=group, logStreamNamePrefix=stream
            ).get("logStreams", [])
        ],
        lambda names: stream in names,
        timeout_s=timeout_s,
        interval_s=5,
        description=f"awslogs stream {stream} in {group}",
    )


def _intra_vpc_sg(ctx, vpc_id: str) -> str:
    """A security group that allows ALL traffic from ITSELF, TAGGED AT CREATION.

    Self-referencing because the injected proxy listens on ports ECS chooses. Created first so
    its LIFO teardown runs last; a lingering task ENI makes the delete retry to a deadline."""
    ec2 = ctx.client("ec2")
    gid = ec2.create_security_group(
        GroupName=ctx.unique_name(_XSVC_PREFIX + "sg-"),
        Description="sim2real xsvc intra-VPC mesh traffic",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]

    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_security_group(GroupId=gid), _RELEASE_S))
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": gid}]}],
    )
    return gid


def _await_operation(ctx, operation_id: str, *, timeout_s=600.0) -> dict:
    """Poll a Cloud Map operation to a TERMINAL status and return it.

    A just-created namespace can exist yet still be unusable by CreateService
    (NamespaceNotFoundException) until its operation succeeds."""
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
    """Deregister every instance, then delete the service.

    DeleteService is ResourceInUse while any instance is registered, and deregistration is
    asynchronous, so the delete is retried while in use."""
    sd = ctx.client("servicediscovery")
    insts = _unless_gone(
        lambda: sd.list_instances(ServiceId=service_id).get("Instances", [])
    )
    for inst in insts or []:
        _unless_gone(
            lambda i=inst: sd.deregister_instance(
                ServiceId=service_id, InstanceId=i["Id"]
            )
        )
    _unless_gone(lambda: sd.delete_service(Id=service_id), 60.0)


def _private_dns_namespace(ctx, vpc_id: str) -> dict:
    """A PRIVATE DNS namespace, polled through get_operation to SUCCESS. -> {Id, Arn, Name}.

    Teardown drains it first: Service Connect creates Cloud Map services inside the namespace,
    and DeleteNamespace is rejected while any remain."""
    sd = ctx.client("servicediscovery")
    name = ctx.unique_name(_XSVC_PREFIX + "ns-") + ".sim2real"
    op_id = sd.create_private_dns_namespace(
        Name=name,
        Vpc=vpc_id,
        Description="sim2real-xsvc ecs service discovery",
        Tags=_tags_kv(),
    )["OperationId"]

    def _drop():
        if _unless_gone(lambda: sd.get_namespace(Id=ns_id)) is None:
            return
        for sid in _namespace_service_ids(ctx, ns_id):
            _delete_cloudmap_service(ctx, sid)
        del_op = _unless_gone(lambda: sd.delete_namespace(Id=ns_id), 60.0)
        if del_op is not None:
            _await_operation(ctx, del_op["OperationId"], timeout_s=180)

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
        _unless_gone(
            lambda: ecs.update_service(cluster=cluster, service=name, desiredCount=0)
        )
        _unless_gone(lambda: ecs.delete_service(cluster=cluster, service=name, force=True))
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
