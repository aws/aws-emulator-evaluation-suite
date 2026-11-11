"""ecs-readonly-mount-point-write-rejected-while-the-writer-sibling-still-writes."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-readonly-mount-point-write-rejected-while-the-writer-sibling-still-writes"

GROUP = "task-storage"

SERVICES = ["ecs", "logs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """One volume mounted into two containers of a task: the path is writable where the mount is
    read-write and refused with EROFS where `readOnly: true`, while the reader still reads the
    writer's payload, so the mount is present when its write is refused."""
    _vpc_id, subnets = _public_vpc(ctx, min_subnets=1)
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
    cluster = _create_cluster(ctx)

    marker = "sim2real-romount-" + ctx.unique_name("")[:10]
    td = _register_task_def(
        ctx,
        [
            {
                "name": "writer",
                "image": _PUBLIC_IMAGE,
                "essential": False,
                "mountPoints": [
                    {"sourceVolume": "shared", "containerPath": "/shared", "readOnly": False}
                ],
                "command": [
                    "sh",
                    "-c",
                    (
                        f"echo {marker}-seed > /shared/seed "
                        f"&& echo {marker}-WRITER-WRITE-OK"
                    ),
                ],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            },
            {
                "name": "readeronly",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "mountPoints": [
                    {"sourceVolume": "shared", "containerPath": "/shared", "readOnly": True}
                ],
                "dependsOn": [{"containerName": "writer", "condition": "SUCCESS"}],
                "command": [
                    "sh",
                    "-c",
                    (
                        f"if echo x > /shared/probe; then echo {marker}-RO-WRITE-OK; "
                        f"else echo {marker}-RO-WRITE-FAILED; fi; "
                        f"cat /shared/seed && echo {marker}-RO-READ-OK"
                    ),
                ],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            },
        ],
        execution_role_arn=exec_role,
        volumes=[{"name": "shared"}],
    )

    task_arn, task_id, task = _run_task_until_role_ready(
        ctx, cluster, td["taskDefinitionArn"], subnets
    )
    by_name = {c["name"]: c for c in task.get("containers", [])}
    writer, reader = by_name.get("writer", {}), by_name.get("readeronly", {})
    assert writer.get("exitCode") == 0, (
        f"the read-write sibling failed, so the read-only refusal proves nothing: {writer!r} "
        f"stoppedReason={task.get('stoppedReason')!r}"
    )
    assert reader.get("exitCode") == 0, (
        f"the read-only container did not run to completion: {reader!r} "
        f"stoppedReason={task.get('stoppedReason')!r}"
    )

    writer_stream = f"ecs/writer/{task_id}"
    reader_stream = f"ecs/readeronly/{task_id}"
    _await_log_stream(ctx, log_group, writer_stream, timeout_s=420)
    _await_log_stream(ctx, log_group, reader_stream, timeout_s=420)

    writer_msgs = _poll_until(
        lambda: _log_messages(ctx, log_group, writer_stream),
        lambda ms: any(f"{marker}-WRITER-WRITE-OK" in m for m in ms),
        timeout_s=420,
        interval_s=5,
        description=f"writer's success line in {writer_stream}",
    )
    reader_msgs = _poll_until(
        lambda: _log_messages(ctx, log_group, reader_stream),
        lambda ms: any(f"{marker}-RO-READ-OK" in m for m in ms),
        timeout_s=420,
        interval_s=5,
        description=f"read-only container's final line in {reader_stream}",
    )
    reader_combined = "\n".join(reader_msgs)

    # (c) the positive control: the same volume, same path, readOnly=False, accepted the write.
    assert any(f"{marker}-WRITER-WRITE-OK" in m for m in writer_msgs), (
        f"the read-write sibling never confirmed its write: {writer_msgs!r}"
    )
    # (a) the specific rejection in the read-only container.
    assert f"{marker}-RO-WRITE-FAILED" in reader_combined, (
        f"a write succeeded through a mountPoint declared readOnly=True: {reader_combined!r}"
    )
    assert "read-only file system" in reader_combined.lower(), (
        f"the write was refused for some reason other than a read-only mount — no EROFS text in "
        f"the stream: {reader_combined!r}"
    )
    # (b) the effect is absent.
    assert f"{marker}-RO-WRITE-OK" not in reader_combined, (
        f"both branches reported, so the shell test is not deciding anything: {reader_combined!r}"
    )
    # ...and the mount was demonstrably THERE at the moment the write was refused.
    assert f"{marker}-seed" in reader_combined, (
        f"the read-only container could not read the writer's payload either, so /shared was not "
        f"mounted at all and the refusal says nothing about readOnly: {reader_combined!r}"
    )


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
_GONE = ("ClusterNotFoundException", "ResourceNotFoundException", "NoSuchEntity")
#: Error codes of a delete refused while a dependency (a stopping task) is released.
_IN_USE = ("ClusterContainsTasksException", "ClusterContainsServicesException",
           "ResourceInUseException")
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _public_vpc(ctx, min_subnets=1):
    """(vpc_id, subnet_ids) of a VPC this check creates: one public subnet per AZ, an internet
    gateway and a default route, so a Fargate task with assignPublicIp=ENABLED can pull its image.

    No NAT gateway or EIP is created, so nothing billable is left behind if teardown is
    interrupted. Teardown waits for the task ENIs to detach before deleting the network."""
    ec2 = ctx.client("ec2")

    def _tag_spec(resource_type):
        tags = [{"Key": "Name", "Value": ctx.unique_name(_XSVC_PREFIX + "net-")}] + _tags_kv()
        return [{"ResourceType": resource_type, "Tags": tags}]

    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    if len(zones) < min_subnets:
        raise AssertionError(f"region {ctx.region} offers {zones!r}; need {min_subnets} zones")
    vpc_id = ec2.create_vpc(CidrBlock="10.87.0.0/16", TagSpecifications=_tag_spec("vpc"))["Vpc"]["VpcId"]
    made: dict = {"subnets": [], "igw": None, "rt": None}

    def _teardown():
        _leaks: list = []
        deadline = time.monotonic() + 600
        while made["subnets"] and time.monotonic() < deadline:
            if not ec2.describe_network_interfaces(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("NetworkInterfaces"):
                break
            time.sleep(10)
        steps = [lambda s=s: ec2.delete_subnet(SubnetId=s) for s in made["subnets"]]
        if made["rt"]:
            steps.append(lambda: ec2.delete_route_table(RouteTableId=made["rt"]))
        if made["igw"]:
            steps.append(lambda: ec2.detach_internet_gateway(InternetGatewayId=made["igw"], VpcId=vpc_id))
            steps.append(lambda: ec2.delete_internet_gateway(InternetGatewayId=made["igw"]))
        steps.append(lambda: ec2.delete_vpc(VpcId=vpc_id))
        for step in steps:
            while True:
                try:
                    step()
                    break
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code.endswith("NotFound") or code == "Gateway.NotAttached":
                        break
                    if code != "DependencyViolation" or time.monotonic() >= deadline:
                        _leaks.append((f"VPC {vpc_id} teardown step failed: {code}", exc))
                        break
                    time.sleep(10)
        if _leaks:
            raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                (e for _, e in _leaks if e is not None), None
            )

    ctx.on_cleanup(_teardown)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw = ec2.create_internet_gateway(TagSpecifications=_tag_spec("internet-gateway"))[
        "InternetGateway"]["InternetGatewayId"]
    made["igw"] = igw
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    rt = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=_tag_spec("route-table"))[
        "RouteTable"]["RouteTableId"]
    made["rt"] = rt
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    for i, az in enumerate(zones[:max(min_subnets, 1)]):
        sn = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.87.{i}.0/24", AvailabilityZone=az,
                               TagSpecifications=_tag_spec("subnet"))["Subnet"]["SubnetId"]
        made["subnets"].append(sn)
        ec2.modify_subnet_attribute(SubnetId=sn, MapPublicIpOnLaunch={"Value": True})
        ec2.associate_route_table(RouteTableId=rt, SubnetId=sn)
    return vpc_id, list(made["subnets"])


def _iam_role(ctx, kind, trust_service, statements):
    """Create a role trusting trust_service with ONE inline policy; returns (name, arn).

    IAM is eventually consistent, so the role + its inline policy are POLLED back
    before any service is asked to assume it; the short real-AWS settle after that
    covers trust-policy propagation to the assuming service (it is a wait, never the
    assertion)."""
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
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
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


def _run_task_until_role_ready(ctx, cluster, td_arn, subnets, *, attempts=6, delay_s=10.0):
    """RunTask right after granting a fresh exec role can fail SYNCHRONOUSLY with
    ClientException("... unable to assume the role ...") while the role's trust
    policy is still propagating to ECS -- confirmed on real AWS, which is why this
    retries the actual RunTask call rather than a blind pre-sleep, and only on that
    exact signature."""
    last_exc = None
    for attempt in range(attempts):
        try:
            task_arn = _run_task(ctx, cluster, td_arn, subnets)
        except ClientError as exc:
            last_exc = exc
            if "unable to assume the role" not in str(exc) or attempt == attempts - 1:
                raise
            time.sleep(delay_s)
            continue
        task_id = task_arn.rsplit("/", 1)[-1]
        task = _await_task(ctx, cluster, task_arn, {"STOPPED"}, timeout_s=900)
        return task_arn, task_id, task
    raise last_exc


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
        kwargs: dict = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
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
            for s in logs.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream).get(
                "logStreams", []
            )
        ],
        lambda names: stream in names,
        timeout_s=timeout_s,
        interval_s=5,
        description=f"awslogs stream {stream} in {group}",
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
