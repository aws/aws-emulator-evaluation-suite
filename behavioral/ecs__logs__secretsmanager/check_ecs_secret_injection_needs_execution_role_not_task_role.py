"""ecs-secret-injection-needs-execution-role-not-task-role."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-secret-injection-needs-execution-role-not-task-role"

GROUP = "container-secret-injection"

SERVICES = ["ecs", "logs", "secretsmanager"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A secret in valueFrom is fetched with the execution role before the container exists: the
    grant on the task role fails the task at start with ResourceInitializationError and no
    stream, and the same statement on the execution role lets the task print the value."""
    _vpc_id, subnets = _public_vpc(ctx, min_subnets=1)
    log_group = _create_log_group(ctx)
    assert _stream_names(ctx, log_group) == [], "fresh log group already has streams"
    cluster = _create_cluster(ctx)

    secret_value = "sim2real-secret-value-" + ctx.unique_name("")
    secret_name = ctx.unique_name(_XSVC_PREFIX + "secret-")
    sm = ctx.client("secretsmanager")
    secret_arn = sm.create_secret(Name=secret_name, SecretString=secret_value, Tags=_tags_kv())[
        "ARN"
    ]
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
        )
    )

    logs_stmt = {
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "*",
    }
    secret_stmt = {
        "Effect": "Allow",
        "Action": "secretsmanager:GetSecretValue",
        "Resource": secret_arn,
    }
    container = {
        "name": "app",
        "image": _PUBLIC_IMAGE,
        "essential": True,
        "command": ["sh", "-c", 'echo "injected=$SIM2REAL_SECRET"'],
        "secrets": [{"name": "SIM2REAL_SECRET", "valueFrom": secret_arn}],
        "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
    }

    # --- Break exactly one thing: the secret grant sits on the task role.
    _bad_exec_name, bad_exec = _iam_role(
        ctx, "ecs-exec-nosecret", "ecs-tasks.amazonaws.com", [logs_stmt]
    )
    _task_name, task_role = _iam_role(
        ctx, "ecs-task-secret", "ecs-tasks.amazonaws.com", [secret_stmt]
    )
    bad_td = _register_task_def(
        ctx, [container], execution_role_arn=bad_exec, task_role_arn=task_role
    )
    bad_arn = _run_task_until_role_ready(ctx, cluster, bad_td["taskDefinitionArn"], subnets)
    bad_task = _await_task(ctx, cluster, bad_arn, {"STOPPED"}, timeout_s=600)

    assert bad_task.get("stopCode") == "TaskFailedToStart", (
        "a task whose EXECUTION role cannot read the secret was not failed at start: "
        f"stopCode={bad_task.get('stopCode')} reason={bad_task.get('stoppedReason')}"
    )
    reason = bad_task.get("stoppedReason", "")
    assert (
        "ResourceInitializationError" in reason
    ), f"expected ResourceInitializationError from secret retrieval, got: {reason!r}"
    assert (
        "AccessDenied" in reason or "not authorized" in reason
    ), f"expected an authorization failure in the stopped reason, got: {reason!r}"
    # `is None`, not falsiness: a container that actually ran and exited 0 reports exitCode 0, and
    # `not 0` is True -- so the falsy form passed for exactly the over-permissive backend this leg
    # exists to reject. A task whose EXECUTION role cannot read the secret must never start, which
    # means no exitCode is reported at all.
    assert bad_task["containers"][0].get("exitCode") is None, bad_task["containers"][0]

    # Effect absent: no container ran, so nothing was written to the log group.
    names = _stream_names(ctx, log_group)
    assert names == [], f"log streams exist for a task that never started: {names}"

    # --- Control: same statement, moved to the execution role.
    _ok_exec_name, ok_exec = _iam_role(
        ctx, "ecs-exec-secret", "ecs-tasks.amazonaws.com", [logs_stmt, secret_stmt]
    )
    ok_td = _register_task_def(
        ctx, [container], execution_role_arn=ok_exec, task_role_arn=task_role
    )
    # A fresh execution role's secret grant reaches the ECS agent a few seconds after IAM
    # returns it; a launch inside that window fails exactly like the broken leg, so it is
    # relaunched to a deadline.
    deadline = _deadline(ctx, 120.0)
    while True:
        ok_arn = _run_task_until_role_ready(ctx, cluster, ok_td["taskDefinitionArn"], subnets)
        ok_task = _await_task(ctx, cluster, ok_arn, {"STOPPED"}, timeout_s=720)
        if ok_task.get("stopCode") != "TaskFailedToStart" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert ok_task["containers"][0].get("exitCode") == 0, (
        f"control task failed: stopCode={ok_task.get('stopCode')} "
        f"reason={ok_task.get('stoppedReason')}"
    )
    ok_stream = f"ecs/app/{ok_arn.rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, log_group, ok_stream, timeout_s=300)
    _await_log_marker(ctx, log_group, ok_stream, f"injected={secret_value}", timeout_s=300)


# ===== helpers =====
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


def _register_task_def(ctx, container_defs, *, execution_role_arn=None, task_role_arn=None):
    ecs = ctx.client("ecs")
    kwargs: dict = dict(
        family=ctx.unique_name(_XSVC_PREFIX + "td-"),
        containerDefinitions=container_defs,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=_ecs_tags_kv(),
    )
    if execution_role_arn:
        kwargs["executionRoleArn"] = execution_role_arn
    if task_role_arn:
        kwargs["taskRoleArn"] = task_role_arn
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return td


def _deadline(ctx, timeout_s: float) -> float:
    """A monotonic deadline timeout_s away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _run_task_until_role_ready(ctx, cluster, td_arn, subnets, *, timeout_s=60.0) -> str:
    """RunTask right after creating a fresh exec role can fail SYNCHRONOUSLY with
    ClientException("... unable to assume the role ...") while the role's trust policy is
    still propagating to ECS; retry the RunTask call itself, only on that signature."""
    deadline = _deadline(ctx, timeout_s)
    while True:
        try:
            return _run_task(ctx, cluster, td_arn, subnets)
        except ClientError as exc:
            if "unable to assume the role" not in str(exc) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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


def _log_messages(ctx, group: str, stream: str) -> list[str]:
    ev = _safe(
        lambda: ctx.client("logs").get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True
        )
    )
    return [e.get("message", "") for e in (ev or {}).get("events", [])]


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


def _await_log_marker(ctx, group: str, stream: str, marker: str, timeout_s=300.0) -> list[str]:
    msgs = _poll_until(
        lambda: _log_messages(ctx, group, stream),
        lambda ms: any(marker in m for m in ms),
        timeout_s=timeout_s,
        interval_s=5,
        description=f"marker {marker!r} in {group}/{stream}",
    )
    assert any(marker in m for m in msgs), msgs
    return msgs


# ECR Public busybox: a tiny image an anonymous Fargate pull can always fetch, so a
# check about logging/networking is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


def _stream_names(ctx, group: str) -> list[str]:
    return [
        s["logStreamName"]
        for s in ctx.client("logs").describe_log_streams(logGroupName=group).get("logStreams", [])
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
