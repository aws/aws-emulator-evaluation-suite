"""awslogs-without-create-log-stream-delivers-nothing."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "awslogs-without-create-log-stream-delivers-nothing"

GROUP = "container-logs-delivery"

SERVICES = ["ecs", "logs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An execution role without logs:CreateLogStream fails the task at start with
    ResourceInitializationError and delivers no stream; a role adding only that action back lets
    the same container run and deliver its line."""
    _vpc_id, subnets = _default_vpc(ctx, min_subnets=1)
    log_group = _create_log_group(ctx)
    assert _stream_names(ctx, log_group) == [], "fresh log group already has streams"
    cluster = _create_cluster(ctx)
    marker = "sim2real-logs-perm-" + ctx.unique_name("")[:8]

    container = {
        "name": "app",
        "image": _PUBLIC_IMAGE,
        "essential": True,
        "command": ["sh", "-c", f"echo {marker}; exit 0"],
        "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
    }

    # --- Break exactly one thing: PutLogEvents without CreateLogStream.
    _bad_name, bad_role = _iam_role(
        ctx,
        "ecs-exec-nostream",
        "ecs-tasks.amazonaws.com",
        [{"Effect": "Allow", "Action": "logs:PutLogEvents", "Resource": "*"}],
    )
    bad_td = _register_task_def(ctx, [container], execution_role_arn=bad_role)
    bad_arn = _run_task(ctx, cluster, bad_td["taskDefinitionArn"], subnets)
    bad_task = _await_task(ctx, cluster, bad_arn, {"STOPPED"}, timeout_s=600)

    assert bad_task.get("stopCode") == "TaskFailedToStart", (
        "task whose execution role cannot create a log stream was not failed at start: "
        f"stopCode={bad_task.get('stopCode')} reason={bad_task.get('stoppedReason')}"
    )
    reason = bad_task.get("stoppedReason", "")
    assert (
        "ResourceInitializationError" in reason
    ), f"expected ResourceInitializationError from the log driver, got: {reason!r}"

    # Effect absent: no stream at all was delivered into the group.
    bad_stream = f"ecs/app/{bad_arn.rsplit('/', 1)[-1]}"
    names = _stream_names(ctx, log_group)
    assert names == [], f"streams exist despite the denied CreateLogStream: {names}"
    assert bad_stream not in names, names

    # --- Control: add CreateLogStream back, change nothing else.
    _ok_name, ok_role = _iam_role(
        ctx,
        "ecs-exec-ok",
        "ecs-tasks.amazonaws.com",
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
    )
    ok_td = _register_task_def(ctx, [container], execution_role_arn=ok_role)
    ok_arn = _run_task(ctx, cluster, ok_td["taskDefinitionArn"], subnets)
    ok_task = _await_task(ctx, cluster, ok_arn, {"STOPPED"}, timeout_s=720)
    assert ok_task["containers"][0].get("exitCode") == 0, (
        f"control task failed: stopCode={ok_task.get('stopCode')} "
        f"reason={ok_task.get('stoppedReason')}"
    )
    ok_stream = f"ecs/app/{ok_arn.rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, log_group, ok_stream, timeout_s=300)
    _await_log_marker(ctx, log_group, ok_stream, marker, timeout_s=300)


# ===== helpers =====
# ECR Public busybox: a tiny image an anonymous Fargate pull can always fetch, so a
# check about logging/networking is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


def _stream_names(ctx, group: str) -> list[str]:
    return [
        s["logStreamName"]
        for s in ctx.client("logs").describe_log_streams(logGroupName=group).get("logStreams", [])
    ]


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


def _default_vpc(ctx, min_subnets=1):
    """(vpc_id, subnet_ids) from the run's shared network, one subnet per AZ.

    The container archetype deliberately reuses the shared network and NEVER builds a
    NAT gateway or EIP: network subnets already have an internet-gateway route, so a
    Fargate task with assignPublicIp=ENABLED can pull its image with zero billable
    networking left behind if teardown is interrupted."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
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


def _run_task(ctx, cluster, td_arn, subnets, sg_ids=None) -> str:
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    awsvpc: dict = {"subnets": subnets, "assignPublicIp": "ENABLED"}
    if sg_ids:
        awsvpc["securityGroups"] = sg_ids

    # The execution role was just created; ECS's own AssumeRole check against it can
    # lag briefly. Retry RunTask itself rather than sleeping a fixed amount.
    def _try():
        try:
            return ecs.run_task(
                cluster=cluster,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration={"awsvpcConfiguration": awsvpc},
            )
        except Exception as exc:  # noqa: BLE001 - IAM propagation lag surfaces as a ClientError
            return exc

    resp = _poll_until(
        _try,
        lambda r: not isinstance(r, Exception),
        timeout_s=90,
        interval_s=10,
        description="the freshly created execution role propagates enough for ECS to assume it",
    )
    if isinstance(resp, Exception):
        raise resp
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
