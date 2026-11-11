"""ecs-service-stabilizes-and-logs-to-cloudwatch."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-service-stabilizes-and-logs-to-cloudwatch"

GROUP = "container-logs-delivery"

SERVICES = ["cloudwatch", "ecr", "ecs"]

PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
_CLUSTER_BUSY = ("ClusterContainsTasksException", "ClusterContainsServicesException",
                 "UpdateInProgressException")

ECS_TASK_EXECUTION_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
)


# Each create_* registers its teardown via ctx.on_cleanup; LIFO order drains the service
# before its cluster is deleted, then the task def, role and log group.
def _default_subnets(ctx) -> list[str]:
    """Public subnet IDs for the awsvpc networkConfiguration Fargate requires; raises if none exist."""
    ec2 = ctx.client("ec2")
    try:
        vpcs = ec2.describe_vpcs(
            Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]
        ).get("Vpcs", [])
        if not vpcs:
            raise AssertionError("no shared network VPC available for Fargate tasks")
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    except AssertionError:
        raise
    except Exception as exc:  # pragma: no cover - environment dependent
        raise AssertionError(f"unable to resolve network subnets: {exc}") from exc
    ids = [s["SubnetId"] for s in subnets]
    if not ids:
        raise AssertionError("shared network has no subnets for Fargate tasks")
    return ids


def _awsvpc_config(ctx) -> dict:
    return {
        "awsvpcConfiguration": {
            "subnets": _default_subnets(ctx),
            "assignPublicIp": "ENABLED",  # required so a public subnet task can pull the image
        }
    }


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Create the ECS service-linked role idempotently: RunTask (unlike CreateService) does not
    auto-create it, and fails with "Unable to assume the service linked role" without it."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception as e:  # noqa: BLE001 - already-exists is success
        msg = str(e).lower()
        if (
            "has been taken" not in msg
            and "already" not in msg
            and "invalidinput" not in msg
        ):
            pass  # non-exists errors: let the subsequent CreateService surface the real problem


def _task_execution_role_arn(ctx) -> str:
    """Create a role trusted by ecs-tasks.amazonaws.com with AmazonECSTaskExecutionRolePolicy and a
    detach-then-delete teardown; IAM propagation lag is tolerated by the task-launch poll."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-role-ecs-tasks-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
        ],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        # A role must have its managed policy detached before it can be deleted.
        _unless_gone(lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn=ECS_TASK_EXECUTION_POLICY), "NoSuchEntity")
        _unless_gone(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ECS_TASK_EXECUTION_POLICY)
    return arn


def _unless_gone(fn, *gone_codes) -> None:
    """Teardown call that returns only on the resource's own not-found codes; anything else raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in gone_codes:
            raise


def _create_log_group(ctx) -> str:
    name = ctx.unique_name("sim2real-xsvc-ecs-lg-")
    logs = ctx.client("logs")
    logs.create_log_group(
        logGroupName=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"},
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name


def _create_cluster(ctx) -> dict:
    name = ctx.unique_name("sim2real-xsvc-ecs-cluster-")
    ecs = ctx.client("ecs")
    resp = ecs.create_cluster(clusterName=name)

    def _cleanup() -> None:
        # A draining service still blocks cluster delete for a while: retry exactly that, then raise.
        deadline = time.monotonic() + 300
        while True:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ClusterNotFoundException":
                    return
                if code not in _CLUSTER_BUSY or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return resp["cluster"]


def _register_fargate_task_def(ctx, container_defs, execution_role_arn=None) -> dict:
    family = ctx.unique_name("sim2real-xsvc-ecs-taskdef-fg-")
    ecs = ctx.client("ecs")
    kwargs: dict = dict(
        family=family,
        containerDefinitions=container_defs,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
    )
    if execution_role_arn:
        kwargs["executionRoleArn"] = execution_role_arn
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))
    return td


def _create_fargate_service(
    ctx, cluster: str, task_def_arn: str, desired_count: int = 1
) -> dict:
    _ensure_ecs_service_linked_role(ctx)
    name = ctx.unique_name("sim2real-xsvc-ecs-svc-")
    ecs = ctx.client("ecs")
    svc = ecs.create_service(
        cluster=cluster,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration=_awsvpc_config(ctx),
    )["service"]

    def _cleanup() -> None:
        # Drain the service (desiredCount=0 + force delete) and WAIT for it to leave
        # ACTIVE before the cluster teardown (registered earlier, runs later) fires —
        # an ACTIVE service blocks cluster deletion.
        _unless_gone(lambda: ecs.update_service(cluster=cluster, service=name, desiredCount=0),
                     "ServiceNotFoundException", "ServiceNotActiveException")
        _unless_gone(lambda: ecs.delete_service(cluster=cluster, service=name, force=True),
                     "ServiceNotFoundException")
        _poll_until(
            lambda: (
                ecs.describe_services(cluster=cluster, services=[name]).get(
                    "services"
                )
                or [{}]
            )[0].get("status", "INACTIVE"),
            lambda st: st in ("INACTIVE", "DRAINING"),
            timeout_s=180,
            interval_s=2,
            description=f"service {name} drain",
        )

    ctx.on_cleanup(_cleanup)
    return svc


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Fargate service (desired 1) with an awslogs container gets a RUNNING task, reports
    runningCount == desiredCount, and the container's stdout lands in the CloudWatch log group."""
    log_group = _create_log_group(ctx)
    exec_role = _task_execution_role_arn(ctx)
    cluster = _create_cluster(ctx)

    marker = "container-log-marker"
    container_defs = [
        {
            "name": "app",
            "image": PUBLIC_IMAGE,
            "essential": True,
            # Emit a distinctive line, then stay up so the service can stabilize.
            "command": ["sh", "-c", f"echo {marker}; sleep 3600"],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": log_group,
                    "awslogs-region": ctx.region,
                    "awslogs-stream-prefix": "ecs",
                },
            },
        }
    ]
    td = _register_fargate_task_def(ctx, container_defs, execution_role_arn=exec_role)

    svc = _create_fargate_service(
        ctx, cluster["clusterName"], td["taskDefinitionArn"], desired_count=1
    )
    assert svc["status"] == "ACTIVE", svc["status"]
    assert svc["desiredCount"] == 1, svc["desiredCount"]

    ecs = ctx.client("ecs")

    # A task that stops inside this grace window is treated as the execution role's
    # attach not having propagated to ECS yet, not a real defect -- the service
    # scheduler will relaunch it. A stop past the window still fails fast.
    iam_propagation_grace_deadline = time.monotonic() + 60

    def _running_task_arn() -> str | None:
        arns = ecs.list_tasks(
            cluster=cluster["clusterName"],
            serviceName=svc["serviceName"],
            desiredStatus="RUNNING",
        ).get("taskArns", [])
        if not arns:
            return None
        tasks = ecs.describe_tasks(cluster=cluster["clusterName"], tasks=arns).get(
            "tasks", []
        )
        for t in tasks:
            if t.get("lastStatus") == "RUNNING":
                return t["taskArn"]
        # Surface an early-stopped task instead of spinning until timeout, once past
        # the IAM propagation grace window.
        for t in tasks:
            if (
                t.get("lastStatus") == "STOPPED"
                and time.monotonic() > iam_propagation_grace_deadline
            ):
                raise AssertionError(f"service task stopped: {t.get('stoppedReason')}")
        return None

    running_arn = _poll_until(
        _running_task_arn,
        lambda a: a is not None,
        timeout_s=420,
        interval_s=5,
        description="service task RUNNING",
    )
    assert running_arn

    stable = _poll_until(
        lambda: ecs.describe_services(
            cluster=cluster["clusterName"], services=[svc["serviceName"]]
        )["services"][0],
        lambda s: s.get("runningCount", 0) >= s.get("desiredCount", 1),
        timeout_s=180,
        interval_s=5,
        description="service runningCount == desiredCount",
    )
    assert stable["runningCount"] >= 1, stable.get("runningCount")

    logs = ctx.client("logs")

    def _log_events() -> list:
        try:
            # No filterPattern: a hyphenated marker is tokenized by CloudWatch and
            # will not match; fetch all events and match client-side below.
            resp = logs.filter_log_events(logGroupName=log_group)
        except Exception:
            return []
        return resp.get("events", [])

    events = _poll_until(
        _log_events,
        lambda evs: any(marker in e.get("message", "") for e in evs),
        timeout_s=180,
        interval_s=5,
        description="container logs in log group",
    )
    assert any(marker in e.get("message", "") for e in events), (
        f"expected {marker!r} in container logs, got {[e.get('message') for e in events]}"
    )


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
