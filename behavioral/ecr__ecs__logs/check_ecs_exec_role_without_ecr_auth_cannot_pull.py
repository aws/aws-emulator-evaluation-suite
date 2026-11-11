"""ecs-exec-role-without-ecr-auth-cannot-pull."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-exec-role-without-ecr-auth-cannot-pull"

GROUP = "container-image-pull"

SERVICES = ["ecr", "ecs", "logs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An execution role without ecr:GetAuthorizationToken fails the task with
    ResourceInitializationError and no log stream; one without the repository actions fails with
    CannotPullContainerError (403). Each leg asserts the absence of the other's error class.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html
    """
    _vpc_id, subnets = _default_vpc(ctx, min_subnets=1)
    log_group = _create_log_group(ctx)
    private_image, repo, _prefix = _pull_through_cache_repo(ctx)
    cluster = _create_cluster(ctx)

    logs_stmt = {
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "*",
    }
    pull_stmt = {
        "Effect": "Allow",
        "Action": [
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
            "ecr:BatchImportUpstreamImage",
        ],
        "Resource": repo["repositoryArn"],
    }
    auth_stmt = {
        "Effect": "Allow",
        "Action": "ecr:GetAuthorizationToken",
        "Resource": "*",
    }

    # Control: the fully-permitted role pulls the image (also populating the cache) and runs it.
    _ok_name, ok_role = _iam_role(
        ctx, "ecs-exec-ok", "ecs-tasks.amazonaws.com", [auth_stmt, pull_stmt, logs_stmt]
    )
    marker = "sim2real-control-pull-ok"
    ok_td = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": private_image,
                "essential": True,
                "command": ["sh", "-c", f"echo {marker}; exit 0"],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=ok_role,
    )
    ok_arn = _run_task(ctx, cluster, ok_td["taskDefinitionArn"], subnets)
    ok_task = _await_task(ctx, cluster, ok_arn, {"STOPPED"}, timeout_s=720)
    assert ok_task["containers"][0].get("exitCode") == 0, (
        "control task with a fully-permitted execution role failed to run the private "
        f"image {private_image}: stopCode={ok_task.get('stopCode')} "
        f"reason={ok_task.get('stoppedReason')}"
    )
    ok_stream = f"ecs/app/{ok_arn.rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, log_group, ok_stream, timeout_s=300)
    _await_log_marker(ctx, log_group, ok_stream, marker, timeout_s=300)

    # Drop only ecr:GetAuthorizationToken. logs:CreateLogStream stays granted, so the missing log
    # stream asserted below is attributable to the container never starting.
    bad_name, bad_role = _iam_role(
        ctx, "ecs-exec-noauth", "ecs-tasks.amazonaws.com", [pull_stmt, logs_stmt]
    )
    bad_td = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": private_image,
                "essential": True,
                "command": ["sh", "-c", f"echo {marker}; exit 0"],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=bad_role,
    )
    bad_arn = _run_task(ctx, cluster, bad_td["taskDefinitionArn"], subnets)
    bad_task = _await_task(ctx, cluster, bad_arn, {"STOPPED"}, timeout_s=600)

    assert bad_task["lastStatus"] == "STOPPED", bad_task.get("lastStatus")
    assert bad_task.get("stopCode") == "TaskFailedToStart", (
        "task without ecr:GetAuthorizationToken was not failed at start: "
        f"stopCode={bad_task.get('stopCode')} reason={bad_task.get('stoppedReason')}"
    )
    reason = bad_task.get("stoppedReason", "")
    assert reason.startswith("ResourceInitializationError:"), (
        "a denied ECR auth token fails the task in the EXECUTION-ROLE resource-initialization "
        f"phase, so the reason must open with 'ResourceInitializationError:'; got: {reason!r}"
    )
    assert "unable to retrieve ecr registry auth" in reason, (
        f"the reason must say which resource could not be retrieved, got: {reason!r}"
    )
    assert "AccessDeniedException" in reason, (
        f"the reason must surface the underlying IAM refusal, got: {reason!r}"
    )
    assert "ecr:GetAuthorizationToken" in reason, (
        "the reason must name the exact action that was denied -- that string is the whole "
        f"diagnostic value of the message; got: {reason!r}"
    )
    assert f"assumed-role/{bad_name}/" in reason, (
        f"the reason must name the execution role {bad_name!r} whose policy is at fault (ECS "
        f"reports the assumed-role ARN it was using), got: {reason!r}"
    )
    assert "CannotPullContainerError" not in reason, (
        "real AWS reserves CannotPullContainerError for a failure of the pull ITSELF (asserted in "
        "the next leg); a missing auth token never reaches the pull, and collapsing the two hides "
        f"which of the role's permissions is wrong; got: {reason!r}"
    )
    assert bad_task["containers"][0].get("exitCode") is None, (
        "the container never ran, so it cannot have an exit code: "
        f"{bad_task['containers'][0]!r}"
    )

    bad_stream = f"ecs/app/{bad_arn.rsplit('/', 1)[-1]}"
    names = _stream_names(ctx, log_group)
    assert bad_stream not in names, (
        f"a log stream {bad_stream!r} exists for a task that could not pull its image: " f"{names}"
    )
    assert ok_stream in names, f"control stream disappeared: {names}"

    # Restore ecr:GetAuthorizationToken and deny the repository-scoped actions instead. The awslogs
    # stream may be created before the pull here, so its absence is not asserted.
    nopull_name, nopull_role = _iam_role(
        ctx, "ecs-exec-nopull", "ecs-tasks.amazonaws.com", [auth_stmt, logs_stmt]
    )
    nopull_td = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": private_image,
                "essential": True,
                "command": ["sh", "-c", f"echo {marker}; exit 0"],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=nopull_role,
    )
    nopull_arn = _run_task(ctx, cluster, nopull_td["taskDefinitionArn"], subnets)
    nopull_task = _await_task(ctx, cluster, nopull_arn, {"STOPPED"}, timeout_s=600)
    assert nopull_task.get("stopCode") == "TaskFailedToStart", (
        f"task {nopull_name} could authenticate but not read the repository, so it must still fail "
        f"at start: stopCode={nopull_task.get('stopCode')} "
        f"reason={nopull_task.get('stoppedReason')}"
    )
    nopull_reason = nopull_task.get("stoppedReason", "")
    assert nopull_reason.startswith("CannotPullContainerError:"), (
        "with a valid auth token but no ecr:BatchGetImage the failure IS the pull, so real AWS "
        f"answers CannotPullContainerError here; got: {nopull_reason!r}"
    )
    assert "403 Forbidden" in nopull_reason, (
        "the pull failure must report the registry's own refusal (HTTP 403 on the manifest "
        f"request), got: {nopull_reason!r}"
    )
    assert private_image in nopull_reason, (
        f"the pull failure must name the image {private_image!r} it could not resolve, got: "
        f"{nopull_reason!r}"
    )
    assert "ResourceInitializationError" not in nopull_reason, (
        "the execution role authenticated successfully here, so this is NOT a "
        f"resource-initialization failure; got: {nopull_reason!r}"
    )
    assert nopull_task["containers"][0].get("exitCode") is None, nopull_task["containers"][0]


def _pull_through_cache_repo(ctx, image_path="docker/library/busybox"):
    """(private_image_uri, repository, prefix) for an ECR pull-through cache repository.

    A pull-through cache rule with an ECR Public upstream yields a runnable private image without
    docker; the repository is pre-created so the pull does not need ecr:CreateRepository."""
    ecr = ctx.client("ecr")
    prefix = ctx.unique_name(_XSVC_PREFIX + "ptc-")
    try:
        rule = ecr.create_pull_through_cache_rule(
            ecrRepositoryPrefix=prefix, upstreamRegistryUrl="public.ecr.aws"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if "LimitExceeded" in code:
            raise AssertionError(f"registry is at its pull-through-cache rule limit: {code}") from exc
        raise
    assert rule["ecrRepositoryPrefix"] == prefix, rule
    ctx.on_cleanup(
        lambda: _gone_ok(lambda: ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix),
                         "PullThroughCacheRuleNotFoundException")
    )
    name = f"{prefix}/{image_path}"
    repo = ecr.create_repository(repositoryName=name, tags=_tags_kv())["repository"]
    ctx.on_cleanup(lambda: _gone_ok(lambda: ecr.delete_repository(repositoryName=name, force=True),
                                    "RepositoryNotFoundException"))
    uri = repo["repositoryUri"] + ":latest"
    assert ".dkr.ecr." in uri, uri
    # Nothing cached yet, so the ECS pull is what imports the image.
    existing = ecr.list_images(repositoryName=name).get("imageIds", [])
    assert existing == [], f"cache repo unexpectedly pre-populated: {existing}"
    return uri, repo, prefix


def _stream_names(ctx, group: str) -> list[str]:
    return [
        s["logStreamName"]
        for s in ctx.client("logs").describe_log_streams(logGroupName=group).get("logStreams", [])
    ]


_XSVC_PREFIX = "sim2real-xsvc-"

_ECS_SLR_NAME = "AWSServiceRoleForECS"

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


def _gone_ok(fn, *codes):
    """Run a teardown call; return only on the given not-found codes and raise every other error."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _safe(fn):
    """Run fn() and return its result, or None if it raised (probe helper)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the result, raising on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _default_vpc(ctx, min_subnets=1):
    """(vpc_id, subnet_ids) from the shared network, one subnet per AZ.

    Its subnets route to an internet gateway, so assignPublicIp=ENABLED tasks pull without a NAT."""
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
    """Create a role trusting trust_service with one inline policy; returns (name, arn).

    IAM is eventually consistent, so the inline policy is polled back; trust propagation to ECS
    is retried in _run_task."""
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
        _gone_ok(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity")
        _gone_ok(lambda: iam.delete_role(RoleName=name), "NoSuchEntity")

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
    """Ensure the ECS service-linked role exists; RunTask needs it but never creates it.

    The role is account-wide and shared by every ECS caller, so it is deliberately not torn down.
    """
    iam = ctx.client("iam")
    if _safe(lambda: iam.get_role(RoleName=_ECS_SLR_NAME)) is not None:
        return
    _swallow(lambda: iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com"))
    for _ in range(15):
        if _safe(lambda: iam.get_role(RoleName=_ECS_SLR_NAME)) is not None:
            return
        time.sleep(2)


def _create_cluster(ctx, settings=None) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-cluster-")
    kwargs: dict = {"clusterName": name, "tags": _ecs_tags_kv()}
    if settings:
        kwargs["settings"] = settings
    ecs.create_cluster(**kwargs)

    def _drop():
        # A DRAINING service / stopping task blocks the delete briefly: retry those codes to a deadline.
        deadline = time.monotonic() + 80.0
        while True:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ClusterNotFoundException":
                    return
                busy = code in ("ClusterContainsTasksException", "ClusterContainsServicesException",
                                "UpdateInProgressException")
                if not busy or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_drop)
    return name


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(_XSVC_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _gone_ok(lambda: logs.delete_log_group(logGroupName=name),
                                    "ResourceNotFoundException"))
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


def _run_task(ctx, cluster, td_arn, subnets, sg_ids=None, timeout_s=120.0, interval_s=6.0) -> str:
    """RunTask, retrying while a just-created role propagates to ECS: the service-linked-role
    message, an 'unable to assume the role' ClientException, or a `failures` entry on a 200."""
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    awsvpc: dict = {"subnets": subnets, "assignPublicIp": "ENABLED"}
    if sg_ids:
        awsvpc["securityGroups"] = sg_ids
    deadline = time.monotonic() + timeout_s
    last_failures = None
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration={"awsvpcConfiguration": awsvpc},
            )
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            transient = "service linked role" in msg or "unable to assume the role" in msg.lower()
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
            continue
        if resp.get("tasks") and not resp.get("failures"):
            arn = resp["tasks"][0]["taskArn"]
            ctx.on_cleanup(lambda: _gone_ok(lambda: ecs.stop_task(cluster=cluster, task=arn),
                                            "ClusterNotFoundException"))
            return arn
        last_failures = resp.get("failures")
        if time.monotonic() >= deadline:
            raise AssertionError(f"RunTask never succeeded (last failures: {last_failures})")
        time.sleep(interval_s)


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
