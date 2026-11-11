"""ecr-pull-through-cache-image-pulled-by-ecs-task."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecr-pull-through-cache-image-pulled-by-ecs-task"

GROUP = "container-image-pull"

SERVICES = ["ecr", "ecs", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ECS task off a private pull-through-cache ECR URI reaches RUNNING, the pull populates the
    cache repository, and the container's stdout reaches CloudWatch Logs via awslogs."""
    ecr = ctx.client("ecr")

    _vpc_id, subnets = _default_vpc(ctx, min_subnets=1)
    log_group = _create_log_group(ctx)
    private_image, repo, _prefix = _pull_through_cache_repo(ctx)
    cache_repo = repo["repositoryName"]

    _role_name, exec_role = _iam_role(
        ctx,
        "ecs-exec",
        "ecs-tasks.amazonaws.com",
        [
            {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                    "ecr:BatchImportUpstreamImage",
                ],
                "Resource": repo["repositoryArn"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    )

    cluster = _create_cluster(ctx)
    marker = "sim2real-ptc-pull-ok"
    td = _register_task_def(
        ctx,
        [
            {
                "name": "app",
                "image": private_image,
                "essential": True,
                "command": ["sh", "-c", f"echo {marker}; sleep 900"],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        execution_role_arn=exec_role,
    )
    task_arn = _run_task(ctx, cluster, td["taskDefinitionArn"], subnets)

    task = _await_task(ctx, cluster, task_arn, {"RUNNING", "STOPPED"}, timeout_s=720)
    assert task["lastStatus"] == "RUNNING", (
        f"task did not reach RUNNING off the private ECR URI {private_image}: "
        f"lastStatus={task.get('lastStatus')} stopCode={task.get('stopCode')} "
        f"stoppedReason={task.get('stoppedReason')}"
    )

    # Effect 1 — the pull materialised the image INSIDE the private repository.
    details = _poll_until(
        lambda: ecr.describe_images(repositoryName=cache_repo).get("imageDetails", []),
        lambda ds: any("latest" in (d.get("imageTags") or []) for d in ds),
        timeout_s=180,
        interval_s=5,
        description=f"cache repo {cache_repo} populated by the ECS pull",
    )
    cached = next(d for d in details if "latest" in (d.get("imageTags") or []))
    assert cached["imageSizeInBytes"] > 0, cached
    assert cached["imageDigest"].startswith("sha256:"), cached["imageDigest"]

    # Effect 2 — the container's stdout reached CloudWatch Logs.
    stream = f"ecs/app/{task_arn.rsplit('/', 1)[-1]}"
    _await_log_stream(ctx, log_group, stream, timeout_s=240)
    _await_log_marker(ctx, log_group, stream, marker, timeout_s=240)


def _pull_through_cache_repo(ctx, image_path="docker/library/busybox"):
    """(private_image_uri, repository, prefix) for an ECR Public pull-through cache repository.

    A pull-through rule gives a runnable image behind a private URI without pushing one; the
    repository is pre-created so the pull does not need ecr:CreateRepository."""
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
    # Baseline: nothing cached yet, so a later DescribeImages hit proves the ECS pull
    # imported it rather than the repository having been pre-populated.
    existing = ecr.list_images(repositoryName=name).get("imageIds", [])
    assert existing == [], f"cache repo unexpectedly pre-populated: {existing}"
    return uri, repo, prefix


_XSVC_PREFIX = "sim2real-xsvc-"

_ECS_SLR_NAME = "AWSServiceRoleForECS"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
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
    """Return fn()'s result, or None if it raised."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
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

    Its subnets route to an internet gateway, so a public-IP Fargate task can pull without a NAT."""
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

    IAM is eventually consistent, so the inline policy is polled back before the role is used."""
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
    """Ensure AWSServiceRoleForECS exists: CreateService auto-creates it, RunTask does not.

    Account-level shared infrastructure, so it is deliberately not torn down."""
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


def _run_task(ctx, cluster, td_arn, subnets, sg_ids=None) -> str:
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    awsvpc: dict = {"subnets": subnets, "assignPublicIp": "ENABLED"}
    if sg_ids:
        awsvpc["securityGroups"] = sg_ids

    def _launch():
        return ecs.run_task(
            cluster=cluster,
            taskDefinition=td_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration={"awsvpcConfiguration": awsvpc},
        )

    # A new service-linked or execution role is readable in IAM seconds before ECS can assume
    # it; RunTask fails synchronously until then, so retry those two errors within a bound.
    deadline = time.monotonic() + 120
    while True:
        try:
            resp = _launch()
            break
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            transient = "service linked role" in msg or "unable to assume the role" in msg
            if transient and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    assert not resp.get("failures"), f"RunTask failures: {resp.get('failures')}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _gone_ok(lambda: ecs.stop_task(cluster=cluster, task=arn),
                                    "ClusterNotFoundException"))
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
