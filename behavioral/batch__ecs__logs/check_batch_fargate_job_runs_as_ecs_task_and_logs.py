"""batch-fargate-job-runs-as-ecs-task-and-logs."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-fargate-job-runs-as-ecs-task-and-logs"

GROUP = "container-batch-job"

SERVICES = ["batch", "ecs", "logs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SUCCEEDED Batch Fargate job is a stopped FARGATE ECS task (exit 0) in the CE's cluster.

    Its reported batch/ log stream exists in CloudWatch Logs and holds the container's marker."""
    ctx.client("batch")
    ecs = ctx.client("ecs")

    vpc_id, subnets = _default_vpc(ctx, min_subnets=1)
    sg_id = _default_sg(ctx, vpc_id)
    log_group = _create_log_group(ctx)
    _role, exec_role = _iam_role(
        ctx,
        "batch-exec",
        "ecs-tasks.amazonaws.com",
        [
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            }
        ],
    )

    ce_name, ce_arn = _create_fargate_ce(ctx, subnets[:2], sg_id)
    ce = _await_ce(ctx, ce_name, {"VALID", "INVALID"}, timeout_s=600)
    assert ce["status"] == "VALID", f"compute environment invalid: {ce}"
    ecs_cluster = ce["ecsClusterArn"]
    assert ecs_cluster, ce

    queue = _create_job_queue(ctx, ce_arn)
    jq = _await_jq(ctx, queue, {"VALID", "INVALID"}, timeout_s=300)
    assert jq["status"] == "VALID", f"job queue invalid: {jq}"

    marker = "sim2real-batch-" + ctx.unique_name("")[:8]
    job_def = _register_batch_job_def(
        ctx, _PUBLIC_IMAGE, ["sh", "-c", f"echo {marker}"], exec_role, log_group
    )
    job_id = _submit_job(ctx, queue, job_def)

    job = _await_job(ctx, job_id, {"SUCCEEDED", "FAILED"}, timeout_s=1200)
    assert job["status"] == "SUCCEEDED", (
        f"job did not succeed: status={job.get('status')} "
        f"statusReason={job.get('statusReason')} "
        f"containerReason={(job.get('container') or {}).get('reason')}"
    )
    container = job["container"]
    assert container.get("exitCode") == 0, container

    # --- Boundary 1: Batch really ran it as an ECS task in the CE's own cluster.
    task_arn = container.get("taskArn")
    assert task_arn, f"SUCCEEDED Fargate job reports no ECS taskArn: {container}"
    tasks = _poll_until(
        lambda: ecs.describe_tasks(cluster=ecs_cluster, tasks=[task_arn]).get("tasks", []),
        lambda ts: bool(ts),
        timeout_s=120,
        interval_s=5,
        description=f"ECS knows task {task_arn} in the compute environment cluster",
    )
    task = tasks[0]
    assert task["clusterArn"] == ecs_cluster, (task["clusterArn"], ecs_cluster)
    assert task.get("launchType") == "FARGATE", task.get("launchType")
    assert task["lastStatus"] == "STOPPED", task["lastStatus"]
    assert task["containers"][0].get("exitCode") == 0, task["containers"][0]

    # --- Boundary 2: the stream Batch points at really holds the container's output.
    stream = container.get("logStreamName")
    assert stream and stream.startswith(
        "batch/"
    ), f"expected a batch/<container>/<task-id> stream name, got {stream!r}"
    _await_log_stream(ctx, log_group, stream, timeout_s=300)
    _await_log_marker(ctx, log_group, stream, marker, timeout_s=300)


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    """Run a teardown step fn(); return when the resource is already gone, raise anything else."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _delete_while_in_use(fn, timeout_s=60.0):
    """Run a Batch delete, retrying every 2 s while Batch refuses it for a dependency still
    draining (ClientException); not-found returns, anything else or the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _swallow(fn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() >= deadline:
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
    """(vpc_id, subnet_ids) from the shared network, one subnet per AZ.

    Its subnets route to an internet gateway, so a public-IP Fargate task pulls without a NAT."""
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
    """Create a role trusting trust_service with one inline policy; return (name, arn).

    The role and policy are polled back (IAM is eventually consistent); the later CE and queue
    waits cover trust propagation before any task assumes it."""
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


def _batch_slr(ctx) -> str:
    """AWSServiceRoleForBatch — the serviceRole a MANAGED compute environment needs.
    Shared, account-level, never deleted by this check."""
    iam = ctx.client("iam")
    existing = _safe(lambda: iam.get_role(RoleName="AWSServiceRoleForBatch"))
    if existing:
        return existing["Role"]["Arn"]
    created = _safe(lambda: iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com"))
    if not created:
        raise AssertionError("cannot resolve the AWS Batch service-linked role")
    _poll_until(
        lambda: _safe(lambda: iam.get_role(RoleName="AWSServiceRoleForBatch")),
        lambda r: r is not None,
        timeout_s=90,
        interval_s=5,
        description="AWSServiceRoleForBatch readable",
    )
    return created["Role"]["Arn"]


def _create_fargate_ce(ctx, subnets, sg_id, max_vcpus=4) -> tuple[str, str]:
    """A MANAGED / FARGATE compute environment in the default VPC (no NAT, no EC2)."""
    bat = ctx.client("batch")
    name = ctx.unique_name(_XSVC_PREFIX + "ce-fg-")
    arn = bat.create_compute_environment(
        computeEnvironmentName=name,
        type="MANAGED",
        state="ENABLED",
        serviceRole=_batch_slr(ctx),
        computeResources={
            "type": "FARGATE",
            "maxvCpus": max_vcpus,
            "subnets": subnets,
            "securityGroupIds": [sg_id],
        },
        tags=dict(_MANAGED_TAGS),
    )["computeEnvironmentArn"]

    def _drop():
        _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
        _swallow(lambda: _await_ce(ctx, name, {"VALID", "INVALID"}, timeout_s=180))
        _delete_while_in_use(lambda: bat.delete_compute_environment(computeEnvironment=name))

    ctx.on_cleanup(_drop)
    return name, arn


def _await_ce(ctx, name, statuses, timeout_s=300.0):
    bat = ctx.client("batch")
    return _poll_until(
        lambda: (
            bat.describe_compute_environments(computeEnvironments=[name]).get("computeEnvironments")
            or [{}]
        )[0],
        lambda ce: ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=5,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _create_job_queue(ctx, ce_arn) -> str:
    bat = ctx.client("batch")
    name = ctx.unique_name(_XSVC_PREFIX + "jq-")
    bat.create_job_queue(
        jobQueueName=name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS),
    )

    def _drop():
        _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
        _swallow(lambda: _await_jq(ctx, name, {"VALID", "INVALID"}, timeout_s=180))
        _delete_while_in_use(lambda: bat.delete_job_queue(jobQueue=name))

    ctx.on_cleanup(_drop)
    return name


def _await_jq(ctx, name, statuses, timeout_s=180.0):
    bat = ctx.client("batch")
    return _poll_until(
        lambda: (bat.describe_job_queues(jobQueues=[name]).get("jobQueues") or [{}])[0],
        lambda jq: jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=5,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _register_batch_job_def(ctx, image, command, exec_role_arn, log_group) -> str:
    bat = ctx.client("batch")
    name = ctx.unique_name(_XSVC_PREFIX + "jd-fg-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": image,
            "command": command,
            "executionRoleArn": exec_role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "0.25"},
                {"type": "MEMORY", "value": "512"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
            "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
            "logConfiguration": _awslogs(log_group, ctx.region, "batch"),
        },
        tags=dict(_MANAGED_TAGS),
    )
    ref = f"{name}:{resp['revision']}"
    ctx.on_cleanup(lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=ref)))
    return ref


def _submit_job(ctx, queue, job_def) -> str:
    bat = ctx.client("batch")
    job_id = bat.submit_job(
        jobName=ctx.unique_name(_XSVC_PREFIX + "job-"),
        jobQueue=queue,
        jobDefinition=job_def,
    )["jobId"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: bat.terminate_job(jobId=job_id, reason="sim2real-xsvc-cleanup"))
    )
    return job_id


def _await_job(ctx, job_id, statuses, timeout_s=1200.0):
    bat = ctx.client("batch")
    return _poll_until(
        lambda: (bat.describe_jobs(jobs=[job_id]).get("jobs") or [{}])[0],
        lambda j: j.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=15,
        description=f"batch job {job_id} status in {sorted(statuses)}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
