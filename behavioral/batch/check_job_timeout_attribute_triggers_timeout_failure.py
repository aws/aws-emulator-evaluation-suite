"""job-timeout-attribute-triggers-timeout-failure."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-timeout-attribute-triggers-timeout-failure"
GROUP = "visibility-timeout-ttl"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/batch/latest/userguide/job_timeouts.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A RUNNING job with attemptDurationSeconds=60 whose container sleeps 600 s ends FAILED with
    isTerminated=True and a statusReason naming the timeout after running at least 55 s and under
    300 s: Batch itself enforces the attempt timeout."""
    batch = ctx.client("batch")
    vpc_id, subnets = _default_subnets(ctx)
    sg_id = _default_sg(ctx, vpc_id)
    exec_role_arn = _create_ecs_execution_role(ctx)

    ce_name = ctx.unique_name("sim2real-batch-ce-")
    ce_arn = _create_fargate_ce(ctx, ce_name, 2, subnets, sg_id)

    queue_name = ctx.unique_name("sim2real-batch-jq-")
    _create_job_queue(ctx, queue_name, [{"order": 1, "computeEnvironment": ce_arn}], priority=1)

    jd_name = ctx.unique_name("sim2real-batch-jd-")
    batch.register_job_definition(
        jobDefinitionName=jd_name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["/bin/sh", "-c", "sleep 600"],
            "executionRoleArn": exec_role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "2048"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        },
        timeout={"attemptDurationSeconds": 60},
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _try_deregister(ctx, jd_name))

    job = batch.submit_job(jobName=ctx.unique_name("sim2real-batch-job-"), jobQueue=queue_name, jobDefinition=jd_name)
    job_id = job["jobId"]
    ctx.on_cleanup(lambda: _try_terminate(ctx, job_id))

    running = _poll_until(
        lambda: batch.describe_jobs(jobs=[job_id])["jobs"][0],
        lambda j: j["status"] in ("RUNNING", "FAILED", "SUCCEEDED"),
        timeout_s=360,
        interval_s=6,
    )
    assert running["status"] == "RUNNING", f"job never reached RUNNING before terminating: {running['status']}/{running.get('statusReason')}"
    started_at = running["startedAt"]

    final = _poll_until(
        lambda: batch.describe_jobs(jobs=[job_id])["jobs"][0],
        lambda j: j["status"] in ("FAILED", "SUCCEEDED"),
        timeout_s=300,
        interval_s=6,
    )
    assert final["status"] == "FAILED", f"job did not fail on timeout, ended as {final['status']}"
    assert final["isTerminated"] is True, f"a job that ended FAILED via the timeout must report isTerminated=True, got {final['isTerminated']!r}"
    reason = (final.get("statusReason") or "").lower()
    assert "time" in reason, f"statusReason does not indicate a timeout: {final.get('statusReason')!r}"
    duration_ms = final["stoppedAt"] - started_at
    assert duration_ms >= 55_000, f"job ran only {duration_ms}ms, shorter than the 60s attemptDurationSeconds timeout"
    # The container command sleeps 600s; a target that ignores the timeout and just lets it
    # run to completion (then fails for an unrelated reason) must not read as "timeout enforced".
    assert duration_ms < 300_000, (
        f"job ran {duration_ms}ms, close to or past the container's own 600s sleep -- this looks "
        "like the command ran to completion rather than being cut short by the 60s timeout"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _default_subnets(ctx, count: int = 2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:

        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:

        raise AssertionError("shared network has no subnets")
    return vpc_id, [s["SubnetId"] for s in subnets[:count]]


def _default_sg(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return sgs[0]["GroupId"]


def _create_ecs_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    import json

    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_MANAGED_TAGS_KV
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # Bounded retry, not a bare sleep: wait for IAM's own read to show the attachment before
    # ECS/Fargate is asked to assume the role, since that read is the only propagation signal IAM
    # exposes.
    _poll_until(
        lambda: iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        lambda policies: any(p["PolicyArn"] == policy_arn for p in policies),
        timeout_s=30,
        interval_s=2,
    )
    return role["Role"]["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_fargate_ce(ctx, name: str, max_vcpus: int, subnets: list, sg_id: str) -> str:
    batch = ctx.client("batch")
    batch.create_compute_environment(
        computeEnvironmentName=name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": max_vcpus,
            "subnets": subnets,
            "securityGroupIds": [sg_id],
        },
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _drain_and_delete_ce(ctx, name))
    ce = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0],
        lambda ce: ce["status"] in ("VALID", "INVALID"),
        timeout_s=120,
        interval_s=5,
    )
    assert ce["status"] == "VALID", f"compute environment failed to validate: {ce.get('statusReason')}"
    return ce["computeEnvironmentArn"]


def _drain_and_delete_ce(ctx, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_compute_environment(computeEnvironment=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0],
            lambda ce: ce["status"] == "VALID",
            timeout_s=120,
            interval_s=5,
        )
        _delete_compute_environment_and_wait(batch, name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _create_job_queue(ctx, name: str, ce_order: list, priority: int) -> str:
    batch = ctx.client("batch")
    resp = batch.create_job_queue(
        jobQueueName=name,
        state="ENABLED",
        priority=priority,
        computeEnvironmentOrder=ce_order,
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _drain_and_delete_jq(ctx, name))
    jq = _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] in ("VALID", "INVALID"),
        timeout_s=120,
        interval_s=4,
    )
    assert jq["status"] == "VALID", f"job queue failed to validate: {jq.get('statusReason')}"
    return resp["jobQueueArn"]


def _drain_and_delete_jq(ctx, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["status"] == "VALID",
            timeout_s=120,
            interval_s=4,
        )
        batch.delete_job_queue(jobQueue=name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _try_terminate(ctx, job_id: str) -> None:
    batch = ctx.client("batch")
    job = batch.describe_jobs(jobs=[job_id])["jobs"][0]
    if job["status"] not in ("SUCCEEDED", "FAILED"):
        batch.terminate_job(jobId=job_id, reason="sim2real-behavioral-cleanup")
        _poll_until(
            lambda: batch.describe_jobs(jobs=[job_id])["jobs"][0],
            lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=120,
            interval_s=5,
        )


def _try_deregister(ctx, jd_name: str) -> None:
    batch = ctx.client("batch")
    for jd in batch.describe_job_definitions(jobDefinitionName=jd_name)["jobDefinitions"]:
        batch.deregister_job_definition(jobDefinition=f"{jd_name}:{jd['revision']}")


def _delete_compute_environment_and_wait(batch, name, timeout_s=300.0, interval_s=5.0):
    """DeleteComputeEnvironment, then wait until it is gone. The delete is asynchronous and needs
    the service role until it completes, so returning early lets a later cleanup delete the role
    and strand the environment."""
    batch.delete_compute_environment(computeEnvironment=name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
        if not [ce for ce in found if ce.get("status") != "DELETED"]:
            return
        time.sleep(interval_s)
    raise AssertionError(f"compute environment {name} still present {timeout_s:.0f}s after delete")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
