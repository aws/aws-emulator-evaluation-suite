"""submit-job-to-disabled-queue-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "submit-job-to-disabled-queue-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitJob to a DISABLED queue fails with ClientException "not ENABLED." and lists no job.

    Re-enabling the queue makes the identical SubmitJob succeed, so the refusal is state-gated."""
    batch = ctx.client("batch")
    vpc_id, subnets = _default_subnets(ctx)
    sg_id = _default_sg(ctx, vpc_id)

    ce_name = ctx.unique_name("sim2real-batch-ce-")
    ce_arn = _create_fargate_ce(ctx, ce_name, 1, subnets, sg_id)

    queue_name = ctx.unique_name("sim2real-batch-jq-")
    queue_arn = _create_job_queue(ctx, queue_name, [{"order": 1, "computeEnvironment": ce_arn}], priority=1)

    exec_role_arn = _get_or_create_execution_role(ctx)

    jd_name = ctx.unique_name("sim2real-batch-jd-")
    batch.register_job_definition(
        jobDefinitionName=jd_name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["/bin/sh", "-c", "sleep 1"],
            "executionRoleArn": exec_role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "0.25"},
                {"type": "MEMORY", "value": "512"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        },
        platformCapabilities=["FARGATE"],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _try_deregister(ctx, jd_name))

    batch.update_job_queue(jobQueue=queue_name, state="DISABLED")
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID" and jq["state"] == "DISABLED",
        timeout_s=90,
        interval_s=4,
    )

    error = _error(
        lambda: batch.submit_job(
            jobName=ctx.unique_name("sim2real-batch-job-rejected-"), jobQueue=queue_name, jobDefinition=jd_name
        )
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "ClientException", f"expected ClientException submitting to a DISABLED queue, got {code}"
    assert message == f"JobQueue {queue_arn} not ENABLED.", f"expected the exact DISABLED-queue refusal message, got {message!r}"

    summaries = batch.list_jobs(jobQueue=queue_name)["jobSummaryList"]
    assert summaries == [], f"a job was created against the DISABLED queue despite the rejection: {summaries}"

    # Positive control: re-enable the queue and the identical submission now succeeds.
    batch.update_job_queue(jobQueue=queue_name, state="ENABLED")
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID" and jq["state"] == "ENABLED",
        timeout_s=90,
        interval_s=4,
    )
    job_id = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-job-accepted-"), jobQueue=queue_name, jobDefinition=jd_name
    )["jobId"]
    ctx.on_cleanup(lambda: _try_terminate(ctx, job_id))
    accepted = batch.describe_jobs(jobs=[job_id])["jobs"][0]
    assert accepted["jobQueue"] == queue_name or queue_name in accepted["jobQueue"], (
        f"expected the accepted job's queue to be {queue_name}, got {accepted['jobQueue']}"
    )
    assert accepted["status"] in ("SUBMITTED", "PENDING", "RUNNABLE", "STARTING", "RUNNING"), (
        f"expected the re-accepted job to be in an active pre-terminal status, got {accepted['status']}"
    )


def _get_or_create_execution_role(ctx) -> str:
    """Create an ECS task execution role (required by Fargate job definitions) and return its ARN.

    It carries AmazonECSTaskExecutionRolePolicy and is polled until IAM shows it."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-exec-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real-behavioral: temporary Fargate execution role",
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _try_delete_execution_role(ctx, role_name))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # IAM is eventually consistent -- wait until the role is readable back before
    # relying on it in RegisterJobDefinition/SubmitJob.
    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"],
        lambda r: r.get("Arn") == role_arn,
        timeout_s=60,
        interval_s=3,
    )
    return role_arn


def _try_delete_execution_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
