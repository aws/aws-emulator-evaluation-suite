"""job-attempt-duration-timeout-terminates-job."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-attempt-duration-timeout-terminates-job"
GROUP = "visibility-timeout-ttl"
SERVICES = ["batch"]


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/batch/latest/userguide/job_timeouts.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A job whose attemptDurationSeconds elapses while RUNNING is automatically
    transitioned to FAILED by AWS Batch (SIGTERM'd on the compute resource), with the
    stoppedAt-startedAt gap tracking the configured timeout and a timeout statusReason."""
    batch = ctx.client("batch")
    subnet_ids, sg_id = _get_default_network(ctx)
    exec_role_arn = _create_ecs_execution_role(ctx)
    ce_arn = _create_fargate_compute_environment(ctx, subnet_ids, sg_id)
    queue_name, queue_arn = _create_fargate_job_queue(ctx, ce_arn)
    job_def_arn = _register_sleep_job_definition(ctx, exec_role_arn)

    attempt_duration = 60  # minimum allowed value
    job_name = ctx.unique_name("sim2real-batch-timeoutjob-")
    job_id = batch.submit_job(
        jobName=job_name,
        jobQueue=queue_name,
        jobDefinition=job_def_arn,
        timeout={"attemptDurationSeconds": attempt_duration},
        tags={"sim2real:managed": "true"},
    )["jobId"]
    ctx.on_cleanup(lambda: _safe(lambda: batch.terminate_job(jobId=job_id, reason="sim2real-cleanup")))

    final = _poll_until(
        lambda: batch.describe_jobs(jobs=[job_id])["jobs"][0],
        lambda j: j["status"] in ("FAILED", "SUCCEEDED"),
        timeout_s=900,
        interval_s=10,
    )
    assert final["status"] == "FAILED", (
        f"expected the job to be killed by its {attempt_duration}s timeout, "
        f"got status={final['status']!r} reason={final.get('statusReason')!r}"
    )
    reason = (final.get("statusReason") or "").lower()
    assert "timeout" in reason or "timed out" in reason, f"unexpected statusReason: {final.get('statusReason')!r}"

    started_at = final.get("startedAt")
    stopped_at = final.get("stoppedAt")
    assert started_at is not None and stopped_at is not None, (
        f"a job that ran and timed out must report both startedAt and stoppedAt, "
        f"got startedAt={started_at!r} stoppedAt={stopped_at!r}"
    )
    elapsed_s = (stopped_at - started_at) / 1000.0
    # Best-effort termination: at least the configured timeout, generously bounded above
    # to absorb the SIGTERM->SIGKILL grace period and scheduler slack.
    assert attempt_duration - 5 <= elapsed_s <= attempt_duration + 180, (
        f"elapsed RUNNING time {elapsed_s:.1f}s is not consistent with a {attempt_duration}s timeout"
    )


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _get_default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host a Fargate compute environment")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return subnet_ids, sg_id


def _create_ecs_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-ecs-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    else:
        raise AssertionError(f"role {role_name} never became visible to IAM reads")
    # No extra fixed sleep here: the compute environment and job queue VALID polls below
    # (tens of seconds each) run before the role is ever assumed by a Fargate task, and
    # already provide the propagation buffer ECS/Fargate needs.
    return role_arn


def _create_fargate_compute_environment(ctx, subnet_ids, sg_id):
    batch = ctx.client("batch")
    ce_name = ctx.unique_name("sim2real-batch-fgce-")
    ce_arn = batch.create_compute_environment(
        computeEnvironmentName=ce_name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": 4,
            "subnets": subnet_ids,
            "securityGroupIds": [sg_id],
        },
        tags={"sim2real:managed": "true"},
    )["computeEnvironmentArn"]

    def _cleanup():
        try:
            batch.update_compute_environment(computeEnvironment=ce_arn, state="DISABLED")
            for _ in range(60):
                d = batch.describe_compute_environments(computeEnvironments=[ce_arn])
                if not d["computeEnvironments"] or d["computeEnvironments"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(5)
            batch.delete_compute_environment(computeEnvironment=ce_arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_arn])["computeEnvironments"][0],
        lambda e: e["status"] == "VALID",
        timeout_s=180,
        interval_s=5,
    )
    return ce_arn


def _create_fargate_job_queue(ctx, ce_arn):
    batch = ctx.client("batch")
    queue_name = ctx.unique_name("sim2real-batch-fgq-")
    queue_arn = batch.create_job_queue(
        jobQueueName=queue_name,
        priority=1,
        state="ENABLED",
        computeEnvironmentOrder=[{"computeEnvironment": ce_arn, "order": 1}],
        tags={"sim2real:managed": "true"},
    )["jobQueueArn"]

    def _cleanup():
        try:
            batch.update_job_queue(jobQueue=queue_arn, state="DISABLED")
            for _ in range(60):
                d = batch.describe_job_queues(jobQueues=[queue_arn])
                if not d["jobQueues"] or d["jobQueues"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(5)
            batch.delete_job_queue(jobQueue=queue_arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0],
        lambda q: q["status"] == "VALID",
        timeout_s=180,
        interval_s=5,
    )
    return queue_name, queue_arn


def _register_sleep_job_definition(ctx, exec_role_arn):
    batch = ctx.client("batch")
    job_def_name = ctx.unique_name("sim2real-batch-timeoutjobdef-")
    resp = batch.register_job_definition(
        jobDefinitionName=job_def_name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["sleep", "3600"],
            "executionRoleArn": exec_role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "0.25"},
                {"type": "MEMORY", "value": "512"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        },
        tags={"sim2real:managed": "true"},
    )
    job_def_arn = resp["jobDefinitionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: batch.deregister_job_definition(jobDefinition=job_def_arn)))
    return job_def_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
