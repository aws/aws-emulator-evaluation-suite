"""job-attempt-duration-timeout-terminates-running-job."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-attempt-duration-timeout-terminates-running-job"
GROUP = "visibility-timeout-ttl"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/batch/latest/userguide/job_timeouts.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A RUNNING job with attemptDurationSeconds=60 whose container sleeps 600 s ends FAILED, with a
    statusReason naming the timeout, 30-300 s after it started: Batch enforces the attempt timeout
    itself, with no TerminateJob call."""

    batch = ctx.client("batch")
    subnets, sg_id = _default_network(ctx)
    exec_role_arn = _create_execution_role(ctx)

    ce_name = ctx.unique_name("sim2real-batch-ce-")
    batch.create_compute_environment(
        computeEnvironmentName=ce_name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": 4,
            "subnets": subnets,
            "securityGroupIds": [sg_id],
        },
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _disable_and_delete_ce(batch, ce_name))
    _wait_ce_status(batch, ce_name, timeout_s=180.0)

    jq_name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=1,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_name}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _disable_and_delete_jq(batch, jq_name))
    _wait_jq_status(batch, jq_name, timeout_s=180.0)

    jd_name = ctx.unique_name("sim2real-batch-jd-")
    jd = batch.register_job_definition(
        jobDefinitionName=jd_name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "command": ["sleep", "600"],
            "executionRoleArn": exec_role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "0.25"},
                {"type": "MEMORY", "value": "512"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        },
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=jd["jobDefinitionArn"]))

    job = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-job-"),
        jobQueue=jq_name,
        jobDefinition=jd["jobDefinitionArn"],
        timeout={"attemptDurationSeconds": 60},
    )
    job_id = job["jobId"]

    running = _wait_job_status(batch, job_id, {"RUNNING"}, {"FAILED", "SUCCEEDED"}, timeout_s=480.0)
    if running["status"] != "RUNNING":
        raise AssertionError(
            f"job never reached RUNNING (a precondition for this test), got "
            f"{running['status']}: {running.get('statusReason')}"
        )
    started_at = running["startedAt"]

    final = _wait_job_status(batch, job_id, set(), {"FAILED", "SUCCEEDED"}, timeout_s=300.0)
    assert final["status"] == "FAILED", (
        f"expected the 60s attemptDurationSeconds to force the job to FAILED, "
        f"got {final['status']}: {final.get('statusReason')}"
    )
    reason = (final.get("statusReason") or "").lower()
    assert "time" in reason, (
        f"job ended FAILED but statusReason does not attribute it to the attemptDurationSeconds "
        f"timeout: {final.get('statusReason')!r}"
    )
    duration_s = (final["stoppedAt"] - started_at) / 1000.0
    assert 30.0 <= duration_s < 300.0, (
        f"job attempt ran for {duration_s:.1f}s; expected a forced termination near the "
        f"60s attemptDurationSeconds, well short of the container's own 600s sleep"
    )


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("the network VPC is not visible to DescribeVpcs; cannot place Fargate resources")
    vpc_id = vpcs[0]["VpcId"]
    subnets = [
        s["SubnetId"]
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ][:2]
    if not subnets:
        raise AssertionError("the network has no subnets to place Fargate resources")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("the network VPC has no default security group")
    return subnets, sgs[0]["GroupId"]


def _create_execution_role(ctx):
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-exec-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _wait_ce_status(batch, name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        ces = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
        last = ces[0] if ces else None
        if last is not None and last["status"] in ("VALID", "INVALID"):
            if last["status"] != "VALID":
                raise AssertionError(f"compute environment {name} entered INVALID: {last.get('statusReason')}")
            return last
        time.sleep(5.0)
    raise AssertionError(f"compute environment {name} did not reach VALID within {timeout_s}s (last={last})")


def _disable_and_delete_ce(batch, name):
    try:
        batch.update_compute_environment(computeEnvironment=name, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        ces = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
        if not ces or ces[0]["status"] in ("VALID", "INVALID"):
            break
        time.sleep(5.0)
    _delete_compute_environment_and_wait(batch, name)


def _wait_jq_status(batch, name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        jqs = batch.describe_job_queues(jobQueues=[name])["jobQueues"]
        last = jqs[0] if jqs else None
        if last is not None and last["status"] in ("VALID", "INVALID"):
            if last["status"] != "VALID":
                raise AssertionError(f"job queue {name} entered INVALID: {last.get('statusReason')}")
            return last
        time.sleep(5.0)
    raise AssertionError(f"job queue {name} did not reach VALID within {timeout_s}s (last={last})")


def _disable_and_delete_jq(batch, name):
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        jqs = batch.describe_job_queues(jobQueues=[name])["jobQueues"]
        if not jqs or jqs[0]["status"] in ("VALID", "INVALID"):
            break
        time.sleep(5.0)
    batch.delete_job_queue(jobQueue=name)


def _wait_job_status(batch, job_id, target_statuses, terminal_statuses, timeout_s=300.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        jobs = batch.describe_jobs(jobs=[job_id])["jobs"]
        if jobs:
            last = jobs[0]
            if last["status"] in target_statuses or last["status"] in terminal_statuses:
                return last
        time.sleep(5.0)
    status = last["status"] if last else None
    raise AssertionError(f"job {job_id} stuck at status {status} after {timeout_s}s (last={last})")


def _delete_compute_environment_and_wait(batch, name, timeout_s=300.0, interval_s=5.0):
    """DeleteComputeEnvironment, then wait until it is gone. The delete is asynchronous and needs
    the service role until it completes, so returning early lets a later cleanup delete the role
    and strand the environment."""
    from botocore.exceptions import ClientError

    retry_deadline = time.monotonic() + timeout_s
    while True:
        if not [ce for ce in batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
                if ce.get("status") != "DELETED"]:
            return
        try:
            batch.delete_compute_environment(computeEnvironment=name)
            break
        except ClientError as e:  # still UPDATING, or a job queue being deleted still references it
            if e.response["Error"]["Code"] != "ClientException" or time.monotonic() >= retry_deadline:
                raise
            time.sleep(interval_s)
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
