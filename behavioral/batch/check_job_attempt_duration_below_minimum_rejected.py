"""job-attempt-duration-below-minimum-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-attempt-duration-below-minimum-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitJob with attemptDurationSeconds below the documented 60-second minimum is
    rejected with ClientException, no job is created as a result, and the same queue/
    definition accepts a job at exactly the 60-second minimum (positive control).
    """
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

    rejected_name = ctx.unique_name("sim2real-batch-badjob-")
    code, message, request_id = _error(
        lambda: batch.submit_job(
            jobName=rejected_name,
            jobQueue=jq_name,
            jobDefinition=jd["jobDefinitionArn"],
            timeout={"attemptDurationSeconds": 59},
        )
    )
    assert code == "ClientException", f"expected ClientException for a sub-60s timeout, got {code}"
    # Batch wraps this validation message with the request id of the refused call.
    expected_message = (
        "Error executing request, Exception : AttemptDurationSeconds in Timeout must be at least "
        f"60 seconds., RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent, via an independent read at the destination: the rejected attempt
    # never appears in the queue's own job list, in ANY status (ListJobs without an
    # explicit jobStatus only returns RUNNING jobs, which would let a job stuck in
    # SUBMITTED/RUNNABLE/etc score as absent by omission -- so every modelled status
    # is checked explicitly).
    queued_names = set()
    for status in ("SUBMITTED", "PENDING", "RUNNABLE", "STARTING", "RUNNING", "SUCCEEDED", "FAILED"):
        page = batch.list_jobs(jobQueue=jq_name, jobStatus=status)["jobSummaryList"]
        queued_names.update(j["jobName"] for j in page)
    assert rejected_name not in queued_names, (
        f"rejected job name {rejected_name!r} unexpectedly appears in the queue's job list "
        f"after a ClientException, got {sorted(queued_names)}"
    )

    # Positive control: the identical queue/definition accepts a job at the 60s minimum.
    control_name = ctx.unique_name("sim2real-batch-okjob-")
    control = batch.submit_job(
        jobName=control_name,
        jobQueue=jq_name,
        jobDefinition=jd["jobDefinitionArn"],
        timeout={"attemptDurationSeconds": 60},
    )
    control_job_id = control.get("jobId")
    assert control_job_id, "SubmitJob succeeded but returned no jobId for the positive control"
    ctx.on_cleanup(lambda: _best_effort_terminate_job(batch, control_job_id))

    # Confirm the control job is actually tracked by Batch (authoritative describe,
    # not the RUNNING-only-by-default list_jobs view which would race the job's
    # SUBMITTED/RUNNABLE/STARTING transition).
    described = batch.describe_jobs(jobs=[control_job_id])["jobs"]
    assert described and described[0]["jobName"] == control_name, (
        "the positive-control job was not found via DescribeJobs after a successful SubmitJob"
    )


# ===== helpers =====


def _best_effort_terminate_job(batch, job_id):
    batch.terminate_job(jobId=job_id, reason="sim2real-behavioral-check cleanup")


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message, RequestId). An unexpected success
    raises, so a target that accepts what AWS refuses is never reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("the account baseline's shared network is missing; Fargate resources need it")
    vpc_id = vpcs[0]["VpcId"]
    subnets = [
        s["SubnetId"]
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ][:2]
    if not subnets:
        raise AssertionError("shared network has no subnets available to place Fargate resources")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnets, sgs[0]["GroupId"]


def _create_execution_role(ctx):
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
