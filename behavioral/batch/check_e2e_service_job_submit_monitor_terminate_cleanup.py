"""e2e-service-job-submit-monitor-terminate-cleanup."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-service-job-submit-monitor-terminate-cleanup"
GROUP = "e2e"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A submitted SAGEMAKER_TRAINING service job is listed by ListServiceJobs, leaves SUBMITTED, ends
    FAILED after TerminateServiceJob, and is listed exactly once with status FAILED by
    ListServiceJobs(jobStatus=FAILED)."""
    batch = ctx.client("batch")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-batch-svcjob-").replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    role_name = ctx.unique_name("sim2real-batch-svcjob-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")

    se_name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "NUM_INSTANCES"}],
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _disable_and_delete(ctx, "service_environment", se_name))
    se_arn = _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[se_name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
        timeout_s=60.0,
    )["serviceEnvironmentArn"]

    jq_name = ctx.unique_name("sim2real-batch-svcjob-jq-")
    batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        jobQueueType="SAGEMAKER_TRAINING",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _disable_and_delete(ctx, "job_queue", jq_name))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=60.0,
    )

    job_name = ctx.unique_name("sim2real-batch-svcjob-")
    payload = json.dumps(
        {
            "TrainingJobName": job_name,
            "RoleArn": role_arn,
            "AlgorithmSpecification": {
                "TrainingInputMode": "File",
                "TrainingImage": "public.ecr.aws/docker/library/busybox:latest",
                "ContainerEntrypoint": ["echo", "sim2real-service-job-test"],
            },
            "ResourceConfig": {"InstanceType": "ml.c5.xlarge", "InstanceCount": 1, "VolumeSizeInGB": 1},
            "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
            "StoppingCondition": {"MaxRuntimeInSeconds": 180},
        }
    )
    def _submit() -> dict[str, Any]:
        return batch.submit_service_job(
            jobName=job_name,
            jobQueue=jq_name,
            serviceJobType="SAGEMAKER_TRAINING",
            serviceRequestPayload=payload,
            retryStrategy={"attempts": 1},
            timeoutConfig={"attemptDurationSeconds": 180},
        )

    # The role was just created; SageMaker Training validates it can be assumed
    # at submission time, which can lag IAM's eventual consistency by a few
    # seconds. Retry the actual submit call (not a bare sleep) until it succeeds.
    submitted = _retry_until_ready(_submit, timeout_s=60.0, interval_s=5.0)
    job_id = submitted["jobId"]
    ctx.on_cleanup(lambda: _terminate_and_wait_service_job(ctx, job_id))

    # ListServiceJobs returns only RUNNING jobs unless jobStatus is given, so a still-SUBMITTED
    # job is invisible to an unfiltered list. Poll across every non-terminal status.
    _poll_until(
        lambda: _find_service_job(batch, jq_name, job_id, _ACTIVE_JOB_STATUSES),
        lambda found: found,
        timeout_s=30.0,
        interval_s=3.0,
    )

    # Progress: it must leave SUBMITTED (get scheduled/considered) within a bounded window.
    progressed = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda j: j["status"] != "SUBMITTED",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert progressed["status"] != "SUBMITTED"

    batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-terminate")
    terminated = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert terminated["status"] == "FAILED", f"expected terminated job to end FAILED, got {terminated['status']}"

    # Same ListServiceJobs filtering rule applies to the terminal read: ask for the
    # status the job actually settled into, not the RUNNING-only default.
    final_list = batch.list_service_jobs(jobQueue=jq_name, jobStatus="FAILED")["jobSummaryList"]
    final_entry = [j for j in final_list if j["jobId"] == job_id]
    assert len(final_entry) == 1, f"terminated service job not found via ListServiceJobs(jobStatus=FAILED): {final_list!r}"
    assert final_entry[0]["status"] == "FAILED", "terminated service job does not report terminal status"


# ListServiceJobs defaults to RUNNING-only; these are every status a job can hold
# between SubmitServiceJob and reaching a terminal state.
_ACTIVE_JOB_STATUSES = ("SUBMITTED", "PENDING", "RUNNABLE", "SCHEDULED", "STARTING", "RUNNING")


def _find_service_job(batch, jq_name: str, job_id: str, statuses: tuple[str, ...]) -> bool:
    for status in statuses:
        listed = batch.list_service_jobs(jobQueue=jq_name, jobStatus=status)["jobSummaryList"]
        if job_id in [j["jobId"] for j in listed]:
            return True
    return False


def _retry_until_ready(fn, timeout_s: float, interval_s: float) -> dict[str, Any]:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ClientException", "ValidationException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _terminate_and_wait_service_job(ctx, job_id: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-cleanup")
        _poll_until(
            lambda: batch.describe_service_job(jobId=job_id),
            lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=180.0,
            interval_s=5.0,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _disable_and_delete(ctx, kind: str, name: str) -> None:
    batch = ctx.client("batch")
    try:
        if kind == "job_queue":
            batch.update_job_queue(jobQueue=name, state="DISABLED")
            _poll_until(
                lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
                lambda jq: jq["status"] == "VALID" and jq["state"] == "DISABLED",
                timeout_s=60.0,
            )
            _retry_delete(lambda: batch.delete_job_queue(jobQueue=name))
            _wait_jq_gone(batch, name)
        elif kind == "service_environment":
            batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
            _poll_until(
                lambda: batch.describe_service_environments(serviceEnvironments=[name])[
                    "serviceEnvironments"
                ][0],
                lambda se: se["status"] == "VALID" and se["state"] == "DISABLED",
                timeout_s=60.0,
            )
            _retry_delete(lambda: batch.delete_service_environment(serviceEnvironment=name))
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _retry_delete(fn, timeout_s=300.0):
    """Run a Batch delete; retry its ClientException refusals every 2 s to timeout_s while a
    dependent finishes deleting. A "does not exist" answer is done; every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_jq_gone(batch, name, timeout_s=300.0):
    """Poll every 2 s until DescribeJobQueues lists the queue absent or DELETED."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        queues = batch.describe_job_queues(jobQueues=[name])["jobQueues"]
        if not queues or queues[0]["status"] == "DELETED":
            return
        time.sleep(2)
    raise AssertionError(f"job queue {name} still present {timeout_s:.0f}s after DeleteJobQueue")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
