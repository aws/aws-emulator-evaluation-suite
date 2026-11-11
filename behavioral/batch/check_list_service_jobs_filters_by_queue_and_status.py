"""list-service-jobs-filters-by-queue-and-status."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-service-jobs-filters-by-queue-and-status"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListServiceJobs honours its jobQueue and jobStatus filters: queue A + FAILED returns exactly
    the job terminated there, excluding its still-active sibling and any job on queue B."""
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_execution_role(ctx)
    bucket = _create_output_bucket(ctx)
    queue_a, _env_a = _create_sagemaker_queue(ctx)
    queue_b, _env_b = _create_sagemaker_queue(ctx)

    job1_name = ctx.unique_name("sim2real-svcjob-a1-")
    job2_name = ctx.unique_name("sim2real-svcjob-a2-")
    job3_name = ctx.unique_name("sim2real-svcjob-b1-")

    job1_id = _submit_service_job_with_role_settle(
        batch, jobName=job1_name, jobQueue=queue_a, serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=_service_job_payload(ctx, job1_name, role_arn, bucket, 300),
    )
    job2_id = _submit_service_job_with_role_settle(
        batch, jobName=job2_name, jobQueue=queue_a, serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=_service_job_payload(ctx, job2_name, role_arn, bucket, 300),
    )
    job3_id = _submit_service_job_with_role_settle(
        batch, jobName=job3_name, jobQueue=queue_b, serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=_service_job_payload(ctx, job3_name, role_arn, bucket, 300),
    )
    for jid in (job1_id, job2_id, job3_id):
        ctx.on_cleanup(lambda jid=jid: _terminate_if_active(batch, jid))

    # Deterministically drive job1 to a terminal FAILED state; job2 and job3 stay active.
    batch.terminate_service_job(jobId=job1_id, reason="filter-test-termination")
    _poll_until(
        lambda: batch.describe_service_job(jobId=job1_id)["status"],
        lambda s: s == "FAILED",
        timeout_s=180,
    )
    job2_status_pre = batch.describe_service_job(jobId=job2_id)["status"]
    job3_status_pre = batch.describe_service_job(jobId=job3_id)["status"]
    assert job2_status_pre != "FAILED", f"expected job2 to stay non-FAILED, got {job2_status_pre!r}"
    assert job3_status_pre != "FAILED", f"expected job3 to stay non-FAILED, got {job3_status_pre!r}"

    # Queue A + FAILED -> exactly job1.
    resp_a_failed = batch.list_service_jobs(jobQueue=queue_a, jobStatus="FAILED")["jobSummaryList"]
    ids_a_failed = {j["jobId"] for j in resp_a_failed}
    assert ids_a_failed == {job1_id}, f"expected only job1 FAILED on queue A, got {ids_a_failed}"

    # Queue B + FAILED -> empty (job1's FAILED state must not leak across queues).
    resp_b_failed = batch.list_service_jobs(jobQueue=queue_b, jobStatus="FAILED")["jobSummaryList"]
    ids_b_failed = {j["jobId"] for j in resp_b_failed}
    assert job1_id not in ids_b_failed, f"job1 (queue A) leaked into queue B's FAILED filter: {ids_b_failed}"
    assert ids_b_failed == set(), f"expected no FAILED jobs on queue B yet, got {ids_b_failed}"

    # Queue A scoped to job2's actual current status returns job2 but not job1/job3.
    job2_status = batch.describe_service_job(jobId=job2_id)["status"]
    resp_a_current = batch.list_service_jobs(jobQueue=queue_a, jobStatus=job2_status)["jobSummaryList"]
    ids_a_current = {j["jobId"] for j in resp_a_current}
    assert job2_id in ids_a_current, f"expected job2 in queue A filtered by its own status {job2_status!r}, got {ids_a_current}"
    assert job1_id not in ids_a_current, f"job1 (FAILED) leaked into queue A's {job2_status!r} filter: {ids_a_current}"
    assert job3_id not in ids_a_current, f"job3 (queue B) leaked into queue A's filter: {ids_a_current}"


# ===== helpers =====

def _settled(fn: Callable[[], Any], timeout_s: float = 0.0):
    """Run a teardown call: a resource already gone is done, a ClientException is retried every
    2 s for timeout_s while a dependency releases, and every other failure raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] in ("NoSuchEntity", "NoSuchBucket") or "does not exist" in error.get("Message", ""):
                return None
            if error["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _terminate_if_active(batch, job_id: str) -> None:
    if batch.describe_service_job(jobId=job_id)["status"] not in ("SUCCEEDED", "FAILED"):
        _settled(lambda: batch.terminate_service_job(jobId=job_id, reason="test-cleanup"))


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sagemaker_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        _settled(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _settled(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"]["RoleName"],
        lambda name: name == role_name,
        timeout_s=30,
        interval_s=2,
    )
    return role_arn


def _submit_service_job_with_role_settle(batch, *, timeout_s=90.0, interval_s=5.0, **kwargs):
    """The just-created IAM role needs time to propagate before Batch can pass it to SageMaker;
    retry the submission itself on that specific failure."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return batch.submit_service_job(**kwargs)["jobId"]
        except ClientError as err:
            msg = err.response["Error"].get("Message", "")
            if "role" not in msg.lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"submit_service_job still rejecting the role after {timeout_s}s: {msg}"
                ) from err
            time.sleep(interval_s)


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-sm-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_sagemaker_queue(ctx) -> tuple[str, str]:
    batch = ctx.client("batch")
    env_name = ctx.unique_name("sim2real-svcenv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 4}],
        state="ENABLED",
        tags={"sim2real-check": CHECK},
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        _settled(lambda: batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED"), 180)
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _settled(lambda: batch.delete_service_environment(serviceEnvironment=env_arn), 180)

    ctx.on_cleanup(_cleanup_env)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
    )

    queue_name = ctx.unique_name("sim2real-svcq-")
    queue_arn = batch.create_job_queue(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_arn}],
        tags={"sim2real-check": CHECK},
    )["jobQueueArn"]

    def _cleanup_queue():
        _settled(lambda: batch.update_job_queue(jobQueue=queue_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _settled(lambda: batch.delete_job_queue(jobQueue=queue_arn), 90)

    ctx.on_cleanup(_cleanup_queue)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
    )
    return queue_arn, env_arn


def _service_job_payload(ctx, job_name: str, role_arn: str, bucket: str, max_runtime: int = 60) -> str:
    payload = {
        "TrainingJobName": job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "hello-world"],
        },
        "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": max_runtime},
    }
    return json.dumps(payload)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
