"""submit-service-job-progresses-to-running."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "submit-service-job-progresses-to-running"
GROUP = "service-job"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SAGEMAKER_TRAINING service job starts SUBMITTED, PENDING or RUNNABLE with its own jobId and
    jobName, then reaches RUNNING (or SUCCEEDED) unterminated with a capacityUsage quantity of at
    least 1 and a startedAt, per DescribeServiceJob."""
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    queue = _create_service_job_queue(ctx)
    # Real AWS Batch requires SAGEMAKER_TRAINING service jobs submitted to a job queue
    # bound to a quota-management scheduling policy to carry a quotaShareName; without
    # it, SubmitServiceJob is rejected outright with ClientException before a job is
    # ever created.
    qs_name = _create_quota_share(ctx, batch, queue["queue_name"])

    job_name = ctx.unique_name("sim2real-batch-sj-")
    training_job_name = job_name
    payload = _service_payload(role_arn, bucket, training_job_name, ctx.region, max_runtime=180)

    submitted = _submit_service_job_with_role_retry(
        batch,
        jobName=job_name,
        jobQueue=queue["queue_name"],
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=payload,
        quotaShareName=qs_name,
        # Real AWS Batch rejects SAGEMAKER_TRAINING service jobs submitted to a job
        # queue backed by a quota-management scheduling policy with ClientException
        # ("Job without schedulingPriority cannot be submitted to a job queue with a
        # ... scheduling policy") unless schedulingPriority is supplied.
        schedulingPriority=10,
        timeoutConfig={"attemptDurationSeconds": 900},
    )
    job_id = submitted["jobId"]
    ctx.on_cleanup(lambda: _safe_terminate_service_job(batch, job_id))

    first = batch.describe_service_job(jobId=job_id)
    assert first["status"] in ("SUBMITTED", "PENDING", "RUNNABLE"), (
        f"expected a non-terminal initial status, got {first['status']!r}"
    )
    # Real DescribeServiceJob omits the "isTerminated" field entirely while a job is
    # not terminated (it is only populated once the job actually terminates), so a
    # missing key is equivalent to False rather than a defect.
    assert first.get("isTerminated", False) is False, (
        f"expected isTerminated False/absent on a fresh job, got {first.get('isTerminated')!r}"
    )
    assert first["jobId"] == job_id, f"expected jobId {job_id!r}, got {first['jobId']!r}"
    assert first["jobName"] == job_name, f"expected jobName {job_name!r}, got {first['jobName']!r}"

    try:
        running = _poll_until(
            lambda: batch.describe_service_job(jobId=job_id),
            lambda d: d["status"] in ("RUNNING", "SUCCEEDED"),
            timeout_s=600,
            interval_s=10,
            fail_states={"FAILED"},
        )
    except _JobFailed as exc:
        raise AssertionError(f"service job unexpectedly went FAILED before RUNNING: {exc}") from exc
    except AssertionError:
        raise AssertionError(
            "SageMaker Training instance did not reach RUNNING within the poll budget "
            "(provisioning-time variability, not a Batch state-machine defect)",
        )

    assert running["status"] in ("RUNNING", "SUCCEEDED"), (
        f"expected RUNNING or SUCCEEDED after the poll, got {running['status']!r}"
    )
    if running["status"] == "RUNNING":
        assert running.get("isTerminated", False) is False, (
            f"expected isTerminated False while RUNNING, got {running.get('isTerminated')!r}"
        )
        usage = running.get("capacityUsage") or []
        assert usage, "expected non-empty capacityUsage once the service job is RUNNING"
        assert usage[0]["quantity"] >= 1, f"expected capacityUsage quantity >= 1, got {usage[0]['quantity']!r}"
        assert running.get("startedAt") is not None, "expected a server-assigned startedAt once RUNNING"


from botocore.exceptions import ClientError

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


class _JobFailed(Exception):
    pass


def _submit_service_job_with_role_retry(batch, *, timeout_s=60.0, interval_s=5.0, **kwargs):
    """Cross-service IAM propagation: the role/policy attachment can take a few seconds to
    become visible to Batch's own role-usability check, so the submission is retried on that
    specific rejection."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return batch.submit_service_job(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            message = exc.response.get("Error", {}).get("Message", "")
            if code != "ClientException" or "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0, fail_states=frozenset()):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if fail_states and last.get("status") in fail_states:
            raise _JobFailed(last.get("statusReason"))
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _safe_terminate_service_job(batch, job_id):
    batch.terminate_service_job(jobId=job_id, reason="sim2real-integration-test-cleanup")


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role_arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-smout-")
    if ctx.region == "us-east-1":
        # us-east-1 is CreateBucket's one region-literal exception: passing a
        # LocationConstraint there is itself rejected, so it must be omitted.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup_bucket():
        try:
            resp = s3.list_objects_v2(Bucket=bucket)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)
    return bucket


def _service_payload(role_arn, bucket, training_job_name, region, max_runtime=180):
    return json.dumps(
        {
            "TrainingJobName": training_job_name,
            "RoleArn": role_arn,
            "AlgorithmSpecification": {
                "TrainingInputMode": "File",
                "TrainingImage": f"763104351884.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.1.0-cpu-py310",
                "ContainerEntrypoint": ["sleep", str(max_runtime + 60)],
            },
            "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
            "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
            "StoppingCondition": {"MaxRuntimeInSeconds": max_runtime},
        }
    )


def _create_service_job_queue(ctx):
    batch = ctx.client("batch")

    # A SAGEMAKER_TRAINING service environment declares capacityLimits, which makes it
    # "Quota Management compatible" -- real AWS Batch then requires the job queue that
    # references it to carry a schedulingPolicyArn (a quota-management scheduling
    # policy); CreateJobQueue is rejected with ClientException otherwise.
    policy_name = ctx.unique_name("sim2real-batch-qsp-")
    policy_arn = batch.create_scheduling_policy(
        name=policy_name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags=_MANAGED_TAGS,
    )["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: batch.delete_scheduling_policy(arn=policy_arn)))

    env_name = ctx.unique_name("sim2real-batch-senv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 5}],
        tags=_MANAGED_TAGS,
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        try:
            batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED")
            for _ in range(40):
                d = batch.describe_service_environments(serviceEnvironments=[env_arn])
                if d["serviceEnvironments"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(3)
            batch.delete_service_environment(serviceEnvironment=env_arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup_env)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0],
        lambda e: e["status"] == "VALID",
        timeout_s=120,
    )

    queue_name = ctx.unique_name("sim2real-batch-sjq-")
    queue_arn = batch.create_job_queue(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"serviceEnvironment": env_arn, "order": 1}],
        schedulingPolicyArn=policy_arn,
        tags=_MANAGED_TAGS,
    )["jobQueueArn"]

    def _cleanup_queue():
        try:
            batch.update_job_queue(jobQueue=queue_arn, state="DISABLED")
            for _ in range(40):
                d = batch.describe_job_queues(jobQueues=[queue_arn])
                if d["jobQueues"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(3)
            batch.delete_job_queue(jobQueue=queue_arn)
            # DeleteJobQueue is asynchronous; the service-environment and scheduling-policy
            # deletes that run next (LIFO) are refused while the queue still references them.
            deadline = time.monotonic() + 180.0
            while batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"]:
                if time.monotonic() > deadline:
                    raise AssertionError("job queue still present 180s after its delete")
                time.sleep(5)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup_queue)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0],
        lambda q: q["status"] == "VALID",
        timeout_s=120,
    )
    return {"env_arn": env_arn, "queue_name": queue_name, "queue_arn": queue_arn}


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_quota_share(ctx, batch, queue_name, *, max_capacity=5):
    qs_name = ctx.unique_name("sim2real-batch-qs-")
    qs_arn = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=queue_name,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=_MANAGED_TAGS,
    )["quotaShareArn"]
    ctx.on_cleanup(lambda: _safe_delete_quota_share(batch, qs_arn))
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=180,
    )
    return qs_name


def _safe_delete_quota_share(batch, arn):
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    for _ in range(20):
        try:
            desc = batch.describe_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
            return
        if desc.get("status") == "VALID":
            break
        time.sleep(3)
    try:
        batch.delete_quota_share(quotaShareArn=arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and "does not exist" in err.get("Message", "")
        ):
            raise
    # DeleteQuotaShare is async: the job queue's cleanup runs right after this (LIFO) and
    # fails with "found existing QuotaShare relationship" unless we wait for the relationship
    # to actually clear first.
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            batch.describe_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            raise
        time.sleep(3)
    raise AssertionError("quota share still present 120s after DeleteQuotaShare")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
