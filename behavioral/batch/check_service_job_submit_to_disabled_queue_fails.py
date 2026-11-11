"""service-job-submit-to-disabled-queue-fails."""

from __future__ import annotations
import json
import time
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "service-job-submit-to-disabled-queue-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "NoSuchEntity"
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _client_error(fn):
    """Call fn() expecting an AWS refusal; return its (Error.Code, Error.Message).

    A call that SUCCEEDS raises AssertionError: an emulator accepting input real AWS refuses
    must fail loudly, not read as a missing code."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _role_readable(iam, role_name):
    """True once IAM serves the role back; False while GetRole still answers NoSuchEntity."""
    try:
        iam.get_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return False
        raise
    return True


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _wait_jq_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _wait_jq_state(bat, name, state, timeout_s=90, interval_s=4):
    """Wait until the queue has *settled* into `state` (not just any settled status) -- avoids
    racing the assertion against an in-flight UPDATING transition."""
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") == "VALID" and jq.get("state") == state,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} settled with state={state}",
    )


def _describe_se(bat, name):
    envs = bat.describe_service_environments(serviceEnvironments=[name]).get(
        "serviceEnvironments", []
    )
    return envs[0] if envs else None


def _wait_se_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_se(bat, name),
        lambda se: se is not None and se.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"service environment {name} status in {sorted(statuses)}",
    )


def _teardown_jq(ctx, bat, name, teardown_deadline):
    """Disable a job queue, wait for it to settle, then delete it (best-effort)."""
    try:
        bat.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=60)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _swallow(lambda: _retry_in_use(ctx, lambda: bat.delete_job_queue(jobQueue=name), teardown_deadline))


def _teardown_se(ctx, bat, name, teardown_deadline):
    """Disable a service environment then delete it (best-effort)."""
    _swallow(lambda: bat.update_service_environment(serviceEnvironment=name, state="DISABLED"))
    _swallow(lambda: _retry_in_use(
        ctx, lambda: bat.delete_service_environment(serviceEnvironment=name), teardown_deadline))


def _create_service_environment(ctx, bat, teardown_deadline, name=None, max_capacity=4, state="ENABLED"):
    name = name or ctx.unique_name("sim2real-behav-se-")
    resp = bat.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        state=state,
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": "NUM_INSTANCES"}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_se(ctx, bat, name, teardown_deadline))
    _wait_se_status(bat, name, {"VALID", "INVALID"})
    return name, resp["serviceEnvironmentArn"]


def _create_service_job_queue(
    ctx, bat, se_arn, teardown_deadline, name=None, priority=1, state="ENABLED", scheduling_policy_arn=None
):
    name = name or ctx.unique_name("sim2real-behav-sjq-")
    kwargs = dict(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        state=state,
        priority=priority,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        tags=_MANAGED_TAGS,
    )
    if scheduling_policy_arn:
        kwargs["schedulingPolicyArn"] = scheduling_policy_arn
    resp = bat.create_job_queue(**kwargs)
    ctx.on_cleanup(lambda: _teardown_jq(ctx, bat, name, teardown_deadline))
    _wait_jq_status(bat, name, {"VALID", "INVALID"})
    return name, resp["jobQueueArn"]


def _create_sagemaker_role(ctx):
    """A minimal SageMaker execution role, real enough for Batch to accept a
    SAGEMAKER_TRAINING service job submission (not necessarily for training to complete --
    the check terminates each accepted job as soon as acceptance is confirmed)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sm-role-")
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
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    _poll_until(
        lambda: _role_readable(iam, role_name),
        lambda readable: readable,
        timeout_s=30,
        interval_s=2,
        description=f"role {role_name} readable back from IAM",
    )
    return role_arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-sm-")
    if ctx.region == "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint for us-east-1 -- this is an
        # S3 API quirk, not a pin of the check's own target region (which follows ctx.region
        # throughout).
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup_bucket():
        try:
            for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)
    return bucket


def _service_payload(role_arn, bucket, training_job_name, region):
    return json.dumps(
        {
            "TrainingJobName": training_job_name,
            "RoleArn": role_arn,
            "AlgorithmSpecification": {
                "TrainingInputMode": "File",
                "TrainingImage": f"123456789012.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.1.0-cpu-py310",
                "ContainerEntrypoint": ["sleep", "240"],
            },
            "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
            "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
            "StoppingCondition": {"MaxRuntimeInSeconds": 180},
        }
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitServiceJob to a DISABLED queue must be rejected, not silently queued -- and the
    rejection is state-gated, not systemic: the identical submission is accepted both before the
    queue is disabled (positive control) and again once it is re-enabled (restore)."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    bat = ctx.client("batch")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    _se_name, se_arn = _create_service_environment(ctx, bat, teardown_deadline, state="ENABLED")
    jq_name, jq_arn = _create_service_job_queue(ctx, bat, se_arn, teardown_deadline, priority=1, state="ENABLED")

    def _submit(job_name):
        payload = _service_payload(role_arn, bucket, job_name, ctx.region)
        return bat.submit_service_job(
            jobName=job_name,
            jobQueue=jq_name,
            serviceJobType="SAGEMAKER_TRAINING",
            serviceRequestPayload=payload,
        )

    def _submit_expect_accepted(job_name, *, when, max_attempts=12, interval_s=5):
        # A just-created IAM role is not instantly assumable by SageMaker/Batch: retry a bounded
        # number of times on that specific, named transient condition, not on any ClientError, so
        # a genuine rejection still fails immediately.
        resp = None
        for attempt in range(max_attempts):
            try:
                resp = _submit(job_name)
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                message = exc.response.get("Error", {}).get("Message", "")
                if code == "AccessDeniedException":
                    raise AssertionError(
                        "service-job API (SubmitServiceJob) not permitted on this account"
                    ) from exc
                role_not_ready = "role" in message.lower() and (
                    "assume" in message.lower() or "not authorized" in message.lower()
                )
                if role_not_ready and attempt < max_attempts - 1:
                    time.sleep(interval_s)
                    continue
                raise AssertionError(
                    f"expected the submission {when} to succeed, got ClientError code={code!r} message={message!r}"
                ) from exc
        job_id = resp["jobId"]
        ctx.on_cleanup(
            lambda: _swallow(lambda: bat.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-cleanup"))
        )
        described = bat.describe_service_job(jobId=job_id)
        assert described["status"] in ("SUBMITTED", "PENDING", "RUNNABLE"), (
            f"expected the submission {when} to be accepted, got status={described['status']!r}"
        )
        assert described["jobId"] == job_id, (
            f"expected the submission {when} to be described under {job_id!r}, got {described['jobId']!r}"
        )
        assert described["jobName"] == job_name, (
            f"expected the submission {when} to be named {job_name!r}, got {described['jobName']!r}"
        )
        return job_id

    # Positive control: the queue is ENABLED, so an ordinary submission must be accepted.
    _submit_expect_accepted(ctx.unique_name("sjob-control-"), when="to an ENABLED queue (positive control)")

    # Break exactly one thing: disable the queue.
    bat.update_job_queue(jobQueue=jq_name, state="DISABLED")
    _wait_jq_state(bat, jq_name, "DISABLED")

    rejected_name = ctx.unique_name("sjob-rejected-")
    code, message = _client_error(lambda: _submit(rejected_name))
    if code == "AccessDeniedException":
        raise AssertionError("service-job API (SubmitServiceJob) not permitted on this account")
    assert code == "ClientException", (
        f"expected ClientException submitting a service job to a DISABLED queue, got {code!r}"
    )
    expected_message = f"JobQueue {jq_arn} not ENABLED."
    assert message == expected_message, (
        f"expected message {expected_message!r} submitting to a DISABLED queue, got {message!r}"
    )

    listed = bat.list_service_jobs(
        jobQueue=jq_name, filters=[{"name": "JOB_NAME", "values": [rejected_name]}]
    ).get("jobSummaryList", [])
    assert listed == [], f"a rejected submission must not appear in the queue, got {listed}"

    # Restore: re-enable the queue, and the identical call succeeds again.
    bat.update_job_queue(jobQueue=jq_name, state="ENABLED")
    _wait_jq_state(bat, jq_name, "ENABLED")

    _submit_expect_accepted(ctx.unique_name("sjob-restored-"), when="once the queue is re-ENABLED (restore)")


#: The suite's cleanup budget; the retries of every teardown of one run share one deadline in it.
_CLEANUP_BUDGET_S = 900.0


def _retry_in_use(ctx, delete, teardown_deadline) -> None:
    """Run a Batch delete, retrying the "found existing ... relationship" refusal every 2 s to the
    run's cleanup deadline while a dependent finishes deleting; "does not exist" is gone."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_BUDGET_S)
    while True:
        try:
            delete()
            return
        except ClientError as err:
            e = err.response["Error"]
            if e["Code"] == "ClientException" and "does not exist" in e.get("Message", ""):
                return
            in_use = e["Code"] == "ClientException" and "found existing" in e.get("Message", "")
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
