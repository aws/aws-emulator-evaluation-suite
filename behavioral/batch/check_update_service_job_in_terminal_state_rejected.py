"""update-service-job-in-terminal-state-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-service-job-in-terminal-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceJob against a service job already in a terminal state (reached via
    TerminateServiceJob) is rejected with ClientException rather than silently applied."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    se_name = _create_service_environment(ctx, teardown_deadline)
    sp_arn = _create_scheduling_policy(ctx, teardown_deadline)
    jq_arn, _jq_name = _create_job_queue(ctx, se_name, teardown_deadline, scheduling_policy_arn=sp_arn)
    qs_arn, qs_name = _create_quota_share(ctx, jq_arn)
    role_arn = _create_sagemaker_execution_role(ctx)

    job1_name = ctx.unique_name("sim2real-batch-sj-")
    resp1 = _submit_service_job(batch, job1_name, jq_arn, qs_name, _training_payload(ctx, role_arn))
    job1_id = resp1["jobId"]

    batch.terminate_service_job(jobId=job1_id, reason="sim2real-behavioral-terminate")
    terminal = _poll_until(
        lambda: batch.describe_service_job(jobId=job1_id),
        lambda job: job["status"] in ("FAILED", "SUCCEEDED"),
        timeout_s=180,
        interval_s=5,
    )
    assert terminal["status"] == "FAILED", f"expected FAILED after TerminateServiceJob, got {terminal['status']}"
    prior_priority = terminal["schedulingPriority"]
    assert prior_priority == 1, f"expected the submitted schedulingPriority of 1, got {prior_priority!r}"

    error = _error(lambda: batch.update_service_job(jobId=job1_id, schedulingPriority=99))
    code, message = error.get("Code"), error.get("Message")
    assert code == "ClientException", f"expected ClientException, got {code}"
    assert message == "UpdateServiceJob cannot be called on a service job which is completed.", f"expected the exact terminal-job update refusal message, got {message!r}"

    unchanged = batch.describe_service_job(jobId=job1_id)
    assert unchanged["schedulingPriority"] == prior_priority, (
        f"UpdateServiceJob must not have applied its schedulingPriority to a terminal service job: "
        f"expected {prior_priority!r}, got {unchanged['schedulingPriority']!r}"
    )

    # positive control: the same call succeeds against a non-terminal service job
    job2_name = ctx.unique_name("sim2real-batch-sj-")
    resp2 = _submit_service_job(batch, job2_name, jq_arn, qs_name, _training_payload(ctx, role_arn))
    job2_id = resp2["jobId"]
    ctx.on_cleanup(lambda: _terminate_quietly(batch, job2_id))

    before = batch.describe_service_job(jobId=job2_id)
    assert before["status"] not in ("FAILED", "SUCCEEDED"), "control job unexpectedly already terminal"
    updated = batch.update_service_job(jobId=job2_id, schedulingPriority=42)
    assert updated["jobId"] == job2_id, f"expected UpdateServiceJob response jobId {job2_id!r}, got {updated['jobId']!r}"
    after = batch.describe_service_job(jobId=job2_id)
    assert after["schedulingPriority"] == 42, f"expected schedulingPriority 42 after update, got {after['schedulingPriority']!r}"


from botocore.exceptions import ClientError

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_service_environment(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m6i.large"}],
        tags=_MANAGED_TAGS,
    )

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
            _poll_until(
                lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
                lambda se: se["state"] == "DISABLED",
                timeout_s=90,
            )
            _retry_in_use(ctx, lambda: batch.delete_service_environment(serviceEnvironment=name), teardown_deadline)
            _poll_until(
                lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"],
                lambda ses: len(ses) == 0,
                timeout_s=150,
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
        timeout_s=90,
    )
    return name


def _create_scheduling_policy(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    resp = batch.create_scheduling_policy(
        name=name, quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"}, tags=_MANAGED_TAGS
    )
    arn = resp["arn"]

    def _cleanup():
        _retry_in_use(ctx, lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_job_queue(ctx, service_environment_name, teardown_deadline, scheduling_policy_arn=None, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    kwargs = dict(
        jobQueueName=name,
        priority=priority,
        jobQueueType="SAGEMAKER_TRAINING",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
    )
    if scheduling_policy_arn:
        kwargs["schedulingPolicyArn"] = scheduling_policy_arn
    kwargs["tags"] = _MANAGED_TAGS
    resp = batch.create_job_queue(**kwargs)
    arn = resp["jobQueueArn"]

    def _cleanup():
        try:
            batch.update_job_queue(jobQueue=arn, state="DISABLED")
            _poll_until(
                lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0],
                lambda jq: jq["state"] == "DISABLED",
                timeout_s=90,
            )
            _retry_in_use(ctx, lambda: batch.delete_job_queue(jobQueue=arn), teardown_deadline)
            _poll_until(
                lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
                lambda jqs: len(jqs) == 0,
                timeout_s=180,
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=90,
    )
    return arn, name


def _create_quota_share(ctx, job_queue_arn, max_capacity=2, capacity_unit="ml.m6i.large"):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qs-")
    resp = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=job_queue_arn,
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": capacity_unit}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags=_MANAGED_TAGS,
    )
    arn = resp["quotaShareArn"]

    def _cleanup():
        try:
            batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
            _poll_until(
                lambda: batch.describe_quota_share(quotaShareArn=arn),
                lambda qs: qs["state"] == "DISABLED",
                timeout_s=90,
            )
            batch.delete_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=arn),
        lambda qs: qs["status"] == "VALID",
        timeout_s=90,
    )
    return arn, name



def _create_sagemaker_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
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
    return role_arn


def _training_payload(ctx, role_arn):
    name = ctx.unique_name("sim2real-batch-training-")
    payload = {
        "TrainingJobName": name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": "123456789012.dkr.ecr.us-west-2.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "hello world"],
        },
        "ResourceConfig": {
            "InstanceType": "ml.m6i.large",
            "InstanceCount": 1,
            "VolumeSizeInGB": 1,
        },
        "OutputDataConfig": {"S3OutputPath": "s3://sim2real-batch-behavioral-dummy/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 60},
    }
    return json.dumps(payload)


def _submit_service_job(batch, job_name, job_queue_arn, quota_share_name, payload_json, timeout_s=90.0):
    # A freshly created IAM role can take a few seconds to propagate before Batch/SageMaker
    # can validate/assume it; retry ClientException submissions within a bounded window.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return batch.submit_service_job(
                jobName=job_name,
                jobQueue=job_queue_arn,
                serviceJobType="SAGEMAKER_TRAINING",
                quotaShareName=quota_share_name,
                schedulingPriority=1,
                serviceRequestPayload=payload_json,
                retryStrategy={"attempts": 1},
                timeoutConfig={"attemptDurationSeconds": 60},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ClientException":
                raise
            last_exc = e
            time.sleep(5)
    raise last_exc



def _terminate_quietly(batch, job_id):
    batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-cleanup")


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
