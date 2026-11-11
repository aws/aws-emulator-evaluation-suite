"""service-job-lifecycle-state-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-job-lifecycle-state-transitions"
GROUP = "state-machine"
SERVICES = ["batch"]


#: A SageMaker training service job's provisioning, run and teardown on AWS.
JOB_TIMEOUT_S = 900.0
#: How long the teardown waits for SageMaker to file the training job's trial component.
TRIAL_COMPONENT_TIMEOUT_S = 240.0

_ORDER = ["SUBMITTED", "PENDING", "RUNNABLE", "SCHEDULED", "STARTING", "RUNNING", "SUCCEEDED", "FAILED"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-svcjob"}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A submitted service job's DescribeServiceJob status never regresses in the documented
    lifecycle order, is first read in a pre-RUNNING status and ends SUCCEEDED with isTerminated false and its own
    jobName: Batch drives every transition."""
    # A SageMaker Training service job commonly needs several minutes just to provision and
    # start, so this check bounds its own polling, measured from the start of run().
    run_start = time.monotonic()
    left = ctx.time_left()
    cap_s = JOB_TIMEOUT_S if left is None else max(1.0, min(JOB_TIMEOUT_S, left - 5.0))

    batch = ctx.client("batch")
    role_arn = _create_sagemaker_execution_role(ctx)
    bucket = _create_output_bucket(ctx)
    queue_arn, _env_arn = _create_sagemaker_queue(ctx)

    job_name = ctx.unique_name("sim2real-svcjob-")
    payload = _service_job_payload(ctx, job_name, role_arn, bucket, max_runtime=90)
    job_id = batch.submit_service_job(
        jobName=job_name,
        jobQueue=queue_arn,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=payload,
        schedulingPriority=1,
        # The queue has a fairshare scheduling policy attached, and real AWS Batch
        # requires every job submitted to such a queue to carry a shareIdentifier.
        shareIdentifier="default",
        tags=dict(_MANAGED_TAGS),
    )["jobId"]
    # Batch runs the service job as a SageMaker training job, and SageMaker files a trial
    # component for it; both outlive the service job. Registered before the terminate below,
    # so LIFO stops the job first and this waits for it to end.
    ctx.on_cleanup(lambda: _delete_sagemaker_training_artifacts(ctx, batch, job_id))
    ctx.on_cleanup(lambda: _best_effort(lambda: batch.terminate_service_job(jobId=job_id, reason="test-cleanup")))

    observed: list[str] = []
    terminal = None
    while time.monotonic() - run_start < cap_s:
        status = batch.describe_service_job(jobId=job_id)["status"]
        if not observed or observed[-1] != status:
            observed.append(status)
            # Monotonic: each newly observed status must not regress before the previous one
            # in the documented lifecycle ordering.
            prev_idx = _ORDER.index(observed[-2]) if len(observed) > 1 else -1
            cur_idx = _ORDER.index(status)
            assert cur_idx >= prev_idx, f"status regressed: {observed}"
        if status in ("SUCCEEDED", "FAILED"):
            terminal = status
            break
        time.sleep(2.0)

    if terminal is None:
        elapsed = round(time.monotonic() - run_start, 1)
        if cap_s < JOB_TIMEOUT_S:
            raise TimeoutError(
                f"the check's time budget ran out after {elapsed}s, before the "
                f"{JOB_TIMEOUT_S:.0f}s wait for a terminal service-job state ended; "
                f"observed={observed}; not graded"
            )
        raise AssertionError(
            f"service job did not reach a terminal state within the {elapsed}s check budget; "
            f"observed={observed}",
        )

    if terminal == "FAILED":
        reason = batch.describe_service_job(jobId=job_id).get("statusReason", "")
        raise AssertionError(
            f"service job ended FAILED (likely SageMaker training-capacity/quota constraint "
            f"in this account, not a Batch defect): {reason}"
        )

    # The first read lands after SubmitServiceJob returns, so a scheduler may already have
    # advanced the job past SUBMITTED; it is graded as a pre-RUNNING status.
    assert observed[0] in ("SUBMITTED", "PENDING", "RUNNABLE", "SCHEDULED"), (
        f"lifecycle did not start in a pre-RUNNING status: observed={observed}"
    )
    assert observed[-1] == "SUCCEEDED", f"lifecycle did not end at SUCCEEDED: observed={observed}"
    final = batch.describe_service_job(jobId=job_id)
    # Real AWS Batch omits the isTerminated boolean from DescribeServiceJob when it is
    # False (rather than always including it), so default to False when absent.
    assert final.get("isTerminated", False) is False, (
        f"expected isTerminated False for a SUCCEEDED job, got {final.get('isTerminated')!r}"
    )
    assert final["jobName"] == job_name, (
        f"expected jobName {job_name!r} on the independent DescribeServiceJob read, "
        f"got {final['jobName']!r}"
    )


def _best_effort(fn: Callable[[], Any]) -> None:
    """Run a teardown call; a not-found answer counts as done and every other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "NoSuchEntity"
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _sagemaker_not_found(exc: ClientError) -> bool:
    """SageMaker answers a not-found target with the ResourceNotFound shape on some operations
    (trial, trial component) and a ValidationException reading "...resource not found..." on
    others (training job); treat both as the same condition."""
    err = exc.response["Error"]
    return err["Code"] == "ResourceNotFound" or "not found" in err.get("Message", "").lower()


def _disassociate_trial_component(sm, trial_component_name: str) -> None:
    """A trial component must be disassociated from every trial it belongs to before it can be
    deleted."""
    for trial in sm.list_trials(TrialComponentName=trial_component_name).get("TrialSummaries", []):
        try:
            sm.disassociate_trial_component(TrialComponentName=trial_component_name, TrialName=trial["TrialName"])
        except ClientError as exc:
            if not _sagemaker_not_found(exc):
                raise


def _delete_sagemaker_training_artifacts(ctx, batch, job_id: str) -> None:
    """Delete the SageMaker training job a service job ran as, and the trial component for it.

    A service job that never started a training job leaves nothing. The trial component appears
    asynchronously once the training job ends, and must leave its trials before it deletes.
    """
    attempt = batch.describe_service_job(jobId=job_id).get("latestAttempt") or {}
    arn = (attempt.get("serviceResourceId") or {}).get("value")
    if not arn:
        return
    sm = ctx.client("sagemaker")
    name = arn.rsplit("/", 1)[-1]
    deadline = time.monotonic() + TRIAL_COMPONENT_TIMEOUT_S
    while True:
        try:
            ended = sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"] in (
                "Completed", "Failed", "Stopped",
            )
        except ClientError as exc:
            if _sagemaker_not_found(exc):
                return
            raise
        components = [
            c["TrialComponentName"]
            for c in sm.list_trial_components(SourceArn=arn).get("TrialComponentSummaries", [])
        ]
        if (ended and components) or time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    for component in components:
        _disassociate_trial_component(sm, component)
        try:
            sm.delete_trial_component(TrialComponentName=component)
        except ClientError as exc:
            if not _sagemaker_not_found(exc):
                raise
    try:
        sm.delete_training_job(TrainingJobName=name)
    except ClientError as exc:
        if not _sagemaker_not_found(exc):
            raise


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv()
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        _best_effort(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _best_effort(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    # Bounded retry over IAM propagation before SageMaker assumes this role: wait until
    # IAM's own read of the attachment reflects it, rather than sleeping a fixed amount.
    _poll_until(
        lambda: iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        lambda policies: any(p["PolicyArn"] == policy_arn for p in policies),
        timeout_s=30.0,
        interval_s=2.0,
    )
    return role_arn


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-sm-out-").lower().replace("_", "-")
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 specifically
    # (the API's original region); every other region requires one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_sagemaker_queue(ctx) -> tuple[str, str]:
    batch = ctx.client("batch")

    # AWS Batch rejects SubmitServiceJob calls that set schedulingPriority/shareIdentifier
    # against a queue that has no scheduling policy attached, so attach a minimal
    # fair-share policy to the queue below.
    policy_name = ctx.unique_name("sim2real-svcschedpol-")
    policy_arn = batch.create_scheduling_policy(
        name=policy_name,
        fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
        tags=dict(_MANAGED_TAGS),
    )["arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: batch.delete_scheduling_policy(arn=policy_arn)))

    env_name = ctx.unique_name("sim2real-svcenv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 4}],
        state="ENABLED",
        tags=dict(_MANAGED_TAGS),
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        _best_effort(lambda: batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _best_effort(lambda: batch.delete_service_environment(serviceEnvironment=env_arn))

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
        schedulingPolicyArn=policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_arn}],
        tags=dict(_MANAGED_TAGS),
    )["jobQueueArn"]

    def _cleanup_queue():
        _best_effort(lambda: batch.update_job_queue(jobQueue=queue_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _best_effort(lambda: batch.delete_job_queue(jobQueue=queue_arn))
        # DeleteJobQueue only schedules the deletion; the service environment and
        # scheduling policy this queue references cannot delete while Batch still sees
        # it, so wait for it to actually disappear rather than just for the call to return.
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"],
            lambda queues: not queues,
            timeout_s=180.0,
        )

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
