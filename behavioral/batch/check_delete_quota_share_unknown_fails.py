"""delete-quota-share-unknown-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-quota-share-unknown-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQuotaShare and DescribeQuotaShare raise ClientException for a malformed quota-share ARN.

    A real quota share is the control: both calls work on it, and once deleted it gives the same refusal.
    """
    batch = ctx.client("batch")
    stack = _create_quota_managed_job_queue(ctx)
    real_arn = _create_quota_share(ctx, stack["job_queue_arn"])
    described = _wait_quota_share_status(batch, real_arn, {"VALID"})

    # Positive control: describe on a real, well-formed ARN succeeds.
    assert described["quotaShareArn"] == real_arn, (
        f"positive-control describe returned wrong arn: {described.get('quotaShareArn')!r}"
    )

    fake_arn = _malformed_quota_share_arn(ctx)

    # Batch embeds the call's own request id in this message.
    code, message, request_id = _error_code(lambda: batch.delete_quota_share(quotaShareArn=fake_arn))
    assert code == "ClientException", (
        f"expected ClientException deleting a malformed quota share arn, got {code!r}"
    )
    expected = _malformed_arn_message(request_id)
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    describe_code, describe_message, describe_request_id = _error_code(
        lambda: batch.describe_quota_share(quotaShareArn=fake_arn)
    )
    assert describe_code == "ClientException", (
        f"malformed quota share arn became describable after a failed delete: {describe_code!r}"
    )
    expected_describe = _malformed_arn_message(describe_request_id)
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    # Effect absent: the real quota share is untouched by the malformed-arn calls.
    unaffected = batch.describe_quota_share(quotaShareArn=real_arn)
    assert unaffected["state"] == described["state"], (
        f"real quota share state changed after unrelated malformed-arn calls: "
        f"{unaffected['state']!r} != {described['state']!r}"
    )

    # Positive control on delete: disable then delete the real share succeeds.
    batch.update_quota_share(quotaShareArn=real_arn, state="DISABLED")
    _wait_quota_share_status(batch, real_arn, {"VALID"})
    batch.delete_quota_share(quotaShareArn=real_arn)
    _wait_quota_share_deleted(batch, real_arn)

    # A mutation on the deleted id also fails, with the same specific code.
    update_code, update_message, _ = _error_code(
        lambda: batch.update_quota_share(quotaShareArn=real_arn, state="ENABLED")
    )
    assert update_code == "ClientException", (
        f"expected ClientException updating a deleted quota share, got {update_code!r}"
    )
    expected_gone = f"{real_arn} does not exist."
    assert update_message == expected_gone, f"expected message {expected_gone!r}, got {update_message!r}"


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it raises. An
    unexpected success raises AssertionError."""
    try:
        fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


def _malformed_arn_message(request_id: str) -> str:
    return (
        "Error executing request, Exception : Quota Share arn should match a valid Quota Share "
        f"arn pattern, RequestId: {request_id}"
    )


def _malformed_quota_share_arn(ctx) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-qs-")
    return f"arn:aws:batch:{ctx.region}:{account_id}:quota-share/{name}"


def _wait_quota_share_status(batch, arn, target_statuses, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = batch.describe_quota_share(quotaShareArn=arn)
        if last["status"] in target_statuses:
            return last
        if last["status"] == "INVALID":
            raise AssertionError(f"quota share became INVALID: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"quota share never reached {target_statuses}, last={last}")


def _wait_quota_share_deleted(batch, arn, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            batch.describe_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ClientException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("quota share was not reported not-found after delete")


def _best_effort_delete_quota_share(ctx, arn):
    batch = ctx.client("batch")
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            batch.describe_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
            return
        batch.delete_quota_share(quotaShareArn=arn)
        time.sleep(3)


def _create_quota_share(ctx, job_queue_arn):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qs-")
    arn = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=job_queue_arn,
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"env": "sim2real-behav"},
    )["quotaShareArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_quota_share(ctx, arn))
    return arn


def _wait_service_environment_valid(ctx, arn, timeout_s=180.0, interval_s=3.0):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = batch.describe_service_environments(serviceEnvironments=[arn])
        envs = resp.get("serviceEnvironments", [])
        if envs:
            status = envs[0]["status"]
            if status == "VALID":
                return envs[0]
            if status == "INVALID":
                raise AssertionError(f"service environment became INVALID: {envs[0]}")
        time.sleep(interval_s)
    raise AssertionError("service environment did not reach VALID in time")


def _wait_job_queue_valid(ctx, arn, timeout_s=180.0, interval_s=3.0):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = batch.describe_job_queues(jobQueues=[arn])
        queues = resp.get("jobQueues", [])
        if queues:
            status = queues[0]["status"]
            if status == "VALID":
                return queues[0]
            if status == "INVALID":
                raise AssertionError(f"job queue became INVALID: {queues[0]}")
        time.sleep(interval_s)
    raise AssertionError("job queue did not reach VALID in time")


def _retry_refused(call, *, timeout_s=60):
    """Run a Batch teardown call, where "does not exist" means already gone.

    Batch answers ClientException while a dependency drains: retry that every 2 s, then raise.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return None
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete_scheduling_policy(ctx, arn):
    batch = ctx.client("batch")
    _retry_refused(lambda: batch.delete_scheduling_policy(arn=arn))


def _create_quota_managed_job_queue(ctx):
    batch = ctx.client("batch")
    sp_name = ctx.unique_name("sim2real-batch-sp-")
    sp = batch.create_scheduling_policy(
        name=sp_name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"env": "sim2real-behav"},
    )
    sp_arn = sp["arn"]
    ctx.on_cleanup(lambda: _safe_delete_scheduling_policy(ctx, sp_arn))

    se_name = ctx.unique_name("sim2real-batch-se-")
    se = batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m5.large"}],
        tags={"env": "sim2real-behav"},
    )
    se_arn = se["serviceEnvironmentArn"]

    def _cleanup_se():
        try:
            batch.update_service_environment(serviceEnvironment=se_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _retry_refused(lambda: batch.delete_service_environment(serviceEnvironment=se_arn), timeout_s=90)

    ctx.on_cleanup(_cleanup_se)
    _wait_service_environment_valid(ctx, se_arn)

    jq_name = ctx.unique_name("sim2real-batch-jq-")
    jq = batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        jobQueueType="SAGEMAKER_TRAINING",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        schedulingPolicyArn=sp_arn,
        tags={"env": "sim2real-behav"},
    )
    jq_arn = jq["jobQueueArn"]

    def _cleanup_jq():
        try:
            batch.update_job_queue(jobQueue=jq_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _retry_refused(lambda: batch.delete_job_queue(jobQueue=jq_arn), timeout_s=90)

    ctx.on_cleanup(_cleanup_jq)
    _wait_job_queue_valid(ctx, jq_arn)
    return {"job_queue_arn": jq_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
