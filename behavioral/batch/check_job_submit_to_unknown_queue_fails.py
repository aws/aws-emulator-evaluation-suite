"""job-submit-to-unknown-queue-fails."""

from __future__ import annotations
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "job-submit-to-unknown-queue-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_BATCH_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
_BATCH_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "batch.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _swallow(fn):
    """Run fn(); only a resource that is already gone is ignored, every other failure raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "NoSuchEntity"
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _err_code_and_message(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises, because accepting a call AWS refuses must not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_ce(bat, name):
    envs = bat.describe_compute_environments(computeEnvironments=[name]).get(
        "computeEnvironments", []
    )
    return envs[0] if envs else None


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _describe_job(bat, job_id):
    js = bat.describe_jobs(jobs=[job_id]).get("jobs", [])
    return js[0] if js else None


def _delete_role(ctx, role_name, policy_arn):
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _unmanaged_service_role_arn(ctx):
    """Create this run's own customer-managed Batch service role for the UNMANAGED CE."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-batch-svcrole-unkq-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_BATCH_TRUST_POLICY),
        Description="SimParity behavioral suite: Batch service role for UNMANAGED CEs",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, _BATCH_SERVICE_POLICY))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BATCH_SERVICE_POLICY)
    return arn


def _create_unmanaged_ce(ctx, bat):
    """UNMANAGED CE (no computeResources / VPC): jobs park in RUNNABLE. Registers teardown.

    A freshly-created IAM role is not instantly assumable by Batch, so the 400 that reports
    exactly that is retried rather than trusting a fixed sleep.
    """
    name = ctx.unique_name("sim2real-behav-ce-unkq-")
    role = _unmanaged_service_role_arn(ctx)
    last_exc = None
    for attempt in range(8):
        try:
            resp = bat.create_compute_environment(
                computeEnvironmentName=name,
                type="UNMANAGED",
                state="ENABLED",
                serviceRole=role,
                tags=_MANAGED_TAGS,
            )
            break
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            transient = (
                "cannot be assumed" in msg
                or "not authorized to perform: sts:assumerole" in msg
                or "does not have permission" in msg
                or ("invalid" in msg and "role" in msg)
            )
            if not transient or attempt == 7:
                raise
            last_exc = exc
            time.sleep(5)
    else:  # pragma: no cover - loop always breaks or raises
        raise last_exc  # type: ignore[misc]
    ctx.on_cleanup(lambda: _teardown_ce(ctx, bat, name))
    return name, resp["computeEnvironmentArn"]


def _retry_client_exception(call, timeout_s=120):
    """Retry a delete Batch refuses with ClientException while a dependency releases, every 2 s; then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _teardown_ce(ctx, bat, name):
    """Disable a compute environment, wait for it to settle, then delete it; a failure raises."""
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in {"VALID", "INVALID"},
        timeout_s=90,
        interval_s=3,
        description=f"compute environment {name} settle before delete",
    )
    _retry_client_exception(lambda: bat.delete_compute_environment(computeEnvironment=name))


def _create_job_queue(ctx, bat, ce_arn):
    name = ctx.unique_name("sim2real-behav-jq-unkq-")
    resp = bat.create_job_queue(
        jobQueueName=name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
    )
    ctx.on_cleanup(lambda: _teardown_jq(ctx, bat, name))
    return name, resp["jobQueueArn"]


def _teardown_jq(ctx, bat, name):
    """Disable a job queue, wait for it to settle, then delete it; a failure raises."""
    try:
        bat.update_job_queue(jobQueue=name, state="DISABLED")
        _poll_until(
            lambda: _describe_jq(bat, name),
            lambda jq: jq is not None and jq.get("status") in {"VALID", "INVALID"},
            timeout_s=60,
            interval_s=3,
            description=f"job queue {name} settle before delete",
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _swallow(lambda: bat.delete_job_queue(jobQueue=name))


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


def _register_basic_job_definition(ctx, bat, name=None, command=None):
    name = name or ctx.unique_name("sim2real-behav-jd-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "vcpus": 1,
            "memory": 128,
            "command": command or ["echo", "hello"],
        },
    )
    revision = resp["revision"]
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, revision))
    return name, revision, resp["jobDefinitionArn"]


def _submit_job(ctx, bat, queue, job_definition):
    name = ctx.unique_name("sim2real-behav-job-")
    resp = bat.submit_job(jobName=name, jobQueue=queue, jobDefinition=job_definition)
    job_id = resp["jobId"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: bat.terminate_job(jobId=job_id, reason="behavioral-test-cleanup"))
    )
    return job_id, resp["jobArn"]


def _wait_job_status(bat, job_id, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job {job_id} status in {sorted(statuses)}",
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitJob to a never-created queue is rejected with ClientException naming it and leaves no phantom
    queue, while the same SubmitJob to a real ENABLED queue reaches RUNNABLE (the positive control).
    """
    bat = ctx.client("batch")
    jd_name, jd_rev, jd_arn = _register_basic_job_definition(ctx, bat)

    ce_name, ce_arn = _create_unmanaged_ce(ctx, bat)
    ce = _poll_until(
        lambda: _describe_ce(bat, ce_name),
        lambda c: c is not None and c.get("status") in {"VALID", "INVALID"},
        description=f"compute environment {ce_name} valid",
    )
    assert ce["status"] == "VALID", f"CE not VALID: {ce.get('statusReason')}"

    jq_name, jq_arn = _create_job_queue(ctx, bat, ce_arn)
    jq = _poll_until(
        lambda: _describe_jq(bat, jq_name),
        lambda q: q is not None and q.get("status") in {"VALID", "INVALID"},
        description=f"job queue {jq_name} valid",
    )
    assert jq["status"] == "VALID", f"queue not VALID: {jq.get('statusReason')}"

    # positive control: SubmitJob against a real, ENABLED queue succeeds and reaches
    # RUNNABLE -- proves SubmitJob itself works in this account before testing absence.
    good_job_id, _good_job_arn = _submit_job(ctx, bat, jq_name, jd_arn)
    good_job = _wait_job_status(bat, good_job_id, {"RUNNABLE"})
    assert good_job["status"] == "RUNNABLE", f"positive control did not reach RUNNABLE: {good_job}"

    bogus_queue = ctx.unique_name("sim2real-behav-batch-absent-queue-")
    code, message = _err_code_and_message(
        lambda: bat.submit_job(
            jobName=ctx.unique_name("sim2real-behav-job-"),
            jobQueue=bogus_queue,
            jobDefinition=f"{jd_name}:{jd_rev}",
        )
    )
    assert code == "ClientException", f"expected ClientException for unknown job queue, got {code!r}"
    expected = f"JobQueue {bogus_queue} not found."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # effect-absent: the bogus name never became a real job queue
    existing = bat.describe_job_queues(jobQueues=[bogus_queue]).get("jobQueues", [])
    assert existing == [], f"expected no job queue named {bogus_queue!r}, got {existing!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
