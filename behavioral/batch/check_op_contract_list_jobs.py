"""op-contract-listJobs."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listJobs"
GROUP = "error-semantics"
SERVICES = ["batch"]

_TAGS = {"sim2real:check": "op-contract-listJobs"}
_TAGS_KV = [{"Key": k, "Value": v} for k, v in _TAGS.items()]


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListJobs defaults to RUNNING-only, requires an explicit status for RUNNABLE jobs, and
    rejects a call that specifies none of jobQueue/arrayJobId/multiNodeJobId."""
    batch = ctx.client("batch")
    ce = _create_unmanaged_ce(ctx)
    jq = _create_job_queue(ctx, ce["arn"])
    jd = _register_job_def(ctx)

    job_name = ctx.unique_name("sim2real-batch-listjobs-")
    job_id = _submit_job(ctx, jq["arn"], jd["arn"], name=job_name)
    ctx.on_cleanup(lambda: batch.terminate_job(jobId=job_id, reason="test-cleanup"))
    # The UNMANAGED CE has no container instances, so RUNNABLE is the state the job rests in
    # for as long as the check holds it.
    job = _wait_job_status(ctx, job_id, {"RUNNABLE", "STARTING", "RUNNING", "SUCCEEDED", "FAILED"}, timeout_s=120.0)
    assert job["status"] == "RUNNABLE", f"job {job_id} must rest in RUNNABLE, got {job['status']!r}"
    actual_status = job["status"]

    # Without an explicit jobStatus filter, only RUNNING jobs are listed -- our RUNNABLE
    # job (no capacity ever available on the UNMANAGED CE) must NOT show up.
    default_list = batch.list_jobs(jobQueue=jq["arn"])["jobSummaryList"]
    assert job_id not in {j["jobId"] for j in default_list}, "unfiltered ListJobs must only return RUNNING jobs"

    # With the matching explicit status filter, the job is returned with correct identity fields.
    # Note: JobSummary (the list_jobs item shape) has no "jobQueue" field -- queue membership
    # is implied by the jobQueue= filter on the call itself. Also, "jobDefinition" is NOT a
    # reliably-present key on real AWS JobSummary entries (observed absent on a real account),
    # so assert identity against the fields that are always present instead: jobName and jobArn
    # (the latter cross-checked against the describe_jobs response for the same job).
    filtered = batch.list_jobs(jobQueue=jq["arn"], jobStatus=actual_status)["jobSummaryList"]
    matches = [j for j in filtered if j["jobId"] == job_id]
    assert len(matches) == 1, f"expected exactly 1 match for {job_id} under status {actual_status}"
    assert matches[0]["jobName"] == job_name, f"expected jobName {job_name!r}, got {matches[0]['jobName']!r}"
    assert matches[0]["jobArn"] == job["jobArn"], f"expected jobArn {job['jobArn']!r}, got {matches[0]['jobArn']!r}"

    # Error boundary: specifying none of jobQueue/arrayJobId/multiNodeJobId is rejected.
    code, message, request_id = _error_code(lambda: batch.list_jobs())
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    # Batch embeds the call's own request id in this message.
    expected = f"Error executing request, Exception : Job queue name is required., RequestId: {request_id}"
    assert message == expected, f"expected {expected!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message, request id). An unexpected
    SUCCESS raises, because accepting a call real AWS refuses must not be reported as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message"), exc.response["ResponseMetadata"].get("RequestId")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _poll_ce_status(ctx, name, target_statuses, timeout_s=90.0):
    batch = ctx.client("batch")

    def probe():
        r = batch.describe_compute_environments(computeEnvironments=[name])
        ces = r["computeEnvironments"]
        return ces[0] if ces else None

    return _poll_until(
        probe, lambda ce: ce is not None and ce["status"] in target_statuses, timeout_s=timeout_s, interval_s=2.0
    )


def _create_batch_service_role(ctx) -> str:
    """Real AWS Batch requires an explicit serviceRole for CreateComputeEnvironment (even
    for UNMANAGED environments) unless the account already has one on file; create a
    minimal one inline."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-svcrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "batch.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_TAGS_KV)
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _detach_role_policy(ctx, role_name, policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _detach_role_policy(ctx, role_name: str, policy_arn: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_compute_environment_with_role(ctx, name: str, service_role_arn: str, timeout_s: float = 60.0):
    """A freshly-created IAM role can take a few seconds to be assumable by batch.amazonaws.com;
    poll by retrying the create call itself rather than sleeping blindly."""
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return batch.create_compute_environment(
                computeEnvironmentName=name,
                type="UNMANAGED",
                state="ENABLED",
                serviceRole=service_role_arn,
                tags=_TAGS,
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


#: The suite's cleanup budget; the retries of every teardown of one run share one deadline in it.
_CLEANUP_BUDGET_S = 900.0
_cleanup_deadlines: dict[int, tuple[object, float]] = {}


def _teardown_ce(ctx, batch, name):
    """Disable and delete the compute environment, then wait until DescribeComputeEnvironments no
    longer lists it: the service role torn down after it must outlive the asynchronous delete.
    ClientException refusals (a queue still detaching, the CE still updating) retry every 2 s."""
    held = _cleanup_deadlines.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _cleanup_deadlines[id(ctx)] = (ctx, time.monotonic() + _CLEANUP_BUDGET_S)
    deadline = held[1]
    steps = [
        lambda: batch.update_compute_environment(computeEnvironment=name, state="DISABLED"),
        lambda: batch.delete_compute_environment(computeEnvironment=name),
    ]
    while True:
        listed = [
            ce
            for ce in batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
            if ce.get("status") != "DELETED"
        ]
        if not listed:
            return
        if steps and listed[0].get("status") != "DELETING":
            try:
                steps[0]()
                steps.pop(0)
                continue
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                    return
                if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                    raise
        elif time.monotonic() >= deadline:
            raise TimeoutError(f"compute environment {name} still listed at the cleanup deadline")
        time.sleep(2)


def _create_unmanaged_ce(ctx) -> dict[str, Any]:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-ce-")
    service_role_arn = _create_batch_service_role(ctx)
    resp = _create_compute_environment_with_role(ctx, name, service_role_arn)

    ctx.on_cleanup(lambda: _teardown_ce(ctx, batch, name))
    _poll_ce_status(ctx, name, {"VALID"})
    return {"name": name, "arn": resp["computeEnvironmentArn"]}


def _poll_jq_status(ctx, name, target_statuses, timeout_s=90.0):
    batch = ctx.client("batch")

    def probe():
        r = batch.describe_job_queues(jobQueues=[name])
        jqs = r["jobQueues"]
        return jqs[0] if jqs else None

    return _poll_until(
        probe, lambda jq: jq is not None and jq["status"] in target_statuses, timeout_s=timeout_s, interval_s=2.0
    )


def _create_job_queue(ctx, ce_arn: str, priority: int = 1) -> dict[str, Any]:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    resp = batch.create_job_queue(
        jobQueueName=name,
        state="ENABLED",
        priority=priority,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=_TAGS,
    )

    def _cleanup():
        try:
            batch.update_job_queue(jobQueue=name, state="DISABLED")
            _poll_jq_status(ctx, name, {"VALID", "INVALID"})
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        batch.delete_job_queue(jobQueue=name)

    ctx.on_cleanup(_cleanup)
    _poll_jq_status(ctx, name, {"VALID"})
    return {"name": name, "arn": resp["jobQueueArn"]}


def _register_job_def(ctx, name: str | None = None) -> dict[str, Any]:
    batch = ctx.client("batch")
    name = name or ctx.unique_name("sim2real-batch-jd-")
    resp = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["sleep", "60"],
            "resourceRequirements": [{"type": "VCPU", "value": "1"}, {"type": "MEMORY", "value": "512"}],
        },
        tags=_TAGS,
    )
    jd_arn = resp["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=jd_arn))
    return {"name": name, "arn": jd_arn, "revision": resp["revision"]}


def _submit_job(ctx, jq_arn: str, jd_arn: str, name: str | None = None) -> str:
    batch = ctx.client("batch")
    name = name or ctx.unique_name("sim2real-batch-job-")
    resp = batch.submit_job(jobName=name, jobQueue=jq_arn, jobDefinition=jd_arn, tags=_TAGS)
    return resp["jobId"]


def _wait_job_status(ctx, job_id: str, target_statuses, timeout_s: float = 90.0):
    batch = ctx.client("batch")

    def probe():
        r = batch.describe_jobs(jobs=[job_id])
        js = r["jobs"]
        return js[0] if js else None

    return _poll_until(
        probe, lambda j: j is not None and j["status"] in target_statuses, timeout_s=timeout_s, interval_s=2.0
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
