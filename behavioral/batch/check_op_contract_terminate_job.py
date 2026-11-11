"""op-contract-terminateJob."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "op-contract-terminateJob"
GROUP = "error-semantics"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateJob forces a RUNNABLE job to FAILED; terminating an already-terminal job is an
    idempotent no-op on the real service (no error), and it must not alter the job's terminal
    status/statusReason."""
    batch = ctx.client("batch")
    ce = _create_unmanaged_ce(ctx)
    jq = _create_job_queue(ctx, ce["arn"])
    jd = _register_job_def(ctx)

    job_id = _submit_job(ctx, jq["arn"], jd["arn"])
    # The UNMANAGED CE has no container instances, so RUNNABLE is the state the job rests in.
    job = _wait_job_status(ctx, job_id, {"RUNNABLE", "STARTING", "RUNNING", "SUCCEEDED", "FAILED"}, timeout_s=120.0)
    assert job["status"] == "RUNNABLE", f"expected the job to rest in RUNNABLE, got {job['status']!r}"

    reason = "sim2real-terminate-reason"
    batch.terminate_job(jobId=job_id, reason=reason)
    final = _wait_job_status(ctx, job_id, {"FAILED"}, timeout_s=60.0)
    assert final["status"] == "FAILED", f"expected TerminateJob to force FAILED, got {final['status']!r}"
    assert final["statusReason"] == reason, (
        f"expected statusReason {reason!r} echoed back, got {final['statusReason']!r}"
    )

    # Error boundary: terminating an already-terminal job is treated by the real service as an
    # idempotent no-op (the call succeeds, it does not raise ClientException), and the forbidden
    # effect (overwriting the original statusReason/attempt history) does not happen.
    batch.terminate_job(jobId=job_id, reason="second-terminate-attempt")
    unchanged = batch.describe_jobs(jobs=[job_id])["jobs"][0]
    assert unchanged["status"] == "FAILED", (
        f"expected second TerminateJob to remain a no-op, got status {unchanged['status']!r}"
    )
    assert unchanged["statusReason"] == reason, (
        f"second TerminateJob call must not overwrite the terminal job's statusReason: "
        f"expected {reason!r}, got {unchanged['statusReason']!r}"
    )


# ===== helpers =====


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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
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
                tags=_MANAGED_TAGS,
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
        tags=_MANAGED_TAGS,
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
        tags=_MANAGED_TAGS,
    )
    jd_arn = resp["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=jd_arn))
    return {"name": name, "arn": jd_arn, "revision": resp["revision"]}


def _submit_job(ctx, jq_arn: str, jd_arn: str, name: str | None = None) -> str:
    batch = ctx.client("batch")
    name = name or ctx.unique_name("sim2real-batch-job-")
    resp = batch.submit_job(jobName=name, jobQueue=jq_arn, jobDefinition=jd_arn)
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
