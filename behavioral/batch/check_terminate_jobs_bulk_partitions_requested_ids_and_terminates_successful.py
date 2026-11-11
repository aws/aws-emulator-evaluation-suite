"""terminate-jobs-bulk-partitions-requested-ids-and-terminates-successful."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "terminate-jobs-bulk-partitions-requested-ids-and-terminates-successful"
GROUP = "job-lifecycle"
SERVICES = ["batch"]

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
_CE_VALID_S = 180       # an UNMANAGED CE has no capacity to provision, so it validates fast
_JQ_VALID_S = 180       # queue VALID follows CE association
_RUNNABLE_S = 180       # SUBMITTED -> RUNNABLE is a scheduler sweep, not a placement
_TERMINAL_S = 300       # a cancel of an unplaced job is bookkeeping, not a container stop
_TEARDOWN_S = 300       # DISABLED -> settle -> deleted -> gone, per resource


def _undo(fn, retry_s=0.0):
    """Run a teardown step; a resource that does not exist is done. Batch's ClientException for a
    resource still in use is retried every 2 s for retry_s; anything else raises."""
    deadline = time.monotonic() + retry_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "NoSuchEntity" or (
                err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")
            ):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result); raise on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_role_assumable(ctx, role_name):
    """Bounded wait for a new role to be readable: IAM is eventually consistent and Batch
    rejects a role it cannot yet resolve."""
    iam = ctx.client("iam")
    _poll_until(
        lambda: iam.get_role(RoleName=role_name).get("Role"),
        lambda r: bool(r and r.get("Arn")),
        timeout_s=60,
        interval_s=3,
        description=f"IAM role {role_name} readable after create",
    )


def _delete_role(ctx, role_name, policy_arn):
    iam = ctx.client("iam")
    _undo(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _undo(lambda: iam.delete_role(RoleName=role_name))


def _batch_service_role_arn(ctx):
    """Create a Batch service role for UNMANAGED CEs, deletion registered; return its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-batch-svc-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_BATCH_TRUST_POLICY),
        Description="SimParity behavioral suite: Batch service role for UNMANAGED CEs",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, _BATCH_SERVICE_POLICY))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BATCH_SERVICE_POLICY)
    _wait_role_assumable(ctx, role_name)
    return arn


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


def _wait_ce(bat, name, statuses, timeout_s=_CE_VALID_S, interval_s=3):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _wait_jq(bat, name, statuses, timeout_s=_JQ_VALID_S, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _teardown_jobs(bat, job_ids):
    """Terminate every non-terminal job, then wait for each to be terminal.
    A queue holding non-terminal jobs cannot be deleted, so this runs before the queue teardown."""
    for jid in list(job_ids):
        _undo(lambda jid=jid: bat.terminate_job(jobId=jid, reason="behavioral-test-cleanup"))
    for jid in list(job_ids):
        _undo(
            lambda jid=jid: _poll_until(
                lambda: _describe_job(bat, jid),
                lambda j: j is None or j.get("status") in ("SUCCEEDED", "FAILED"),
                timeout_s=_TEARDOWN_S,
                interval_s=5,
                description=f"job {jid} terminal before queue teardown",
            )
        )


def _teardown_jq(bat, name):
    """DISABLE -> poll settled -> DeleteJobQueue -> poll gone."""
    _undo(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _undo(lambda: _wait_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    _undo(lambda: bat.delete_job_queue(jobQueue=name), retry_s=60)  # a queue still draining rejects the delete
    _undo(
        lambda: _poll_until(
            lambda: _describe_jq(bat, name),
            lambda jq: jq is None,
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"job queue {name} gone",
        )
    )


def _teardown_ce(bat, name):
    """DISABLE -> poll settled -> DeleteComputeEnvironment -> poll gone."""
    _undo(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _undo(lambda: _wait_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    _undo(lambda: bat.delete_compute_environment(computeEnvironment=name), retry_s=60)  # a still-referenced CE rejects the delete
    _undo(
        lambda: _poll_until(
            lambda: _describe_ce(bat, name),
            lambda ce: ce is None,
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"compute environment {name} gone",
        )
    )


def _unmanaged_queue(ctx, bat):
    """UNMANAGED CE (no computeResources) + ENABLED queue, so jobs park in RUNNABLE.
    CreateComputeEnvironment is retried while the new IAM role is not yet assumable by Batch."""
    ce_name = ctx.unique_name("sim2real-behav-ce-unmgd-")
    role = _batch_service_role_arn(ctx)
    ce_arn = None
    for attempt in range(8):
        try:
            ce_arn = bat.create_compute_environment(
                computeEnvironmentName=ce_name,
                type="UNMANAGED",
                state="ENABLED",
                serviceRole=role,
                tags=dict(_MANAGED_TAGS),
            )["computeEnvironmentArn"]
            break
        except Exception as exc:  # noqa: BLE001 - only an IAM-propagation 400 is retryable
            msg = str(exc).lower()
            retryable = (
                "cannot be assumed" in msg
                or "sts:assumerole" in msg
                or "does not have permission" in msg
            )
            if not retryable or attempt == 7:
                raise
            time.sleep(5)
    assert ce_arn, f"create_compute_environment never returned an ARN for {ce_name}"
    ctx.on_cleanup(lambda: _teardown_ce(bat, ce_name))
    ce = _wait_ce(bat, ce_name, {"VALID", "INVALID"})
    assert ce["status"] == "VALID", (
        f"UNMANAGED compute environment {ce_name} must reach VALID, got {ce['status']!r}: "
        f"{ce.get('statusReason')!r}"
    )

    jq_name = ctx.unique_name("sim2real-behav-jq-")
    bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_jq(bat, jq_name))
    jq = _wait_jq(bat, jq_name, {"VALID", "INVALID"})
    assert jq["status"] == "VALID", (
        f"job queue {jq_name} must reach VALID, got {jq['status']!r}: {jq.get('statusReason')!r}"
    )
    return jq_name


def _register_jd(ctx, bat):
    """A trivial container job definition. It is never actually run on an UNMANAGED CE."""
    name = ctx.unique_name("sim2real-behav-jd-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "command": ["/bin/sh", "-c", "exit 0"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
        tags=dict(_MANAGED_TAGS),
    )
    rev = resp["revision"]
    ctx.on_cleanup(
        lambda: _undo(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{rev}"))
    )
    return f"{name}:{rev}"


def _submit_runnable(ctx, bat, queue, job_def):
    """Submit a job and wait for it to park in RUNNABLE. Returns the jobId."""
    jid = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"), jobQueue=queue, jobDefinition=job_def
    )["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [jid]))
    _poll_until(
        lambda: _describe_job(bat, jid),
        lambda j: j is not None and j.get("status") == "RUNNABLE",
        timeout_s=_RUNNABLE_S,
        interval_s=3,
        description=f"job {jid} parked in RUNNABLE on the UNMANAGED compute environment",
    )
    return jid


def _wait_terminal(bat, job_id):
    """Wait for SUCCEEDED or FAILED."""
    return _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") in ("SUCCEEDED", "FAILED"),
        timeout_s=_TERMINAL_S,
        interval_s=3,
        description=f"job {job_id} reached SUCCEEDED or FAILED",
    )


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateJobs partitions the requested ids exhaustively and disjointly into successful and
    errors, terminates every successful job with the bulk reason, and leaves other jobs untouched.
    """
    bat = ctx.client("batch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; refusing to run against an unidentified target"

    queue = _unmanaged_queue(ctx, bat)
    job_def = _register_jd(ctx, bat)

    control_job = _submit_runnable(ctx, bat, queue, job_def)
    bulk_a = _submit_runnable(ctx, bat, queue, job_def)
    bulk_b = _submit_runnable(ctx, bat, queue, job_def)
    refreeze_probe = _submit_runnable(ctx, bat, queue, job_def)

    # Positive control: singular TerminateJob works, so a no-op bulk call is not an account issue.
    control_reason = f"sim2real-control-{uuid.uuid4().hex[:12]}"
    bat.terminate_job(jobId=control_job, reason=control_reason)
    control = _wait_terminal(bat, control_job)
    assert control["status"] == "FAILED", (
        f"the positive control: TerminateJob on a RUNNABLE job must move it to FAILED, got "
        f"{control['status']!r} (statusReason={control.get('statusReason')!r})"
    )
    assert control_reason in (control.get("statusReason") or ""), (
        f"the positive control's reason must be readable through DescribeJobs; expected "
        f"{control_reason!r} inside statusReason, got {control.get('statusReason')!r}"
    )

    # The unknown id's bucket is not asserted: singular TerminateJob accepts unknown ids.
    unknown_job = str(uuid.uuid4())  # a well-formed Batch job id that has never existed
    requested = [bulk_a, bulk_b, unknown_job]
    bulk_reason = f"sim2real-bulk-{uuid.uuid4().hex[:12]}"
    resp = bat.terminate_jobs(jobs=requested, reason=bulk_reason)

    successful = resp["successful"]
    errors = resp["errors"]
    errored_ids = [e["jobId"] for e in errors]

    assert set(successful) | set(errored_ids) == set(requested), (
        f"TerminateJobs must account for every requested id exactly once; requested "
        f"{sorted(requested)}, successful {sorted(successful)}, errors "
        f"{sorted(errored_ids)} — missing {sorted(set(requested) - set(successful) - set(errored_ids))}, "
        f"invented {sorted((set(successful) | set(errored_ids)) - set(requested))}"
    )
    assert not (set(successful) & set(errored_ids)), (
        f"an id may not appear in BOTH successful and errors; overlap is "
        f"{sorted(set(successful) & set(errored_ids))}"
    )
    assert len(successful) == len(set(successful)) and len(errored_ids) == len(set(errored_ids)), (
        f"neither bucket may repeat an id; successful={successful!r} errors={errored_ids!r}"
    )
    assert bulk_a in successful and bulk_b in successful, (
        f"both real RUNNABLE jobs must be accepted for termination; successful={sorted(successful)} "
        f"does not contain both {bulk_a} and {bulk_b}"
    )
    for entry in errors:
        assert entry.get("code"), (
            f"every errors entry must name WHY the job was not terminated; entry {entry!r} "
            f"carries no code"
        )
        assert entry.get("message"), (
            f"every errors entry must carry a human-readable message; entry {entry!r} does not"
        )

    # Batch may prefix the reason, so statusReason is checked for containment.
    for jid in (bulk_a, bulk_b):
        job = _wait_terminal(bat, jid)
        assert job["status"] == "FAILED", (
            f"job {jid} was reported successful by TerminateJobs, so DescribeJobs must show it "
            f"FAILED, got {job['status']!r} (statusReason={job.get('statusReason')!r})"
        )
        assert bulk_reason in (job.get("statusReason") or ""), (
            f"the bulk reason must be returned by a future DescribeJobs on job {jid}; expected "
            f"{bulk_reason!r} inside statusReason, got {job.get('statusReason')!r}"
        )
        assert not job.get("attempts"), (
            f"job {jid} was never placed on the UNMANAGED compute environment, so terminating it "
            f"must leave it with no attempts; got {job.get('attempts')!r}"
        )

    # The unknown id must not be describable, whichever bucket the service put it in.
    assert bat.describe_jobs(jobs=[unknown_job])["jobs"] == [], (
        f"DescribeJobs must return no job for the fabricated id {unknown_job}; TerminateJobs must "
        f"not have brought a job into existence"
    )

    before = _describe_job(bat, bulk_a)
    repeat = bat.terminate_jobs(jobs=[bulk_a], reason=f"sim2real-repeat-{uuid.uuid4().hex[:8]}")
    assert set(repeat["successful"]) | {e["jobId"] for e in repeat["errors"]} == {bulk_a}, (
        f"the repeat call must still account for its one id; got successful="
        f"{repeat['successful']!r} errors={repeat['errors']!r}"
    )
    for i in range(3):
        after = _describe_job(bat, bulk_a)
        assert (
            after["status"] == before["status"]
            and after.get("stoppedAt") == before.get("stoppedAt")
            and after.get("statusReason") == before.get("statusReason")
        ), (
            f"read {i + 1} of 3: terminating an already-FAILED job must be a no-op, but job "
            f"{bulk_a} changed from status={before['status']!r} stoppedAt={before.get('stoppedAt')!r} "
            f"reason={before.get('statusReason')!r} to status={after['status']!r} "
            f"stoppedAt={after.get('stoppedAt')!r} reason={after.get('statusReason')!r}"
        )
        time.sleep(2)

    # The untouched job proves the terminations came from the calls, not a collapsed queue.
    still_runnable = _describe_job(bat, refreeze_probe)
    assert still_runnable["status"] == "RUNNABLE", (
        f"the untouched probe job must still be RUNNABLE, proving TerminateJobs terminated only "
        f"the ids it was given; got {still_runnable['status']!r} "
        f"(statusReason={still_runnable.get('statusReason')!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
