"""cancel-jobs-bulk-cancels-pending-job-and-leaves-terminal-job-frozen."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-jobs-bulk-cancels-pending-job-and-leaves-terminal-job-frozen"
GROUP = "job-lifecycle"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_UNMANAGED_ROLE_NAME = "sim2real-behav-batch-service-role"
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


def _swallow(fn):
    """Run fn(), treating only the resource's not-found answers as already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


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
    """Bounded wait for a new role to be readable via GetRole.

    IAM is eventually consistent and Batch rejects a role it cannot yet resolve.
    """
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
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _batch_service_role_arn(ctx):
    """Create-or-adopt the Batch service role an UNMANAGED CE needs.

    Cleanup is registered only when this call created it, so a pre-existing role is never reaped.
    """
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName=_UNMANAGED_ROLE_NAME)["Role"]["Arn"]
    except Exception:  # noqa: BLE001 - absence is the create-or-adopt branch, not a verdict
        pass
    try:
        resp = iam.create_role(
            RoleName=_UNMANAGED_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(_BATCH_TRUST_POLICY),
            Description="SimParity behavioral suite: Batch service role for UNMANAGED CEs",
            Tags=_tags_kv(),
        )
        arn = resp["Role"]["Arn"]
    except Exception as exc:  # noqa: BLE001 - lost a create race; adopt the winner's role
        try:
            return iam.get_role(RoleName=_UNMANAGED_ROLE_NAME)["Role"]["Arn"]
        except Exception:
            raise AssertionError(
                f"cannot create or resolve a customer-managed Batch service role: {exc}"
            ) from exc
    _swallow(
        lambda: iam.attach_role_policy(
            RoleName=_UNMANAGED_ROLE_NAME, PolicyArn=_BATCH_SERVICE_POLICY
        )
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, _UNMANAGED_ROLE_NAME, _BATCH_SERVICE_POLICY))
    _wait_role_assumable(ctx, _UNMANAGED_ROLE_NAME)
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


def _teardown_jobs(bat, job_ids):
    """Terminate every non-terminal job, then wait for each to be terminal.

    A queue holding non-terminal jobs cannot be deleted, so this must run before queue teardown.
    """
    for jid in list(job_ids):
        _swallow(lambda jid=jid: bat.terminate_job(jobId=jid, reason="behavioral-test-cleanup"))
    for jid in list(job_ids):
        _swallow(
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
    _retry_refused(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _swallow(lambda: _wait_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    _retry_refused(lambda: bat.delete_job_queue(jobQueue=name))
    _swallow(
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
    _retry_refused(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _swallow(lambda: _wait_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    _retry_refused(lambda: bat.delete_compute_environment(computeEnvironment=name))
    _swallow(
        lambda: _poll_until(
            lambda: _describe_ce(bat, name),
            lambda ce: ce is None,
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"compute environment {name} gone",
        )
    )


def _unmanaged_queue(ctx, bat):
    """UNMANAGED CE (no computeResources) + ENABLED queue, so jobs park in RUNNABLE forever.

    A new IAM role is not instantly assumable by Batch, so that 400 is retried.
    """
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
        lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{rev}"))
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


def _submit_pending(ctx, bat, queue, job_def, blocker_id):
    """Submit a job blocked on `blocker_id` and wait for it to settle in PENDING. Returns jobId."""
    jid = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"),
        jobQueue=queue,
        jobDefinition=job_def,
        dependsOn=[{"jobId": blocker_id}],
    )["jobId"]
    # A dependent stays PENDING until its blocker is terminal, so the blocker is terminated first.
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [blocker_id, jid]))
    job = _poll_until(
        lambda: _describe_job(bat, jid),
        lambda j: j is not None and j.get("status") in ("PENDING", "RUNNABLE", "FAILED", "SUCCEEDED"),
        timeout_s=_RUNNABLE_S,
        interval_s=3,
        description=f"job {jid} leaves SUBMITTED",
    )
    assert job["status"] == "PENDING", (
        f"a job whose dependsOn parent has not finished must be held in PENDING so that "
        f"CancelJobs has a cancellable non-terminal job to act on; got {job['status']!r}"
    )
    return jid


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelJobs flags a dependency-blocked PENDING job isCancelled without moving it to FAILED,
    leaves an already-FAILED job in the same call frozen, and touches no unnamed job.

    Reference: https://docs.aws.amazon.com/batch/latest/APIReference/API_CancelJobs.html
    """
    bat = ctx.client("batch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; refusing to run against an unidentified target"

    queue = _unmanaged_queue(ctx, bat)
    job_def = _register_jd(ctx, bat)

    # One permanently-RUNNABLE blocker gives every dependent job a stable PENDING state.
    blocker = _submit_runnable(ctx, bat, queue, job_def)
    pending_job = _submit_pending(ctx, bat, queue, job_def, blocker)
    probe_job = _submit_pending(ctx, bat, queue, job_def, blocker)

    # Positive control: CancelJob on a plain RUNNABLE job reaches FAILED; it is then reused as
    # the already-terminal id in the bulk call.
    terminal_job = _submit_runnable(ctx, bat, queue, job_def)
    pre_reason = f"sim2real-pre-{uuid.uuid4().hex[:12]}"
    bat.cancel_job(jobId=terminal_job, reason=pre_reason)
    frozen_before = _wait_terminal(bat, terminal_job)
    assert frozen_before["status"] == "FAILED", (
        f"the positive control: CancelJob on a RUNNABLE job must move it to FAILED, got "
        f"{frozen_before['status']!r} (statusReason={frozen_before.get('statusReason')!r})"
    )
    assert pre_reason in (frozen_before.get("statusReason") or ""), (
        f"the positive control's reason must be readable through DescribeJobs; expected "
        f"{pre_reason!r} inside statusReason, got {frozen_before.get('statusReason')!r}"
    )
    assert "stoppedAt" not in frozen_before, (
        f"a job cancelled before ever starting must have no stoppedAt even once FAILED, got "
        f"{frozen_before.get('stoppedAt')!r}"
    )

    requested = [pending_job, terminal_job]
    bulk_reason = f"sim2real-bulk-{uuid.uuid4().hex[:12]}"
    resp = bat.cancel_jobs(jobs=requested, reason=bulk_reason)
    successful = resp["successful"]
    errored_ids = [e["jobId"] for e in resp["errors"]]

    assert set(successful) | set(errored_ids) == set(requested), (
        f"CancelJobs must account for every requested id exactly once; requested "
        f"{sorted(requested)}, successful {sorted(successful)}, errors {sorted(errored_ids)} — "
        f"missing {sorted(set(requested) - set(successful) - set(errored_ids))}, invented "
        f"{sorted((set(successful) | set(errored_ids)) - set(requested))}"
    )
    assert not (set(successful) & set(errored_ids)), (
        f"an id may not appear in BOTH successful and errors; overlap is "
        f"{sorted(set(successful) & set(errored_ids))}"
    )
    assert pending_job in successful, (
        f"a dependency-blocked PENDING job is still accepted for cancellation, so it must be "
        f"reported successful; successful={sorted(successful)} does not contain {pending_job} "
        f"(errors={resp['errors']!r})"
    )
    for entry in resp["errors"]:
        assert entry.get("code") and entry.get("message"), (
            f"every errors entry must name WHY the job was not cancelled; entry {entry!r} is "
            f"missing a code or a message"
        )

    # AWS defers the FAILED transition until the scheduler evaluates the job, which never
    # happens while its dependsOn stays unsatisfied, so it stays PENDING with isCancelled set.
    for i in range(3):
        after = _describe_job(bat, pending_job)
        assert after["status"] == "PENDING", (
            f"read {i + 1} of 3: a job blocked on an unsatisfied dependsOn must stay PENDING even "
            f"after being reported successful by CancelJobs — the FAILED transition is deferred "
            f"until the scheduler evaluates it, which never happens while blocked; got "
            f"{after['status']!r}"
        )
        assert after.get("isCancelled") is True, (
            f"read {i + 1} of 3: job {pending_job} was reported successful by CancelJobs, so "
            f"DescribeJobs must show isCancelled=True even though status stays PENDING; got "
            f"{after.get('isCancelled')!r}"
        )
        time.sleep(2)
    blocked_after = _describe_job(bat, pending_job)
    assert not blocked_after.get("attempts"), (
        f"job {pending_job} was never placed on the UNMANAGED compute environment, so it must "
        f"record no attempts even while cancelled and blocked; got {blocked_after.get('attempts')!r}"
    )
    assert "startedAt" not in blocked_after, (
        f"a dependency-blocked job must have no startedAt regardless of cancellation, got "
        f"{blocked_after.get('startedAt')!r}"
    )

    # The untouched probe shows only a job named in the call gets flagged.
    probe = _describe_job(bat, probe_job)
    assert probe["status"] == "PENDING" and not probe.get("isCancelled"), (
        f"the untouched probe job must still be PENDING with no isCancelled flag, proving "
        f"CancelJobs acted only on the ids it was given; got status={probe['status']!r} "
        f"isCancelled={probe.get('isCancelled')!r}"
    )

    for i in range(3):
        after = _describe_job(bat, terminal_job)
        assert after["status"] == frozen_before["status"], (
            f"read {i + 1} of 3: an already-FAILED job named in a CancelJobs call must not change "
            f"status; it went from {frozen_before['status']!r} to {after['status']!r}"
        )
        assert "stoppedAt" not in after, (
            f"read {i + 1} of 3: a job cancelled before ever starting must still have no "
            f"stoppedAt after a later bulk cancel; got {after.get('stoppedAt')!r}"
        )
        assert after.get("statusReason") == frozen_before.get("statusReason"), (
            f"read {i + 1} of 3: the terminal job's statusReason must still name the FIRST cancel "
            f"({pre_reason!r}), not the bulk one ({bulk_reason!r}); was "
            f"{frozen_before.get('statusReason')!r}, now {after.get('statusReason')!r}"
        )
        time.sleep(2)

    blocker_now = _describe_job(bat, blocker)
    assert blocker_now["status"] == "RUNNABLE", (
        f"the blocker must still be RUNNABLE, proving the cancels did not cascade to the "
        f"dependency parent; got {blocker_now['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
