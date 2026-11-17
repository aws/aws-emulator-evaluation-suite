"""cancel-jobs-over-fifty-ids-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-jobs-over-fifty-ids-rejected"
GROUP = "job-listing"
SERVICES = ["batch", "ecs", "iam"]

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "batch.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_SERVICE_ROLE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")


def _delete_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SERVICE_ROLE_POLICY)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-batch-unmgd-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SERVICE_ROLE_POLICY)
    return arn


def _create_ce(ctx, bat, role_arn):
    name = ctx.unique_name("sim2real-behav-ce-")
    last_exc = None
    for attempt in range(10):
        try:
            arn = bat.create_compute_environment(
                computeEnvironmentName=name,
                type="UNMANAGED",
                state="ENABLED",
                serviceRole=role_arn,
                tags={"sim2real:managed": "true"},
            )["computeEnvironmentArn"]
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "").lower()
            if "cannot be assumed" not in msg and "not authorized" not in msg and "sts:assumerole" not in msg:
                raise
            last_exc = exc
            time.sleep(4)
    else:
        raise last_exc
    ctx.on_cleanup(lambda: _teardown_ce(bat, name))
    ce = _poll_until(
        lambda: bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0],
        lambda c: c["status"] in ("VALID", "INVALID"),
        description=f"compute environment {name} settles",
    )
    assert ce["status"] == "VALID", f"compute environment did not validate: {ce.get('statusReason')!r}"
    return name, arn


def _teardown_ce(bat, name):
    if not bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]:
        return
    bat.update_compute_environment(computeEnvironment=name, state="DISABLED")
    _poll_until(
        lambda: bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        description=f"compute environment {name} disabled",
    )
    deadline = time.monotonic() + 300.0
    while True:
        try:
            bat.delete_compute_environment(computeEnvironment=name)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    _poll_until(
        lambda: bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"],
        lambda envs: not envs or envs[0]["status"] == "DELETED",
        timeout_s=300.0,
        interval_s=5.0,
        description=f"compute environment {name} deleted",
    )


def _create_queue(ctx, bat, ce_arn):
    jq_name = ctx.unique_name("sim2real-behav-jq-")
    jq_arn = bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=1,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags={"sim2real:managed": "true"},
    )["jobQueueArn"]
    ctx.on_cleanup(lambda: _teardown_queue(bat, jq_name))
    jq = _poll_until(
        lambda: bat.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
        lambda q: q["status"] in ("VALID", "INVALID"),
        description=f"job queue {jq_name} settles",
    )
    assert jq["status"] == "VALID", f"job queue did not validate: {jq.get('statusReason')!r}"
    return jq_name


def _teardown_queue(bat, name):
    if not bat.describe_job_queues(jobQueues=[name])["jobQueues"]:
        return
    bat.update_job_queue(jobQueue=name, state="DISABLED")
    _poll_until(
        lambda: bat.describe_job_queues(jobQueues=[name])["jobQueues"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        description=f"job queue {name} disabled",
    )
    bat.delete_job_queue(jobQueue=name)
    _poll_until(
        lambda: bat.describe_job_queues(jobQueues=[name])["jobQueues"],
        lambda qs: not qs or qs[0]["status"] == "DELETED",
        timeout_s=300.0,
        interval_s=5.0,
        description=f"job queue {name} deleted",
    )


def _deregister_batch_jd(bat, ref):
    """Deregister one Batch job definition revision; an already-gone one is fine."""
    try:
        bat.deregister_job_definition(jobDefinition=ref)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


def _sweep_ecs_task_defs(ctx, refs, *, budget_s=90.0, interval_s=5.0):
    """Remove the same-named ECS task definition registering a Batch job definition creates,
    which DeregisterJobDefinition never removes.

    Batch can create it asynchronously, well after DeregisterJobDefinition returns, so this
    runs LAST among this check's cleanups (registered first; LIFO) and polls a bounded window
    rather than firing once right after the create -- a ref that never appears was never
    pushed to ECS and is not a leak.
    """
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + budget_s
    remaining = set(refs)
    while remaining and time.monotonic() < deadline:
        for ref in list(remaining):
            try:
                ecs.deregister_task_definition(taskDefinition=ref)
            except ClientError as exc:
                message = exc.response["Error"].get("Message", "")
                if "does not exist" in message or "Unable to describe task definition" in message:
                    continue
                raise
            failures = ecs.delete_task_definitions(taskDefinitions=[ref]).get("failures") or []
            assert not failures, f"DeleteTaskDefinitions refused {ref}: {failures!r}"
            remaining.discard(ref)
        if remaining:
            time.sleep(interval_s)


def _register_jd(ctx, bat, jd_refs):
    jd_name = ctx.unique_name("sim2real-behav-jd-")
    resp = bat.register_job_definition(
        jobDefinitionName=jd_name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "command": ["echo", "hi"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
    )
    ref = f"{jd_name}:{resp['revision']}"
    jd_refs.append(ref)
    ctx.on_cleanup(lambda: _deregister_batch_jd(bat, ref))
    return resp["jobDefinitionArn"]


def _error(fn):
    """(code, message, request_id) of the ClientError fn() raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response["ResponseMetadata"].get("RequestId")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CancelJobs accepts up to 50 job ids per call -- at the cap, every unresolvable id is
    reported successful and the one real RUNNABLE job is cancelled to FAILED; one id past the
    cap is refused outright with ClientException, and the call still works at the cap afterward."""
    bat = ctx.client("batch")
    jd_refs: list[str] = []
    ctx.on_cleanup(lambda: _sweep_ecs_task_defs(ctx, jd_refs))
    role_arn = _service_role(ctx)
    _ce_name, ce_arn = _create_ce(ctx, bat, role_arn)
    jq_name = _create_queue(ctx, bat, ce_arn)
    jd_arn = _register_jd(ctx, bat, jd_refs)

    real_job_id = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"), jobQueue=jq_name, jobDefinition=jd_arn
    )["jobId"]
    ctx.on_cleanup(
        lambda: _poll_until(
            lambda: bat.describe_jobs(jobs=[real_job_id])["jobs"],
            lambda js: not js or js[0]["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=180.0,
            interval_s=3.0,
            description=f"job {real_job_id} reaches terminal",
        )
    )

    unknown_49 = [str(uuid.uuid4()) for _ in range(49)]
    at_cap = [real_job_id, *unknown_49]
    cap_resp = bat.cancel_jobs(jobs=at_cap, reason="sim2real behavioral boundary check")
    assert cap_resp["errors"] == [], f"a 50-id CancelJobs must report no errors, got {cap_resp['errors']!r}"
    assert set(cap_resp["successful"]) == set(at_cap), (
        f"a 50-id CancelJobs must report every id successful (unknown ids included), "
        f"got {sorted(cap_resp['successful'])!r}"
    )

    settled = _poll_until(
        lambda: bat.describe_jobs(jobs=[real_job_id])["jobs"][0],
        lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
        description=f"cancelled job {real_job_id} reaches a terminal state",
    )
    assert settled["status"] == "FAILED", f"a cancelled RUNNABLE job must land FAILED, got {settled['status']!r}"

    over_cap = [*at_cap, str(uuid.uuid4())]
    code, message, request_id = _error(lambda: bat.cancel_jobs(jobs=over_cap, reason="sim2real behavioral boundary check"))
    assert code == "ClientException", f"CancelJobs for 51 ids: expected ClientException, got {code!r}"
    expected_message = (
        "Error executing request, Exception : A maximum of 50 jobs can be specified per request., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"CancelJobs for 51 ids: expected message {expected_message!r}, got {message!r}"

    again = bat.cancel_jobs(jobs=at_cap, reason="sim2real behavioral boundary check")
    assert again["errors"] == [], f"the 50-id call after the refusal must still report no errors, got {again['errors']!r}"
    assert set(again["successful"]) == set(at_cap), (
        f"the 50-id call after the refusal must still report every id successful, "
        f"got {sorted(again['successful'])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
