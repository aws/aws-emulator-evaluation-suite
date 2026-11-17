"""submit-job-without-revision-resolves-to-latest-active."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "submit-job-without-revision-resolves-to-latest-active"
GROUP = "job-definitions"
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


def _container_props():
    return {
        "image": "busybox:1.36",
        "command": ["echo", "hi"],
        "resourceRequirements": [
            {"type": "VCPU", "value": "1"},
            {"type": "MEMORY", "value": "512"},
        ],
    }


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _terminate(bat, job_id):
    job = bat.describe_jobs(jobs=[job_id])["jobs"]
    if job and job[0]["status"] not in ("SUCCEEDED", "FAILED"):
        bat.terminate_job(jobId=job_id, reason="behavioral check teardown")
        _poll_until(
            lambda: bat.describe_jobs(jobs=[job_id])["jobs"][0]["status"],
            lambda s: s in ("SUCCEEDED", "FAILED"),
            timeout_s=180.0,
            interval_s=3.0,
            description=f"job {job_id} reaches terminal",
        )


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitJob given a job definition name with no revision resolves to the latest ACTIVE
    revision, never a later revision that has since been deregistered; referencing the
    deregistered revision explicitly by name:revision is refused."""
    bat = ctx.client("batch")
    jd_refs: list[str] = []
    ctx.on_cleanup(lambda: _sweep_ecs_task_defs(ctx, jd_refs))
    role_arn = _service_role(ctx)
    _ce_name, ce_arn = _create_ce(ctx, bat, role_arn)
    jq_name = _create_queue(ctx, bat, ce_arn)

    jd_name = ctx.unique_name("sim2real-behav-jd-")
    rev1 = bat.register_job_definition(
        jobDefinitionName=jd_name, type="container", containerProperties=_container_props()
    )["revision"]
    jd_refs.append(f"{jd_name}:{rev1}")
    ctx.on_cleanup(lambda: _deregister_batch_jd(bat, f"{jd_name}:{rev1}"))
    assert rev1 == 1, f"first registration of a fresh name must be revision 1, got {rev1}"

    rev2 = bat.register_job_definition(
        jobDefinitionName=jd_name, type="container", containerProperties=_container_props()
    )["revision"]
    jd_refs.append(f"{jd_name}:{rev2}")
    ctx.on_cleanup(lambda: _deregister_batch_jd(bat, f"{jd_name}:{rev2}"))
    assert rev2 == 2, f"second registration of the same name must be revision 2, got {rev2}"

    bat.deregister_job_definition(jobDefinition=f"{jd_name}:{rev2}")
    deregistered = _poll_until(
        lambda: bat.describe_job_definitions(jobDefinitions=[f"{jd_name}:{rev2}"])["jobDefinitions"][0],
        lambda jd: jd["status"] == "INACTIVE",
        description=f"revision {rev2} of {jd_name} reaches INACTIVE",
    )
    assert deregistered["status"] == "INACTIVE", f"deregistered revision 2 is {deregistered['status']!r}"

    job_id = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"), jobQueue=jq_name, jobDefinition=jd_name
    )["jobId"]
    ctx.on_cleanup(lambda: _terminate(bat, job_id))

    described = bat.describe_jobs(jobs=[job_id])["jobs"][0]
    expected_jd_arn = f"arn:aws:batch:{ctx.region}:{ctx.account}:job-definition/{jd_name}:{rev1}"
    assert described["jobDefinition"] == expected_jd_arn, (
        f"a bare job-definition name must resolve to the latest ACTIVE revision "
        f"({expected_jd_arn}), got {described['jobDefinition']!r}"
    )

    code, message = _error(
        lambda: bat.submit_job(
            jobName=ctx.unique_name("sim2real-behav-job-"),
            jobQueue=jq_name,
            jobDefinition=f"{jd_name}:{rev2}",
        )
    )
    assert code == "ClientException", f"submitting against a deregistered revision: expected ClientException, got {code!r}"
    expected_jd2_arn = f"arn:aws:batch:{ctx.region}:{ctx.account}:job-definition/{jd_name}:{rev2}"
    expected_message = f"JobDefinition {expected_jd2_arn} is not in ACTIVE status."
    assert message == expected_message, (
        f"submitting against a deregistered revision: expected message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
