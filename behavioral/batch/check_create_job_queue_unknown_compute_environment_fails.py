"""create-job-queue-unknown-compute-environment-fails."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-job-queue-unknown-compute-environment-fails"
GROUP = 'error-semantics'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateJobQueue succeeds against a valid compute environment and is rejected when it
    references a non-existent one, so an unresolvable compute environment reference is a real 400
    boundary."""
    batch = ctx.client("batch")
    ce = _create_unmanaged_ce(ctx)
    good_queue = _create_job_queue(ctx, ce["arn"])
    live = _describe_jq(batch, good_queue["name"])
    assert live is not None and live["computeEnvironmentOrder"][0]["computeEnvironment"] == ce["arn"], (
        f"positive control: CreateJobQueue with a real compute environment must succeed "
        f"and be readable back, got {live!r}"
    )

    bogus_suffix = ctx.unique_name("sim2real-behav-ce-missing-")
    # The caller's own account, so the reference is unresolvable rather than foreign-owned.
    bogus_arn = f"arn:aws:batch:{ctx.region}:{ctx.account}:compute-environment/{bogus_suffix}"
    bad_name = ctx.unique_name("sim2real-behav-jq-badce-")
    code, message, request_id = _error_code(lambda: batch.create_job_queue(
        jobQueueName=bad_name,
        state="ENABLED",
        priority=1,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": bogus_arn}],
    ))
    assert code == "ClientException", (
        f"expected ClientException for unresolvable computeEnvironment, got {code!r}"
    )
    expected_message = (
        "Compute Environments must be created and valid before attaching them to a job queue"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert _describe_jq(batch, bad_name) is None, (
        f"rejected CreateJobQueue must not leave a job queue behind, found {bad_name!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available and must not be reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _describe_jq(batch, name):
    qs = batch.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _describe_ce(batch, name):
    ces = batch.describe_compute_environments(computeEnvironments=[name]).get("computeEnvironments", [])
    return ces[0] if ces else None


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last state={last!r}")


def _poll_ce_status(ctx, name, target_statuses, timeout_s=90.0):
    batch = ctx.client("batch")
    return _poll_until(
        lambda: _describe_ce(batch, name),
        lambda ce: ce is not None and ce["status"] in target_statuses,
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"compute environment {name} status in {sorted(target_statuses)}",
    )


def _poll_jq_status(ctx, name, target_statuses, timeout_s=90.0):
    batch = ctx.client("batch")
    return _poll_until(
        lambda: _describe_jq(batch, name),
        lambda jq: jq is not None and jq["status"] in target_statuses,
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"job queue {name} status in {sorted(target_statuses)}",
    )


def _delete_role(ctx, role_name: str, policy_arn: str) -> None:
    iam = ctx.client("iam")
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


def _create_batch_service_role(ctx) -> str:
    """Real AWS Batch requires an explicit serviceRole for CreateComputeEnvironment (even for
    UNMANAGED environments) unless the account already has one on file; create a minimal one
    inline."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-batch-svcrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "batch.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, policy_arn))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


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
    name = ctx.unique_name("sim2real-behav-ce-goodce-")
    service_role_arn = _create_batch_service_role(ctx)
    resp = _create_compute_environment_with_role(ctx, name, service_role_arn)
    ctx.on_cleanup(lambda: _teardown_ce(ctx, batch, name))
    _poll_ce_status(ctx, name, {"VALID"})
    return {"name": name, "arn": resp["computeEnvironmentArn"]}


def _create_job_queue(ctx, ce_arn: str, priority: int = 1) -> dict[str, Any]:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-behav-jq-goodce-")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
