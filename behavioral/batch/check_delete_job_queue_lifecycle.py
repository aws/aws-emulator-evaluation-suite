"""delete-job-queue-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-job-queue-lifecycle"
GROUP = "error-semantics"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteJobQueue rejects an ENABLED queue, then succeeds once submissions are disabled."""
    batch = ctx.client("batch")
    subnet_ids, sg_id = _get_default_subnets_and_sg(ctx)
    ce_name = ctx.unique_name("sim2real-batch-ce-")
    queue_name = ctx.unique_name("sim2real-batch-jq-")

    ce_arn = batch.create_compute_environment(
        computeEnvironmentName=ce_name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": 4,
            "subnets": subnet_ids,
            "securityGroupIds": [sg_id],
        },
        tags=dict(_MANAGED_TAGS),
    )["computeEnvironmentArn"]
    ctx.on_cleanup(lambda: _force_delete_ce(batch, ce_name))
    _poll_until(
        lambda: _describe_ce(batch, ce_name),
        lambda e: e is not None and e["status"] == "VALID",
        timeout_s=180,
    )

    queue_arn = batch.create_job_queue(
        jobQueueName=queue_name,
        state="ENABLED",
        priority=1,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS),
    )["jobQueueArn"]
    ctx.on_cleanup(lambda: _force_delete_queue(batch, queue_name))
    queue = _poll_until(
        lambda: _describe_queue(batch, queue_name),
        lambda q: q is not None and q["status"] in ("VALID", "INVALID"),
        timeout_s=180,
    )
    assert queue["status"] == "VALID", f"job queue failed to validate: {queue}"
    assert queue["state"] == "ENABLED"

    # Negative: deleting an ENABLED (submissions-open) queue is rejected.
    code, message = _error_code(lambda: batch.delete_job_queue(jobQueue=queue_name))
    assert code == "ClientException", f"expected ClientException deleting ENABLED queue, got {code}"
    expected = "Cannot delete an enabled job queue, set the state to DISABLED first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_there = _describe_queue(batch, queue_name)
    assert still_there is not None and still_there["status"] != "DELETING"

    # Positive control: disable submissions, then the delete succeeds.
    batch.update_job_queue(jobQueue=queue_name, state="DISABLED")
    disabled = _poll_until(
        lambda: _describe_queue(batch, queue_name),
        lambda q: q is not None and q["state"] == "DISABLED" and q["status"] == "VALID",
        timeout_s=180,
    )
    assert disabled["state"] == "DISABLED"

    batch.delete_job_queue(jobQueue=queue_name)
    gone = _poll_until(
        lambda: _describe_queue(batch, queue_name),
        lambda q: q is None,
        timeout_s=180,
    )
    assert gone is None, "job queue still describable after successful delete"

    # A mutation on the now-dead id must also fail, not silently no-op.
    dead_code, dead_message = _error_code(lambda: batch.update_job_queue(jobQueue=queue_name, state="DISABLED"))
    assert dead_code == "ClientException", (
        f"expected ClientException updating a deleted job queue, got {dead_code!r}"
    )
    expected_dead = f"{queue_arn} does not exist."
    assert dead_message == expected_dead, f"expected message {expected_dead!r}, got {dead_message!r}"


def _get_default_subnets_and_sg(ctx) -> tuple[list[str], str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available for compute environment networking")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets in shared network")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group in shared network")
    return [s["SubnetId"] for s in subnets[:2]], sgs[0]["GroupId"]


def _describe_ce(batch: Any, name: str) -> dict[str, Any] | None:
    envs = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
    return envs[0] if envs else None


def _describe_queue(batch: Any, name: str) -> dict[str, Any] | None:
    queues = batch.describe_job_queues(jobQueues=[name])["jobQueues"]
    return queues[0] if queues else None


def _poll_until(probe, predicate, timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


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


def _force_delete_queue(batch: Any, name: str) -> None:
    queues = batch.describe_job_queues(jobQueues=[name])["jobQueues"]
    if not queues:
        return
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_refused(lambda: batch.delete_job_queue(jobQueue=name), timeout_s=120)


def _force_delete_ce(batch: Any, name: str) -> None:
    envs = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
    if not envs:
        return
    try:
        batch.update_compute_environment(computeEnvironment=name, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_refused(lambda: batch.delete_compute_environment(computeEnvironment=name), timeout_s=180)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
