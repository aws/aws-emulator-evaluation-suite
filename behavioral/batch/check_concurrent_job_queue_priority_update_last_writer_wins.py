"""concurrent-job-queue-priority-update-last-writer-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-job-queue-priority-update-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateJobQueue priority changes on the same queue converge to a single
    consistent final priority (one of the submitted values) with no lost/corrupted/interleaved
    partial write, rather than oscillating or landing on a value nobody requested."""
    batch = ctx.client("batch")

    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    ce_arn, _ = _create_fargate_compute_environment(ctx, ctx.unique_name("sim2real-batch-ce-"), subnet_id, sg_id, max_vcpus=1)
    jq_arn = _create_job_queue(ctx, ctx.unique_name("sim2real-batch-jq-"), [{"order": 1, "computeEnvironment": ce_arn}], priority=1)

    submitted_priorities = [10, 20, 30, 40, 50, 60]

    def _update(p: int):
        try:
            batch.update_job_queue(jobQueue=jq_arn, priority=p)
            return ("ok", p)
        except Exception as exc:  # AWS Batch serializes updates; concurrent racers may be rejected
            return ("error", str(exc))

    with ThreadPoolExecutor(max_workers=len(submitted_priorities)) as pool:
        results = list(pool.map(_update, submitted_priorities))

    successes = [p for status, p in results if status == "ok"]
    assert successes, f"expected at least one concurrent UpdateJobQueue call to succeed, got {results}"

    # Wait for the queue to settle out of UPDATING back to a stable VALID status.
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"][0]["status"],
        lambda s: s == "VALID",
        timeout_s=120,
        interval_s=3,
    )

    # Convergence check: poll (bounded) until the same priority value is observed on several
    # consecutive samples, rather than trusting a single fixed-delay snapshot.
    final_priority = _poll_stable(
        lambda: batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"][0]["priority"],
        timeout_s=60.0,
        interval_s=3.0,
        required_consecutive=3,
    )
    assert isinstance(final_priority, int) and final_priority in submitted_priorities, (
        f"final priority {final_priority} is not one of the concurrently submitted values {submitted_priorities}"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _poll_stable(probe, timeout_s=60.0, interval_s=3.0, required_consecutive=3):
    """Poll (bounded) until `probe()` returns the same value on `required_consecutive` samples
    in a row, proving convergence rather than trusting a single fixed-delay snapshot."""
    deadline = time.monotonic() + timeout_s
    last = None
    streak = 0
    while time.monotonic() < deadline:
        current = probe()
        if current == last:
            streak += 1
            if streak >= required_consecutive:
                return current
        else:
            streak = 1
            last = current
        time.sleep(interval_s)
    raise AssertionError(
        f"value never stabilized within {timeout_s}s (required {required_consecutive} consecutive "
        f"matches); last value={last!r}, streak={streak}"
    )


def _default_subnet_and_sg(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available for an AWS Batch Fargate compute environment")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets in the shared network")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _create_fargate_compute_environment(ctx, name, subnet_id, sg_id, max_vcpus=4):
    batch = ctx.client("batch")
    ce_arn = batch.create_compute_environment(
        computeEnvironmentName=name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": max_vcpus,
            "subnets": [subnet_id],
            "securityGroupIds": [sg_id],
        },
        tags=_MANAGED_TAGS,
    )["computeEnvironmentArn"]
    ctx.on_cleanup(lambda: _delete_compute_environment(ctx, ce_arn))
    detail = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_arn])["computeEnvironments"][0],
        lambda d: d["status"] in ("VALID", "INVALID"),
        timeout_s=120,
    )
    assert detail["status"] == "VALID", f"compute environment failed to become VALID: {detail.get('statusReason')}"
    return ce_arn, detail.get("ecsClusterArn")


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


def _delete_compute_environment(ctx, ce_arn):
    batch = ctx.client("batch")
    try:
        batch.update_compute_environment(computeEnvironment=ce_arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_arn])["computeEnvironments"][0]["status"],
        lambda s: s == "VALID",
        timeout_s=120,
    )
    _retry_refused(lambda: batch.delete_compute_environment(computeEnvironment=ce_arn), timeout_s=100)


def _create_job_queue(ctx, name, ce_order, priority=1):
    batch = ctx.client("batch")
    jq_arn = batch.create_job_queue(
        jobQueueName=name, state="ENABLED", priority=priority, computeEnvironmentOrder=ce_order, tags=_MANAGED_TAGS
    )["jobQueueArn"]
    ctx.on_cleanup(lambda: _delete_job_queue(ctx, jq_arn))
    detail = _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"][0],
        lambda d: d["status"] in ("VALID", "INVALID"),
        timeout_s=120,
    )
    assert detail["status"] == "VALID", f"job queue failed to become VALID: {detail.get('statusReason')}"
    return jq_arn


def _delete_job_queue(ctx, jq_arn):
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=jq_arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"][0]["status"],
        lambda s: s == "VALID",
        timeout_s=120,
    )
    _retry_refused(lambda: batch.delete_job_queue(jobQueue=jq_arn), timeout_s=100)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
