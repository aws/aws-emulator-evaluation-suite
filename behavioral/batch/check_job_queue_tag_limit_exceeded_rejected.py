"""job-queue-tag-limit-exceeded-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-queue-tag-limit-exceeded-rejected"
GROUP = "representation"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource refuses 51 tags on a job queue with BadRequestException and applies none of them.

    Tagging the same queue with exactly 50 tags succeeds and persists (positive control).
    """
    batch = ctx.client("batch")
    iam = ctx.client("iam")

    role_arn = _create_batch_service_role(ctx, iam)

    ce_name = ctx.unique_name("sim2real-batch-tagcap-ce-")
    _create_compute_environment_with_retry(batch, ce_name, role_arn)
    ctx.on_cleanup(lambda: _disable_and_delete_compute_environment(ctx, ce_name))
    ce_arn = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"][0],
        lambda ce: ce["status"] == "VALID",
        timeout_s=60.0,
    )["computeEnvironmentArn"]

    jq_name = ctx.unique_name("sim2real-batch-tagcap-jq-")
    batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
    )
    ctx.on_cleanup(lambda: _disable_and_delete_job_queue(ctx, jq_name))
    jq_arn = _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=60.0,
    )["jobQueueArn"]

    too_many_tags = {f"key{i}": f"value{i}" for i in range(51)}
    code, message = _error(lambda: batch.tag_resource(resourceArn=jq_arn, tags=too_many_tags))
    assert code == "BadRequestException", f"expected BadRequestException for 51 tags, got {code!r}"
    expected_message = "The resultant tag set must not have more than 50 user tags."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_negative = batch.list_tags_for_resource(resourceArn=jq_arn)["tags"]
    assert after_negative == {}, f"tags were partially applied despite rejection: {after_negative}"

    # Positive control: exactly 50 tags is accepted and persists.
    exactly_50_tags = {f"key{i}": f"value{i}" for i in range(50)}
    batch.tag_resource(resourceArn=jq_arn, tags=exactly_50_tags)
    after_positive = batch.list_tags_for_resource(resourceArn=jq_arn)["tags"]
    assert after_positive == exactly_50_tags, "50-tag positive control did not persist correctly"


def _create_batch_service_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-batch-svcrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "batch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    import json as _json

    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_json.dumps(trust_policy)
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"],
        lambda arn: arn == role_arn,
        timeout_s=30.0,
        interval_s=2.0,
    )
    return role_arn


def _create_compute_environment_with_retry(batch, ce_name: str, role_arn: str) -> None:
    """A brand-new IAM role is not instantly assumable by Batch. Bounded retry, not a
    blind sleep: keep retrying CreateComputeEnvironment against the role until Batch
    itself reports the role is usable, or give up after a stated deadline."""
    deadline = time.monotonic() + 60.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            batch.create_compute_environment(
                computeEnvironmentName=ce_name, type="UNMANAGED", serviceRole=role_arn
            )
            return
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            transient = (
                "cannot be assumed" in msg
                or "not authorized to perform: sts:assumerole" in msg
                or "does not have permission" in msg
                or ("invalid" in msg and "role" in msg)
            )
            if not transient:
                raise
            last_exc = exc
            time.sleep(5.0)
    raise AssertionError(f"role {role_arn!r} never became assumable by Batch: {last_exc}")


def _error(fn) -> Any:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    so a target that accepts what AWS refuses is never reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _disable_and_delete_job_queue(ctx, jq_name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=jq_name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
            lambda jq: jq["status"] == "VALID" and jq["state"] == "DISABLED",
            timeout_s=60.0,
        )
        batch.delete_job_queue(jobQueue=jq_name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"],
        lambda jqs: not jqs or jqs[0]["status"] == "DELETED",
        timeout_s=180.0,
    )


#: The suite's cleanup budget; the retries of every teardown of one run share one deadline in it.
_CLEANUP_BUDGET_S = 900.0
_cleanup_deadlines: dict[int, tuple[object, float]] = {}


def _disable_and_delete_compute_environment(ctx, ce_name: str) -> None:
    """Disable and delete the compute environment, then wait until DescribeComputeEnvironments no
    longer lists it: the service role torn down after it must outlive the asynchronous delete.
    ClientException refusals (a queue still detaching, the CE still updating) retry every 2 s."""
    batch = ctx.client("batch")
    held = _cleanup_deadlines.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _cleanup_deadlines[id(ctx)] = (ctx, time.monotonic() + _CLEANUP_BUDGET_S)
    deadline = held[1]
    steps = [
        lambda: batch.update_compute_environment(computeEnvironment=ce_name, state="DISABLED"),
        lambda: batch.delete_compute_environment(computeEnvironment=ce_name),
    ]
    while True:
        listed = [
            ce
            for ce in batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"]
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
            raise TimeoutError(f"compute environment {ce_name} still listed at the cleanup deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
