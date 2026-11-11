"""job-queue-tag-unicode-value-round-trip."""
from __future__ import annotations

import json as _json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-queue-tag-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Job-queue tag values of the allowed ASCII charset and of unicode letters from several scripts
    round-trip byte-identically, while the same value plus one emoji is rejected with
    BadRequestException and leaves no partial tag applied.
    """
    batch = ctx.client("batch")
    iam = ctx.client("iam")

    role_arn = _create_batch_service_role(ctx, iam)

    ce_name = ctx.unique_name("sim2real-batch-unmanaged-ce-")
    batch.create_compute_environment(
        computeEnvironmentName=ce_name, type="UNMANAGED", serviceRole=role_arn
    )
    ctx.on_cleanup(lambda: _disable_and_delete_compute_environment(ctx, ce_name))
    ce_arn = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_name])[
            "computeEnvironments"
        ][0],
        lambda ce: ce["status"] == "VALID",
        # IAM role -> Batch control-plane propagation is eventually consistent; this
        # poll's own retries absorb that delay, so no separate grace sleep is needed.
        timeout_s=90.0,
    )["computeEnvironmentArn"]

    jq_name = ctx.unique_name("sim2real-batch-tag-jq-")
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

    # Positive control: the full allowed ASCII charset round-trips byte-identical.
    allowed_value = "Team A_1.prod:eu/west=1+beta-2@example"
    batch.tag_resource(resourceArn=jq_arn, tags={"Environment": allowed_value})
    after_ascii = batch.list_tags_for_resource(resourceArn=jq_arn)["tags"]
    assert after_ascii.get("Environment") == allowed_value, (
        f"allowed-charset tag value mutated in round-trip: {after_ascii.get('Environment')!r} != {allowed_value!r}"
    )

    # Contrast control: unicode *letters* from multiple scripts, plus precomposed
    # Latin accents, round-trip byte-identical -- the boundary is "letter", not
    # "ASCII". The allowed class is letters, numbers, spaces and ``_ . : / = + - @``.
    unicode_letters_value = "東京-café-Zürich-Ω"
    batch.tag_resource(resourceArn=jq_arn, tags={"Environment": unicode_letters_value})
    after_letters = batch.list_tags_for_resource(resourceArn=jq_arn)["tags"]
    assert after_letters.get("Environment") == unicode_letters_value, (
        f"unicode-letter tag value mutated in round-trip: {after_letters.get('Environment')!r} != {unicode_letters_value!r}"
    )

    # Negative boundary: appending a single emoji to the identical, otherwise-valid
    # string is rejected wholesale -- isolating the emoji, not the unicode letters,
    # as the cause.
    emoji_value = unicode_letters_value + "-🚀"
    code, message = _error(lambda: batch.tag_resource(resourceArn=jq_arn, tags={"Environment": emoji_value}))
    assert code == "BadRequestException", (
        f"expected BadRequestException rejecting a tag value containing an emoji, got {code!r}"
    )
    expected_message = (
        "Tags can only contain letters, numbers, spaces, and the following special characters: _ . : / = + - @"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    after_reject = batch.list_tags_for_resource(resourceArn=jq_arn)["tags"]
    assert after_reject.get("Environment") == unicode_letters_value, (
        f"rejected emoji tag value was nonetheless partially applied: {after_reject.get('Environment')!r}"
    )



# ===== helpers =====
def _error(fn) -> Any:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_json.dumps(trust_policy)
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # IAM role propagation to Batch's control plane is eventually consistent; get_role
    # succeeding is necessary but not sufficient, so the remaining margin is absorbed
    # by the CE-VALID poll's own 90s of retries, not an unconditional sleep.
    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"],
        lambda arn: arn == role_arn,
        timeout_s=30.0,
        interval_s=2.0,
    )
    return role_arn


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

