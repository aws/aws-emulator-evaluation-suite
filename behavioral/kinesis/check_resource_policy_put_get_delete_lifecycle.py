"""resource-policy-put-get-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-put-get-delete-lifecycle"
GROUP = "resource-policy"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy makes a policy retrievable via GetResourcePolicy, and
    DeleteResourcePolicy removes it, yielding a not-found on a subsequent get."""
    kinesis = ctx.client("kinesis")
    stream = _create_provisioned_stream(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # No resource policy exists yet. On real AWS, GetResourcePolicy for a resource with no
    # policy attached succeeds and returns Policy="{}" (an empty JSON object) rather than
    # raising ResourceNotFoundException or omitting the field entirely.
    initial_policy = _current_resource_policy(kinesis, stream["arn"])
    assert initial_policy is None, f"expected no policy initially, got Policy={initial_policy!r}"

    sid = ctx.unique_name("sim2real-behav-policy-").replace("-", "")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kinesis:DescribeStreamSummary",
                "Resource": stream["arn"],
            }
        ],
    }
    kinesis.put_resource_policy(ResourceARN=stream["arn"], Policy=json.dumps(policy_doc))

    fetched = _poll_until(
        lambda: kinesis.get_resource_policy(ResourceARN=stream["arn"])["Policy"],
        lambda p: p is not None,
        timeout_s=30,
        interval_s=2,
    )
    fetched_doc = json.loads(fetched)
    assert fetched_doc["Statement"][0]["Sid"] == sid
    assert fetched_doc["Statement"][0]["Action"] == "kinesis:DescribeStreamSummary"

    kinesis.delete_resource_policy(ResourceARN=stream["arn"])

    def _probe():
        return _current_resource_policy(kinesis, stream["arn"])

    final_policy = _poll_until(_probe, lambda p: p is None, timeout_s=30, interval_s=2)
    assert final_policy is None, f"expected no policy after delete, got Policy={final_policy!r}"

    # The identifier is now truly gone, not just absent from one read: a second delete on the
    # same (now policy-less) resource must fail rather than silently no-op.
    second_delete_code, second_delete_message = _error(
        lambda: kinesis.delete_resource_policy(ResourceARN=stream["arn"])
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on double delete, got {second_delete_code!r}"
    )
    expected_message = f"No resource policy found for resource ARN {stream['arn']}."
    assert second_delete_message == expected_message, (
        f"double DeleteResourcePolicy message {second_delete_message!r}, expected {expected_message!r}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, but the call succeeded")


def _current_resource_policy(kinesis, arn):
    try:
        resp = kinesis.get_resource_policy(ResourceARN=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise
    policy = resp.get("Policy") or None
    if policy is None:
        return None
    # Real AWS represents "no policy attached" as Policy="{}" (a syntactically valid but empty
    # JSON object) rather than omitting the field -- normalize that to "no policy" like the
    # omitted-field/ResourceNotFoundException cases above.
    try:
        parsed = json.loads(policy)
    except (TypeError, ValueError):
        return policy
    if not parsed:
        return None
    return policy


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_provisioned_stream(ctx, shard_count=1):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kpol-")
    kinesis.create_stream(
        StreamName=name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"}
    )

    def _cleanup():
        try:
            kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
