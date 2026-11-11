"""resource-policy-large-json-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-policy-large-json-round-trip"
GROUP = "server-side"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy with unicode and whitespace in a Condition value round-trips byte-for-byte
    through Put/GetResourcePolicy, and after DeleteResourcePolicy the policy reads back as "{}"."""
    kinesis = ctx.client("kinesis")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-respolicy-")
    _wait_for_shard_capacity(kinesis)
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name))
    _wait_for_stream_active(ctx, name)
    stream_arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]

    # a Condition *string value* carries internal whitespace runs and unicode -- these survive
    # even if the surrounding JSON formatting is re-serialized/minified by the service. (Sid is
    # restricted to a narrower charset by the policy validator, so the payload goes in a
    # Condition value instead, which is opaque to the service and preserved verbatim.)
    marker = "AllowRead  \t 日本語 -  测试   nested\u00a0whitespace"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowConsumerRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStreamSummary"],
                "Resource": stream_arn,
                "Condition": {"StringEquals": {"aws:PrincipalTag/probe-marker": marker}},
            }
        ],
    }
    policy_json = json.dumps(policy, ensure_ascii=False)
    kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=policy_json)

    fetched = json.loads(kinesis.get_resource_policy(ResourceARN=stream_arn)["Policy"])
    fetched_marker = fetched["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalTag/probe-marker"]
    assert fetched_marker == marker, f"whitespace/unicode not preserved byte-for-byte: {fetched_marker!r} != {marker!r}"
    assert fetched["Statement"][0]["Resource"] == stream_arn, (
        f"resource mismatch after round-trip: {fetched['Statement'][0]['Resource']!r} != {stream_arn!r}"
    )

    kinesis.delete_resource_policy(ResourceARN=stream_arn)

    # A get issued right after delete can still return the just-deleted document (eventual
    # consistency), so poll until it is gone; a stream with no policy then answers with the
    # empty policy document "{}".
    timeout_s = max(1.0, min(240.0, (ctx.time_left() or 240.0) - 10.0))
    policy = _poll_for_revocation(kinesis, stream_arn, marker, timeout_s=timeout_s)
    assert json.loads(policy) == {}, f"expected the empty policy document after delete, got {policy!r}"


def _wait_for_shard_capacity(kinesis, needed=1, timeout_s=90.0):
    """Poll DescribeLimits until at least `needed` shards are free; DeleteStream releases
    OpenShardCount only eventually, so a momentary shortfall is waited out."""
    deadline = time.monotonic() + timeout_s
    limits = None
    while time.monotonic() < deadline:
        limits = kinesis.describe_limits()
        if limits["ShardLimit"] - limits["OpenShardCount"] >= needed:
            return limits
        time.sleep(3.0)
    raise AssertionError(
        f"shared account had no free shard capacity within {timeout_s}s "
        f"(ShardLimit={limits['ShardLimit'] if limits else '?'}, "
        f"OpenShardCount={limits['OpenShardCount'] if limits else '?'}); "
        "likely another large stream elsewhere in the account is still deleting"
    )


def _poll_for_revocation(kinesis, stream_arn, marker, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_policy = None
    while time.monotonic() < deadline:
        last_policy = kinesis.get_resource_policy(ResourceARN=stream_arn).get("Policy") or ""
        if marker not in last_policy:
            return last_policy
        time.sleep(interval_s)
    raise AssertionError(
        f"resource policy (probe marker still present) survived {timeout_s}s after "
        f"DeleteResourcePolicy: {last_policy!r}"
    )


def _wait_for_stream_active(ctx, name, timeout_s=180.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3.0)
    raise AssertionError(f"stream {name} did not reach ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
