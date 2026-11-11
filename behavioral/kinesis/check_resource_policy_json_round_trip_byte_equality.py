"""resource-policy-json-round-trip-byte-equality."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-policy-json-round-trip-byte-equality"
GROUP = "representation"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy JSON document written via PutResourcePolicy is returned with the
    exact same statements/values by GetResourcePolicy (whitespace/key-order tolerant)."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    _wait_stream_active(ctx, kinesis, stream_name)
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
        "StreamARN"
    ]
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["kinesis:DescribeStreamSummary", "kinesis:GetRecords"],
                "Resource": stream_arn,
            }
        ],
    }
    # deliberately pretty-print with nested indentation/whitespace to prove the
    # service normalizes formatting rather than corrupting content.
    policy_json = json.dumps(policy_doc, indent=4, sort_keys=True)
    kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=policy_json)
    ctx.on_cleanup(lambda: kinesis.delete_resource_policy(ResourceARN=stream_arn))

    fetched_raw = _wait_for_policy(ctx, kinesis, stream_arn)
    fetched = json.loads(fetched_raw)
    assert fetched == policy_doc, f"policy round-trip mismatch: {fetched!r} != {policy_doc!r}"


def _wait_stream_active(ctx, kinesis, stream_name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _wait_for_policy(ctx, kinesis, stream_arn, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return kinesis.get_resource_policy(ResourceARN=stream_arn)["Policy"]
        except Exception as exc:  # noqa: BLE001 - retry until propagated
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"resource policy never became readable: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
