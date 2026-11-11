"""resource-policy-document-byte-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-policy-document-byte-preserved"
GROUP = "representation"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The exact JSON policy document set via PutResourcePolicy, including
    nested structure, is returned unchanged (structurally) by GetResourcePolicy."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(ctx, name)
    stream_arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
        "StreamARN"
    ]
    account_id = stream_arn.split(":")[4]

    policy = {
        "Version": "2012-10-17",
        "Id": "sim2real-nested-policy",
        "Statement": [
            {
                "Sid": "AllowCrossAccountRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["kinesis:GetRecords", "kinesis:GetShardIterator"],
                "Resource": stream_arn,
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "Bool": {"aws:SecureTransport": "true"},
                },
            }
        ],
    }
    kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=json.dumps(policy))
    ctx.on_cleanup(lambda: kinesis.delete_resource_policy(ResourceARN=stream_arn))

    returned = json.loads(kinesis.get_resource_policy(ResourceARN=stream_arn)["Policy"])
    assert returned == policy, f"policy document not structurally preserved: put={policy!r} got={returned!r}"
    got_secure_transport = returned["Statement"][0]["Condition"]["Bool"]["aws:SecureTransport"]
    assert got_secure_transport == "true", (
        f"nested Condition.Bool.aws:SecureTransport not preserved: expected 'true', got {got_secure_transport!r}"
    )
    got_action = returned["Statement"][0]["Action"]
    expected_action = ["kinesis:GetRecords", "kinesis:GetShardIterator"]
    assert got_action == expected_action, f"Action list not preserved: expected {expected_action!r}, got {got_action!r}"


def _wait_stream_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
