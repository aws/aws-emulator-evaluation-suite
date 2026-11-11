"""resource-policy-invalid-json-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-invalid-json-rejected"
GROUP = "representation"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with malformed JSON is rejected with InvalidArgumentException and
    leaves the previously-stored policy untouched; a subsequent valid update still succeeds."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"}
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    _wait_stream_active(ctx, kinesis, stream_name)
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
        "StreamARN"
    ]
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    original_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOriginalRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kinesis:DescribeStreamSummary",
                "Resource": stream_arn,
            }
        ],
    }
    kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=json.dumps(original_policy))
    ctx.on_cleanup(lambda: _safe_delete_policy(kinesis, stream_arn))

    code, message = _error(
        lambda: kinesis.put_resource_policy(ResourceARN=stream_arn, Policy="{not valid json at all")
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected_message = "Policy validation error: This policy contains invalid Json"
    assert message == expected_message, (
        f"malformed-JSON PutResourcePolicy message {message!r}, expected {expected_message!r}"
    )

    unchanged = json.loads(kinesis.get_resource_policy(ResourceARN=stream_arn)["Policy"])
    assert unchanged == original_policy, "malformed PutResourcePolicy call mutated the stored policy"

    # positive control: a subsequent, well-formed PutResourcePolicy must still take effect
    updated_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowUpdatedRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kinesis:GetRecords",
                "Resource": stream_arn,
            }
        ],
    }
    kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=json.dumps(updated_policy))
    fetched = json.loads(kinesis.get_resource_policy(ResourceARN=stream_arn)["Policy"])
    assert fetched == updated_policy, "valid PutResourcePolicy call (positive control) did not persist"


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


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete_policy(kinesis, stream_arn):
    try:
        kinesis.delete_resource_policy(ResourceARN=stream_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
