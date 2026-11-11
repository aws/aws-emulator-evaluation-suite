"""get-resource-policy-without-policy-fails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resource-policy-without-policy-fails"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a stream with no policy succeeds with "{}", not an error; a missing
    stream fails with ResourceNotFoundException, and an attached policy is returned as set."""
    kinesis = ctx.client("kinesis")
    name, stream_arn = _create_active_stream(ctx)

    # No policy attached is a success with an empty-object document, not an error.
    resp = kinesis.get_resource_policy(ResourceARN=stream_arn)
    fetched = json.loads(resp["Policy"])
    assert fetched == {}, f"expected an empty policy document, got {fetched!r}"

    # Contrast: a resource that truly does not exist DOES raise ResourceNotFoundException
    # (the not-found error is about the STREAM, not the absence of a policy).
    bogus_arn = stream_arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("sim2real-kinesis-missing-")
    code, message = _error(lambda: kinesis.get_resource_policy(ResourceARN=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Stream {bogus_arn.rsplit('/', 1)[1]} under account {ctx.account} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SelfDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kinesis:DescribeStreamSummary",
                "Resource": stream_arn,
            }
        ],
    }
    kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _delete_policy_ignore_missing(kinesis, stream_arn))

    fetched = json.loads(kinesis.get_resource_policy(ResourceARN=stream_arn)["Policy"])
    assert fetched["Statement"][0]["Sid"] == "SelfDescribe", (
        f"expected the just-attached policy statement 'SelfDescribe', got {fetched!r}"
    )


def _create_active_stream(ctx, shard_count: int = 1) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinesis-")
    kinesis.create_stream(
        StreamName=name,
        ShardCount=shard_count,
        StreamModeDetails={"StreamMode": "PROVISIONED"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    arn = _wait_stream_active(ctx, name)
    return name, arn


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        last_status = desc["StreamStatus"]
        if last_status == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(interval_s)
    raise AssertionError(f"stream never became ACTIVE (last status={last_status})")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _delete_policy_ignore_missing(kinesis, stream_arn: str) -> None:
    try:
        kinesis.delete_resource_policy(ResourceARN=stream_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
