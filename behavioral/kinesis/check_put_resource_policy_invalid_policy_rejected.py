"""put-resource-policy-invalid-policy-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-resource-policy-invalid-policy-rejected"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy rejects valid JSON that is not a valid policy (Effect outside Allow/Deny)
    with InvalidArgumentException, keeps the stored policy, and accepts a later valid update."""
    kinesis = ctx.client("kinesis")
    stream = _create_provisioned_stream(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    root_principal = f"arn:aws:iam::{account_id}:root"

    # Positive control: a well-formed policy must be accepted and persisted before we ever
    # exercise the negative -- without this, "rejects a bad Effect" is indistinguishable from
    # "rejects every PutResourcePolicy".
    original_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOriginalDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": root_principal},
                "Action": "kinesis:DescribeStreamSummary",
                "Resource": stream["arn"],
            }
        ],
    }
    kinesis.put_resource_policy(ResourceARN=stream["arn"], Policy=json.dumps(original_policy))
    ctx.on_cleanup(lambda: _safe_delete_policy(kinesis, stream["arn"]))
    assert _current_resource_policy(kinesis, stream["arn"]) == original_policy, (
        "positive control: well-formed PutResourcePolicy call did not persist"
    )

    invalid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BadEffect",
                "Effect": "MaybeAllow",
                "Principal": {"AWS": root_principal},
                "Action": "kinesis:DescribeStreamSummary",
                "Resource": stream["arn"],
            }
        ],
    }
    code, message = _error(
        lambda: kinesis.put_resource_policy(ResourceARN=stream["arn"], Policy=json.dumps(invalid_policy))
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code!r}"
    expected_message = "Policy validation error: Invalid effect: MaybeAllow"
    assert message == expected_message, (
        f"invalid-Effect PutResourcePolicy message {message!r}, expected {expected_message!r}"
    )

    # Effect-absent: the invalid attempt must not have clobbered the previously-stored policy.
    policy_after = _current_resource_policy(kinesis, stream["arn"])
    assert policy_after == original_policy, (
        f"invalid PutResourcePolicy call mutated the stored policy, got Policy={policy_after!r}"
    )

    # And the write path itself is still healthy: a subsequent well-formed update must still
    # take effect, so the rejection above is a validation gate and not a wedged resource.
    updated_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowUpdatedRead",
                "Effect": "Allow",
                "Principal": {"AWS": root_principal},
                "Action": "kinesis:GetRecords",
                "Resource": stream["arn"],
            }
        ],
    }
    kinesis.put_resource_policy(ResourceARN=stream["arn"], Policy=json.dumps(updated_policy))
    assert _current_resource_policy(kinesis, stream["arn"]) == updated_policy, (
        "well-formed PutResourcePolicy call after the rejection (positive control) did not persist"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
    parsed = json.loads(policy)
    if not parsed:
        return None
    return parsed


def _safe_delete_policy(kinesis, arn):
    try:
        kinesis.delete_resource_policy(ResourceARN=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    name = ctx.unique_name("sim2real-behav-kpolneg-")
    kinesis.create_stream(StreamName=name, ShardCount=shard_count)

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
