"""resource-policy-put-get-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")

def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )

def _wait_stream_ready(c, name, timeout_s=150):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 90, 2, f"stream {name} shards addressable")

def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

def _stream_arn(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]

CHECK = "resource-policy-put-get-delete"
GROUP = 'resource-policy'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy / GetResourcePolicy / DeleteResourcePolicy round-trip; after delete the
    granted statement is revoked (policy gone or no longer containing it).
    """
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    stream_arn = _stream_arn(c, name)

    # Kinesis validates that the policy principal actually resolves, so a placeholder account is
    # rejected with InvalidArgumentException("Invalid principal in policy document"). Derive the real
    # account/partition from the stream ARN rather than hardcoding one.
    arn_parts = stream_arn.split(":")
    partition, account_id = arn_parts[1], arn_parts[4]
    policy = (
        '{"Version":"2012-10-17","Statement":[{"Sid":"FidelityProbe","Effect":"Allow",'
        f'"Principal":{{"AWS":"arn:{partition}:iam::{account_id}:root"}},'
        f'"Action":"kinesis:GetRecords","Resource":"{stream_arn}"}}]}}'
    )
    c.put_resource_policy(ResourceARN=stream_arn, Policy=policy)

    # Resource-policy reads are eventually consistent, so poll rather than assuming Put is immediately
    # visible to Get.
    got = _poll(
        lambda: c.get_resource_policy(ResourceARN=stream_arn),
        lambda r: "kinesis:GetRecords" in r["Policy"],
        timeout_s=90,
        interval_s=3,
        description="PutResourcePolicy visible to GetResourcePolicy",
    )
    assert json.loads(got["Policy"]) == json.loads(policy), (
        f"expected the put policy document back, got Policy={got['Policy']!r}"
    )

    c.delete_resource_policy(ResourceARN=stream_arn)

    # Deletion is eventually consistent; once the grant is gone the stream answers with the empty
    # policy document "{}", never an error.
    final = _poll(
        lambda: c.get_resource_policy(ResourceARN=stream_arn)["Policy"],
        lambda pol: "kinesis:GetRecords" not in pol,
        timeout_s=120,
        interval_s=3,
        description="DeleteResourcePolicy revokes the granted statement",
    )
    assert json.loads(final) == {}, f"expected the empty policy document after delete, got {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
