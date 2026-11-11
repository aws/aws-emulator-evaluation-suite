"""put-resource-policy-overwrites-previous-policy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-resource-policy-overwrites-previous-policy"
GROUP = "concurrency"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second PutResourcePolicy call fully REPLACES the prior policy document
    rather than merging statements into it (AWS docs: "Updating an existing
    resource-based policy means replacing the existing one")."""
    kinesis = ctx.client("kinesis")
    name, stream_arn = _create_active_stream(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    root_principal = f"arn:aws:iam::{account_id}:root"

    policy_one = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "StatementOne",
                "Effect": "Allow",
                "Principal": {"AWS": root_principal},
                "Action": "kinesis:DescribeStreamSummary",
                "Resource": stream_arn,
            }
        ],
    }
    kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=json.dumps(policy_one))
    ctx.on_cleanup(lambda: kinesis.delete_resource_policy(ResourceARN=stream_arn))

    fetched_one = json.loads(kinesis.get_resource_policy(ResourceARN=stream_arn)["Policy"])
    sids_one = {stmt["Sid"] for stmt in fetched_one["Statement"]}
    assert sids_one == {"StatementOne"}, f"unexpected initial statements: {sids_one}"

    policy_two = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "StatementTwo",
                "Effect": "Allow",
                "Principal": {"AWS": root_principal},
                "Action": "kinesis:ListShards",
                "Resource": stream_arn,
            }
        ],
    }
    kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=json.dumps(policy_two))

    fetched_two = json.loads(kinesis.get_resource_policy(ResourceARN=stream_arn)["Policy"])
    sids_two = {stmt["Sid"] for stmt in fetched_two["Statement"]}
    assert sids_two == {"StatementTwo"}, (
        f"second PutResourcePolicy should fully replace the document, got statements {sids_two}"
    )
    assert "StatementOne" not in sids_two, "prior statement survived a full-replace PutResourcePolicy"


def _create_active_stream(ctx, shard_count: int = 1) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinesis-")
    kinesis.create_stream(
        StreamName=name,
        ShardCount=shard_count,
        StreamModeDetails={"StreamMode": "PROVISIONED"},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
