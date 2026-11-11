"""subscribe-to-shard-missing-permission-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "subscribe-to-shard-missing-permission-denied"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c6", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubscribeToShard called by a principal that was never granted
    kinesis:SubscribeToShard is rejected with AccessDeniedException, and the
    same call with the caller's normal (permitted) credentials succeeds."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-efoperm-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"}
    )
    ctx.on_cleanup(lambda: _safe_delete_stream(kinesis, stream_name))
    summary = _wait_stream_active(kinesis, stream_name)
    stream_arn = summary["StreamARN"]
    shard_id = kinesis.list_shards(StreamARN=stream_arn)["Shards"][0]["ShardId"]
    probe_data = b"sim2real-behav-efoperm-probe"
    kinesis.put_record(StreamARN=stream_arn, Data=probe_data, PartitionKey="pk")

    consumer_name = ctx.unique_name("sim2real-behav-efopermconsumer-")
    consumer_arn = kinesis.register_stream_consumer(
        StreamARN=stream_arn,
        ConsumerName=consumer_name,
        Tags={"sim2real": "ga-depth-kinesis"},
    )["Consumer"]["ConsumerARN"]
    _wait_consumer_active(kinesis, stream_arn, consumer_arn)

    role_arn = _create_no_permission_role(ctx)
    unprivileged_kinesis = _assume_role_client(ctx, role_arn)

    code, message = _error(
        lambda: _open_subscription(
            unprivileged_kinesis, consumer_arn, shard_id, "TRIM_HORIZON"
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    role_name = role_arn.rsplit("/", 1)[1]
    expected_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/sim2real-behav-noperm is not "
        f"authorized to perform: kinesis:SubscribeToShard on resource: {consumer_arn} because no "
        f"identity-based policy allows the kinesis:SubscribeToShard action"
    )
    assert message == expected_message, (
        f"denied SubscribeToShard message {message!r}, expected {expected_message!r}"
    )

    # positive control: the identical call with the caller's normal (permitted)
    # credentials succeeds and actually delivers the record put above
    records = _open_subscription(kinesis, consumer_arn, shard_id, "TRIM_HORIZON")
    assert records, "positive-control subscription delivered no records"
    assert records[0]["Data"] == probe_data, (
        f"expected probe record {probe_data!r}, got {records[0]['Data']!r}"
    )


def _wait_stream_active(kinesis, stream_name: str, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} never became ACTIVE, last={summary}")


def _wait_consumer_active(kinesis, stream_arn: str, consumer_arn: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerARN=consumer_arn
        )["ConsumerDescription"]["ConsumerStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"consumer {consumer_arn} never became ACTIVE, last={status}")


def _create_no_permission_role(ctx) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-noperm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "ga-depth-kinesis"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # intentionally attach no permission policy: default-deny covers this check
    return role_arn


def _assume_role_client(ctx, role_arn: str, timeout_s: float = 30.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-behav-noperm"
            )["Credentials"]
            return ctx.client(
                "kinesis",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"could not assume role {role_arn} in time: {last_exc}")


def _open_subscription(
    kinesis, consumer_arn: str, shard_id: str, starting_type: str, max_events: int = 5
) -> list[dict[str, Any]]:
    resp = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn,
        ShardId=shard_id,
        StartingPosition={"Type": starting_type},
    )
    records: list[dict[str, Any]] = []
    for i, event in enumerate(resp["EventStream"]):
        if "SubscribeToShardEvent" in event:
            records.extend(event["SubscribeToShardEvent"]["Records"])
        if records or i >= max_events - 1:
            break
    return records


def _error(fn) -> tuple[str | None, str | None]:
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response.get("Error", {}).get("Code"), response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be denied, but it succeeded with {result!r}")


def _safe_delete_stream(kinesis, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
