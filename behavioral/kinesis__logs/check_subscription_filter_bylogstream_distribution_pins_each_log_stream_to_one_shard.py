"""subscription-filter-bylogstream-distribution-pins-each-log-stream-to-one-shard."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscription-filter-bylogstream-distribution-pins-each-log-stream-to-one-shard"
GROUP = "e2e"
SERVICES = ["kinesis", "logs"]

# The partition-key derivation is undocumented, so the rule (one key per log stream) is asserted,
# not a literal; two log streams may share a shard on a 2-shard stream, so distinct shards are not.

_SHARD_COUNT = 2
#: Rounds of PutLogEvents, so more than one delivery batch per log stream is possible.
_ROUNDS = 4
_EVENTS_PER_ROUND = 2
_ROUND_GAP_S = 4.0
_DELIVERY_BUDGET_S = 240.0
_POLL_INTERVAL_S = 10.0
#: The gzip magic number. Asserted directly so a failure can say what the first bytes really were.
_GZIP_MAGIC = b"\x1f\x8b"


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudWatch Logs subscription filter with distribution=ByLogStream routes every batch from
    one log stream to one Kinesis partition key — and therefore one shard — so each log stream's
    events keep their order, while a different log stream gets a different key."""
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stream = _create_active_stream(ctx, shard_count=_SHARD_COUNT)
    shard_ids = _shard_ids(ctx, stream["name"], expect=_SHARD_COUNT)
    role_arn = _create_logs_delivery_role(ctx, stream["arn"])

    log_group = ctx.unique_name("sim2real-xsvc-lg-")
    logs.create_log_group(
        logGroupName=log_group, tags={"sim2real": "behavioral", "sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    log_stream_a = "stream-alpha"
    log_stream_b = "stream-bravo"
    for log_stream in (log_stream_a, log_stream_b):
        logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    filter_name = ctx.unique_name("sim2real-xsvc-sf-")
    _retry_invalid_parameter(
        lambda: logs.put_subscription_filter(
            logGroupName=log_group,
            filterName=filter_name,
            filterPattern="",
            destinationArn=stream["arn"],
            roleArn=role_arn,
            distribution="ByLogStream",
        ),
        timeout_s=120.0,
        description=(
            "PutSubscriptionFilter to be accepted once the IAM role's trust and kinesis:PutRecord "
            "grant have propagated (CloudWatch Logs validates the destination synchronously)"
        ),
    )
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(
            logGroupName=log_group, filterName=filter_name
        )
    )
    described = logs.describe_subscription_filters(
        logGroupName=log_group, filterNamePrefix=filter_name
    )["subscriptionFilters"]
    assert len(described) == 1, (
        f"DescribeSubscriptionFilters returned {len(described)} filters for prefix {filter_name!r}; "
        "expected exactly 1"
    )
    assert described[0]["distribution"] == "ByLogStream", (
        f"the filter reports distribution {described[0].get('distribution')!r}; expected "
        "'ByLogStream' — the rest of this check is only meaningful if the setting stuck"
    )

    # ---- Produce interleaved traffic on two log streams ----
    expected: dict[str, list[str]] = {log_stream_a: [], log_stream_b: []}
    for round_index in range(_ROUNDS):
        for log_stream in (log_stream_a, log_stream_b):
            messages = [
                f"{log_stream}|r{round_index}|e{event_index}"
                for event_index in range(_EVENTS_PER_ROUND)
            ]
            now_ms = int(time.time() * 1000)
            logs.put_log_events(
                logGroupName=log_group,
                logStreamName=log_stream,
                logEvents=[
                    {"timestamp": now_ms + offset, "message": message}
                    for offset, message in enumerate(messages)
                ],
            )
            expected[log_stream].extend(messages)
        # Pacing so Logs has a chance to emit more than one delivery batch per log stream.
        time.sleep(_ROUND_GAP_S)

    total_expected = sum(len(v) for v in expected.values())

    # ---- Terminal read at the CONSUMER: drain both Kinesis shards ----
    def _drain() -> list[dict]:
        return _read_all_shards(ctx, stream["name"], shard_ids)

    records = _poll_until(
        _drain,
        lambda rows: sum(len(r["messages"]) for r in rows) >= total_expected,
        timeout_s=_DELIVERY_BUDGET_S,
        interval_s=_POLL_INTERVAL_S,
        description=(
            f"all {total_expected} log events to be delivered to the {_SHARD_COUNT}-shard Kinesis "
            f"destination stream {stream['name']}"
        ),
    )

    # ---- Group what arrived by the log stream the envelope names ----
    keys_by_log_stream: dict[str, set[str]] = {log_stream_a: set(), log_stream_b: set()}
    shards_by_log_stream: dict[str, set[str]] = {log_stream_a: set(), log_stream_b: set()}
    order_by_log_stream: dict[str, list[str]] = {log_stream_a: [], log_stream_b: []}
    batches_by_log_stream: dict[str, int] = {log_stream_a: 0, log_stream_b: 0}

    for row in records:
        log_stream = row["log_stream"]
        assert log_stream in keys_by_log_stream, (
            f"a delivered envelope names logStream {log_stream!r}; expected one of "
            f"{[log_stream_a, log_stream_b]}"
        )
        assert row["log_group"] == log_group, (
            f"a delivered envelope names logGroup {row['log_group']!r}; expected {log_group!r}"
        )
        assert row["owner"] == account, (
            f"a delivered envelope names owner {row['owner']!r}; expected the caller account "
            f"{account!r}"
        )
        assert row["subscription_filters"] == [filter_name], (
            f"a delivered envelope names subscriptionFilters {row['subscription_filters']!r}; "
            f"expected exactly [{filter_name!r}]"
        )
        keys_by_log_stream[log_stream].add(row["partition_key"])
        shards_by_log_stream[log_stream].add(row["shard_id"])
        order_by_log_stream[log_stream].extend(row["messages"])
        batches_by_log_stream[log_stream] += 1

    # ---- Completeness: the positive control that this wiring delivers at all ----
    for log_stream, messages in expected.items():
        assert order_by_log_stream[log_stream] == messages, (
            f"log stream {log_stream!r} was delivered {order_by_log_stream[log_stream]!r}; expected "
            f"exactly {messages!r} in that order. ByLogStream confines a log stream to one shard, "
            "and one Kinesis shard preserves write order, so the order is part of the contract"
        )

    # ---- THE PROPERTY: one partition key per log stream, and the two differ ----
    keys_a = keys_by_log_stream[log_stream_a]
    keys_b = keys_by_log_stream[log_stream_b]
    assert len(keys_a) == 1, (
        f"log stream {log_stream_a!r} arrived under {len(keys_a)} distinct Kinesis partition keys "
        f"{sorted(keys_a)} across {batches_by_log_stream[log_stream_a]} record(s); ByLogStream must "
        "use ONE key per log stream"
    )
    assert len(keys_b) == 1, (
        f"log stream {log_stream_b!r} arrived under {len(keys_b)} distinct Kinesis partition keys "
        f"{sorted(keys_b)} across {batches_by_log_stream[log_stream_b]} record(s); ByLogStream must "
        "use ONE key per log stream"
    )
    assert keys_a != keys_b, (
        f"both log streams arrived under the SAME partition key {sorted(keys_a)}; ByLogStream must "
        "derive the key FROM the log stream, so two different log streams must differ. A constant "
        "key would distribute nothing"
    )
    assert len(shards_by_log_stream[log_stream_a]) == 1, (
        f"log stream {log_stream_a!r} was spread across shards "
        f"{sorted(shards_by_log_stream[log_stream_a])}; ByLogStream must confine it to one"
    )
    assert len(shards_by_log_stream[log_stream_b]) == 1, (
        f"log stream {log_stream_b!r} was spread across shards "
        f"{sorted(shards_by_log_stream[log_stream_b])}; ByLogStream must confine it to one"
    )

    # ---- Always-invalid input: an out-of-vocabulary distribution is refused, changing nothing ----
    # The accepted ByLogStream call above is the positive control; there is no restore beat because
    # "ByShard" can never become a legal value.
    err = _client_error(
        lambda: logs.put_subscription_filter(
            logGroupName=log_group,
            filterName=filter_name,
            filterPattern="",
            destinationArn=stream["arn"],
            roleArn=role_arn,
            distribution="ByShard",
        )
    )
    assert err.get("Code") == "InvalidParameterException", (
        "PutSubscriptionFilter with distribution='ByShard' must be refused; expected "
        f"InvalidParameterException, got {err.get('Code')!r}: {err.get('Message')!r}"
    )
    assert err.get("Message") == (
        "1 validation error detected: Value at 'distribution' failed to satisfy constraint: "
        "Member must satisfy enum value set: [Random, ByLogStream]"
    ), f"PutSubscriptionFilter with distribution='ByShard' returned message {err.get('Message')!r}"
    after = logs.describe_subscription_filters(
        logGroupName=log_group, filterNamePrefix=filter_name
    )["subscriptionFilters"]
    assert len(after) == 1 and after[0]["distribution"] == "ByLogStream", (
        f"after the refused update the filter reports {after!r}; expected the single unchanged "
        "ByLogStream filter — a rejected PutSubscriptionFilter must not half-apply"
    )



def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observation: {last!r}"
    )


def _client_error(fn) -> dict:
    """Return the botocore Error dict. An unexpected SUCCESS raises, because an emulator ACCEPTING
    input real AWS refuses must not be reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _retry_invalid_parameter(fn, *, timeout_s: float, description: str):
    """Retry through IAM trust/permission propagation, which surfaces as InvalidParameterException.

    Re-raises the last exception past the deadline — it never swallows the failure.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"timed out after {timeout_s}s waiting for {description}; last error: "
                    f"{exc.response.get('Error', {})!r}"
                ) from exc
            time.sleep(5.0)


def _create_active_stream(ctx, *, shard_count: int) -> dict[str, str]:
    """Create-or-adopt a provisioned stream, tagged, and wait until it is ACTIVE."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-xsvc-kds-")
    try:
        kinesis.create_stream(
            StreamName=name,
            ShardCount=shard_count,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
            Tags={"sim2real": "behavioral", "sim2real-check": CHECK},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
            raise
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=240.0,
        interval_s=3.0,
        description=f"stream {name} to reach ACTIVE",
    )
    return {"name": name, "arn": summary["StreamARN"]}


def _shard_ids(ctx, stream_name: str, *, expect: int) -> list[str]:
    kinesis = ctx.client("kinesis")

    def probe() -> list:
        try:
            return kinesis.list_shards(StreamName=stream_name)["Shards"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ResourceInUseException", "ResourceNotFoundException"):
                return []
            raise

    shards = _poll_until(
        probe,
        lambda s: len(s) == expect,
        timeout_s=120.0,
        interval_s=3.0,
        description=f"exactly {expect} shards to be addressable on {stream_name}",
    )
    return [s["ShardId"] for s in shards]


def _create_logs_delivery_role(ctx, stream_arn: str) -> str:
    """An IAM role CloudWatch Logs can assume to PutRecord(s) into this one stream."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-logs-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[
            {"Key": "sim2real", "Value": "behavioral"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )["Role"]["Arn"]
    policy_name = "kinesis-write"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                        "Resource": stream_arn,
                    }
                ],
            }
        ),
    )
    # LIFO teardown: the inline policy must go before the role.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _read_all_shards(ctx, stream_name: str, shard_ids: list[str]) -> list[dict]:
    """Every DATA_MESSAGE envelope on every shard, with the Kinesis routing that carried it.

    CloudWatch Logs' synchronous destination validation also puts a CONTROL_MESSAGE on the stream;
    it is filtered out here.
    """
    kinesis = ctx.client("kinesis")
    rows: list[dict] = []
    for shard_id in shard_ids:
        iterator = kinesis.get_shard_iterator(
            StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        for _ in range(20):
            resp = kinesis.get_records(ShardIterator=iterator, Limit=1000)
            for record in resp["Records"]:
                blob = record["Data"]
                assert blob[:2] == _GZIP_MAGIC, (
                    f"a CloudWatch Logs record on {shard_id} does not start with the gzip magic "
                    f"{_GZIP_MAGIC!r}; its first bytes are {blob[:8]!r}. Logs compresses every "
                    "subscription payload with GZIP"
                )
                envelope = json.loads(gzip.decompress(blob))
                if envelope["messageType"] != "DATA_MESSAGE":
                    continue
                rows.append(
                    {
                        "shard_id": shard_id,
                        "partition_key": record["PartitionKey"],
                        "log_group": envelope["logGroup"],
                        "log_stream": envelope["logStream"],
                        "owner": envelope["owner"],
                        "subscription_filters": envelope["subscriptionFilters"],
                        "messages": [e["message"] for e in envelope["logEvents"]],
                    }
                )
            next_iterator = resp.get("NextShardIterator")
            if not next_iterator or not resp["Records"]:
                break
            iterator = next_iterator
            time.sleep(0.5)  # 5 TPS/shard cap; a pacer, not a wait for an effect.
    return rows


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
