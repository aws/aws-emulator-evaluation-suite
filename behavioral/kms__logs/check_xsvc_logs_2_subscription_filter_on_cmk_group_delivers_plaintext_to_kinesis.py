"""xsvc-logs-2-subscription-filter-on-cmk-group-delivers-plaintext-to-kinesis."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-logs-2-subscription-filter-on-cmk-group-delivers-plaintext-to-kinesis"
GROUP = "kms-encrypted-subscription"
SERVICES = ["kms", "logs"]

_GZIP_MAGIC = b"\x1f\x8b"


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A subscription filter on a CMK-encrypted log group delivers events to an unencrypted
    Kinesis stream as plain GZIP JSON naming the group, with messages exactly as written, because
    the key protects data at rest inside CloudWatch Logs only.
    """
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    kinesis = ctx.client("kinesis")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-xsvc-lg-cmksub-")
    group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{group}"
    key_arn = _create_logs_key(ctx, kms, account_id, group_arn)

    stream_name, stream_arn = _create_active_stream(ctx)
    enc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"].get(
        "EncryptionType", "NONE")
    # An unencrypted stream rules out the stream itself being why the payload is readable.
    assert enc == "NONE", f"destination stream must be unencrypted for this check; EncryptionType={enc!r}"
    # ListShards can still see CREATING just after DescribeStreamSummary reports ACTIVE.
    shards = _retry_code(lambda: kinesis.list_shards(StreamName=stream_name)["Shards"],
                         "ResourceInUseException", timeout_s=_budget_s(ctx, 60.0), ctx=ctx,
                         description=f"ListShards on {stream_name!r} once it is ACTIVE")
    shard_ids = [s["ShardId"] for s in shards]
    role_arn = _create_logs_delivery_role(ctx, stream_arn)

    _register_group_teardown(ctx, logs, group)
    _retry_code(
        lambda: logs.create_log_group(logGroupName=group, kmsKeyId=key_arn,
                                      tags={"sim2real-check": CHECK}),
        "InvalidParameterException", timeout_s=_budget_s(ctx, 120.0), ctx=ctx,
        description=f"CreateLogGroup {group!r} with its CMK",
    )
    assert _kms_key_of(logs, group) == key_arn, (
        f"group kmsKeyId is {_kms_key_of(logs, group)!r}, expected {key_arn!r}"
    )
    logs.create_log_stream(logGroupName=group, logStreamName="app")

    filter_name = ctx.unique_name("sim2real-xsvc-sf-")
    _retry_code(
        lambda: logs.put_subscription_filter(
            logGroupName=group, filterName=filter_name, filterPattern="",
            destinationArn=stream_arn, roleArn=role_arn),
        "InvalidParameterException", timeout_s=_budget_s(ctx, 120.0), ctx=ctx,
        description="PutSubscriptionFilter once the delivery role has propagated",
    )
    ctx.on_cleanup(lambda: _quiet(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName=filter_name),
        "ResourceNotFoundException"))

    marker = ctx.unique_name("evt-")
    written = [f"{marker} {i} payload={'p' * (i + 1)} é" for i in range(3)]

    def _delivered():
        msgs = []
        for raw, env in _read_envelopes(kinesis, stream_name, shard_ids):
            if env.get("messageType") != "DATA_MESSAGE":
                continue
            assert env.get("logGroup") == group, f"envelope names group {env.get('logGroup')!r}, expected {group!r}"
            assert env.get("logStream") == "app", f"envelope names stream {env.get('logStream')!r}"
            assert env.get("subscriptionFilters") == [filter_name], (
                f"envelope subscriptionFilters={env.get('subscriptionFilters')!r}, expected [{filter_name!r}]")
            for ev in env["logEvents"]:
                if ev["message"].startswith(marker):
                    assert marker.encode("ascii") in raw, (
                        "the decompressed record must carry the event marker in plaintext")
                msgs.append(ev["message"])
        return msgs

    # Subscription filters take effect after a lag, so write rounds until our marker arrives;
    # every round's events must arrive exactly as written.
    got = []
    arrived = False
    deadline = time.monotonic() + _budget_s(ctx, 8 * 45.0)
    rnd = 0
    while not arrived and time.monotonic() < deadline:
        batch = [f"{m} r{rnd}" for m in written]
        base = int(time.time() * 1000)
        resp = logs.put_log_events(
            logGroupName=group, logStreamName="app",
            logEvents=[{"timestamp": base + i, "message": m} for i, m in enumerate(batch)])
        assert "rejectedLogEventsInfo" not in resp, f"PutLogEvents partially rejected: {resp!r}"
        round_s = min(15.0, max(deadline - time.monotonic(), 0.0))
        arrived, got = _poll_for(_delivered, lambda ms, b=batch: all(x in ms for x in b),
                                 timeout_s=round_s, interval_s=1.0)
        if arrived:
            delivered_batch = [m for m in got if m.endswith(f" r{rnd}")]
            assert delivered_batch == batch, (
                f"round {rnd} delivered {delivered_batch!r}, expected exactly {batch!r} in order")
        rnd += 1
    if not arrived and _budget_spent(ctx):
        raise TimeoutError("a round of events to reach Kinesis: the run budget ended first; not graded")
    assert arrived, f"no round of events reached Kinesis within {rnd} rounds; last read {got!r}"
    ours = [m for m in got if m.startswith(marker)]
    assert ours, f"no events from {marker!r} were ever delivered; got {got!r}"
    assert _kms_key_of(logs, group) == key_arn, "the group must still be CMK-encrypted after delivery"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _retry_code(fn, transient_code, *, timeout_s, description, ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != transient_code or time.monotonic() >= deadline:
                if exc.response["Error"]["Code"] == transient_code and ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"{description}: the run budget ended first; not graded") from exc
                raise AssertionError(f"{description} failed: {exc.response['Error']!r}") from exc
            time.sleep(2.0)


def _poll_for(probe, predicate, *, timeout_s, interval_s):
    """(met, last): poll probe() until predicate(last) holds or timeout_s elapses."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return False, last
        time.sleep(interval_s)
        last = probe()
    return True, last


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition", ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last: {last!r}")


def _kms_key_of(logs, group):
    found = [g for g in logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
             if g["logGroupName"] == group]
    assert len(found) == 1, f"expected exactly one log group named {group!r}, found {len(found)}"
    return found[0].get("kmsKeyId")


def _quiet(fn, *ok_codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ok_codes:
            raise


def _create_logs_key(ctx, kms, account_id, group_arn):
    """Create a CMK usable by CloudWatch Logs only for ``group_arn``.

    Its cleanup is registered first, so LIFO runs it after the filter and log group are gone.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AccountAdmin", "Effect": "Allow",
             "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "CloudWatchLogsForOneGroup", "Effect": "Allow",
             "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
             "Action": ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*",
                        "kms:GenerateDataKey*", "kms:Describe*"],
             "Resource": "*",
             "Condition": {"ArnEquals": {"kms:EncryptionContext:aws:logs:arn": group_arn}}},
        ],
    }
    key_arn = kms.create_key(
        Policy=json.dumps(policy),
        Description=ctx.unique_name("sim2real-xsvc-logs-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))
    return key_arn


def _register_group_teardown(ctx, logs, group):
    def _teardown():
        # DisassociateKmsKey BEFORE the group goes, and both before the key is scheduled.
        _quiet(lambda: logs.disassociate_kms_key(logGroupName=group), "ResourceNotFoundException")
        _quiet(lambda: logs.delete_log_group(logGroupName=group), "ResourceNotFoundException")

    ctx.on_cleanup(_teardown)


def _create_active_stream(ctx):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-xsvc-kds-")
    kinesis.create_stream(StreamName=name, ShardCount=1,
                          StreamModeDetails={"StreamMode": "PROVISIONED"},
                          Tags={"sim2real": "behavioral", "sim2real-check": CHECK})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE", timeout_s=_budget_s(ctx, 180.0),
        interval_s=1.0, ctx=ctx,
        description=f"stream {name} to reach ACTIVE")
    return name, summary["StreamARN"]


def _create_logs_delivery_role(ctx, stream_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-logs-role-")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
        "Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                               Tags=[{"Key": "sim2real-check", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="kinesis-write", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Action": ["kinesis:PutRecord", "kinesis:PutRecords"], "Resource": stream_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="kinesis-write"))
    return role_arn


def _read_envelopes(kinesis, stream_name, shard_ids):
    """Return (decompressed bytes, parsed envelope) for every record from TRIM_HORIZON.

    boto3 has already undone the base64 framing, so ``Data`` must start with the gzip magic.
    """
    out = []
    for shard_id in shard_ids:
        it = kinesis.get_shard_iterator(StreamName=stream_name, ShardId=shard_id,
                                        ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        for _ in range(20):
            resp = kinesis.get_records(ShardIterator=it, Limit=1000)
            for rec in resp["Records"]:
                blob = rec["Data"]
                assert blob[:2] == _GZIP_MAGIC, (
                    f"a subscription record must be plain GZIP; first bytes were {blob[:8]!r}")
                raw = gzip.decompress(blob)
                out.append((raw, json.loads(raw)))
            it = resp.get("NextShardIterator")
            if not it or resp.get("MillisBehindLatest", 0) == 0:
                break
            time.sleep(0.25)  # 5 reads/s/shard pacing, not a wait for an effect
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
