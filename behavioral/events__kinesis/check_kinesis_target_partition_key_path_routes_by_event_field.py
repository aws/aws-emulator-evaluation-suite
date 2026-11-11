"""kinesis-target-partition-key-path-routes-by-event-field."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "kinesis-target-partition-key-path-routes-by-event-field"
GROUP = 'eventing'
SERVICES = ['events', 'kinesis']

_STREAM_ACTIVE_TIMEOUT_S = 240.0
_DELIVERY_BUDGET_S = 180.0
_ROLE_PROPAGATION_TIMEOUT_S = 120.0

_SOURCE = "sim2real.events-kinesis-pkp"
_DETAIL_TYPE = "sim2real.partition-key-path"

#: The JSON path under test, and the two values it must select. Two DIFFERENT tenants so the path
#: is shown to be evaluated per event rather than resolved once to a constant.
_PARTITION_KEY_PATH = "$.detail.tenant"
_TENANTS = ("tenant-alpha", "tenant-omega")

_SELECTED_TARGET_ID = "sel"
_DEFAULT_TARGET_ID = "dflt"

#: The shape of the second half of a default target's compound partition key.
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _poll(probe, predicate, timeout_s, interval_s=3.0, what=""):
    """Bounded retry that RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _wait_stream_active(kinesis, name: str) -> None:
    _poll(
        lambda: kinesis.describe_stream_summary(
            StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=_STREAM_ACTIVE_TIMEOUT_S,
        interval_s=5.0,
        what=f"stream {name!r} reaching ACTIVE",
    )


def _read_records(kinesis, name: str, want: int, budget_s: float) -> list[dict]:
    """Every record on every shard of *name*, from TRIM_HORIZON, until *want* of them or timeout."""
    shards = [s["ShardId"] for s in kinesis.describe_stream(
        StreamName=name)["StreamDescription"]["Shards"]]
    iters = {
        sid: kinesis.get_shard_iterator(
            StreamName=name, ShardId=sid, ShardIteratorType="TRIM_HORIZON",
        )["ShardIterator"]
        for sid in shards
    }
    seen: list[dict] = []
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline and len(seen) < want:
        for sid, it in list(iters.items()):
            if it is None:
                continue
            resp = kinesis.get_records(ShardIterator=it, Limit=100)
            seen += resp.get("Records", [])
            iters[sid] = resp.get("NextShardIterator")
        if len(seen) < want:
            time.sleep(2.0)
    return seen


def _events_target_role(ctx, iam, stream_arn: str) -> str:
    """A role EventBridge can assume to put records on exactly this stream."""
    name = ctx.unique_name("sim2real-behav-pkp-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real-behav events->kinesis partition key path",
        Tags=[{"Key": "sim2real", "Value": "partition-key-path"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(iam, name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="put-record",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                "Resource": stream_arn,
            }],
        }),
    )
    return arn


def _drop_role(iam, name: str) -> None:
    from botocore.exceptions import ClientError
    try:
        iam.delete_role_policy(RoleName=name, PolicyName="put-record")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _drain_dlq(sqs, url: str, wait_s: int = 2) -> list[dict]:
    """Every message currently visible on *url*, deleted as it is read."""
    out: list[dict] = []
    while True:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s,
            MessageAttributeNames=["All"],
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            return out
        for m in msgs:
            out.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


@tags("axis:happy-path", "cap:c2", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A target with PartitionKeyPath puts each record under the JSON-encoded selected value
    (`"tenant-alpha"`, quoted), per event; a twin target without it uses the envelope `id`, bare
    or as `{id}_{uuid}`.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_KinesisParameters.html
    """
    ev = ctx.client("events")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")

    # --- the consumer stream, created first so no delivery can predate it -------------------
    stream = ctx.unique_name("sim2real-behav-pkp-")
    kinesis.create_stream(StreamName=stream, ShardCount=2)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream,
                                                 EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, stream)
    kinesis.add_tags_to_stream(StreamName=stream,
                               Tags={"sim2real": "partition-key-path"})
    stream_arn = kinesis.describe_stream_summary(
        StreamName=stream)["StreamDescriptionSummary"]["StreamARN"]

    role_arn = _events_target_role(ctx, iam, stream_arn)

    bus = ctx.unique_name("sim2real-behav-pkp-")
    ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": "partition-key-path"}])
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus))

    rule = f"{bus}-r"
    ev.put_rule(Name=rule, EventBusName=bus, State="ENABLED",
                EventPattern=json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}))
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule, EventBusName=bus))

    # EventBridge's first delivery can fail FAILED_TO_ASSUME_ROLE even after PutTargets accepted
    # the new role (IAM propagation); a DLQ makes that cause observable so only it is retried.
    sqs = ctx.client("sqs")
    dlq_name = ctx.unique_name("sim2real-behav-pkp-dlq-")
    dlq_url = sqs.create_queue(QueueName=dlq_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(
        QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": dlq_arn,
        }],
    })})

    targets = [
        {"Id": _SELECTED_TARGET_ID, "Arn": stream_arn, "RoleArn": role_arn,
         "KinesisParameters": {"PartitionKeyPath": _PARTITION_KEY_PATH},
         "DeadLetterConfig": {"Arn": dlq_arn}},
        {"Id": _DEFAULT_TARGET_ID, "Arn": stream_arn, "RoleArn": role_arn,
         "DeadLetterConfig": {"Arn": dlq_arn}},
    ]
    # A freshly minted role is not immediately assumable by EventBridge; PutTargets validates it.
    put = _poll(
        lambda: ev.put_targets(Rule=rule, EventBusName=bus, Targets=targets),
        lambda r: r["FailedEntryCount"] == 0,
        timeout_s=_ROLE_PROPAGATION_TIMEOUT_S,
        interval_s=5.0,
        what="put_targets accepting the freshly minted events role",
    )
    ctx.on_cleanup(lambda: ev.remove_targets(
        Rule=rule, EventBusName=bus, Ids=[_SELECTED_TARGET_ID, _DEFAULT_TARGET_ID]))
    assert put["FailedEntryCount"] == 0, (
        f"put_targets reported {put['FailedEntryCount']} failures: {put.get('FailedEntries')!r}"
    )

    # The configuration must really be what this check claims to be testing.
    configured = {t["Id"]: t for t in ev.list_targets_by_rule(
        Rule=rule, EventBusName=bus)["Targets"]}
    assert set(configured) == {_SELECTED_TARGET_ID, _DEFAULT_TARGET_ID}, (
        f"expected exactly the two targets {_SELECTED_TARGET_ID!r} and {_DEFAULT_TARGET_ID!r}, "
        f"got {sorted(configured)!r}"
    )
    assert configured[_SELECTED_TARGET_ID]["KinesisParameters"] == {
        "PartitionKeyPath": _PARTITION_KEY_PATH}, (
        f"the selected target must carry PartitionKeyPath {_PARTITION_KEY_PATH!r}, "
        f"ListTargetsByRule reports {configured[_SELECTED_TARGET_ID].get('KinesisParameters')!r}"
    )
    assert "KinesisParameters" not in configured[_DEFAULT_TARGET_ID], (
        f"the twin target must carry NO KinesisParameters, or it is not a control; got "
        f"{configured[_DEFAULT_TARGET_ID].get('KinesisParameters')!r}"
    )

    # --- one PutEvents, two events, two tenants, retried only for the one known IAM race -------
    # EventBridge does not retry an AccessDenied invocation, so each retry sends a fresh
    # PutEvents; any DLQ cause other than FAILED_TO_ASSUME_ROLE fails immediately.
    want = 2 * len(_TENANTS)
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    probes: dict[str, str] = {}
    mine: list[dict] = []
    while True:
        probes = {t: ctx.unique_name("p-") for t in _TENANTS}
        resp = ev.put_events(Entries=[
            {"EventBusName": bus, "Source": _SOURCE, "DetailType": _DETAIL_TYPE,
             "Detail": json.dumps({"tenant": tenant, "probe": probe})}
            for tenant, probe in probes.items()
        ])
        assert resp["FailedEntryCount"] == 0, (
            f"put_events reported {resp['FailedEntryCount']} failures: {resp['Entries']!r}"
        )

        # --- the terminal read, at the CONSUMER -------------------------------------------------
        records = _read_records(kinesis, stream, want, 20.0)
        mine = [r for r in records
                if json.loads(r["Data"]).get("detail", {}).get("probe") in set(probes.values())]
        if len(mine) == want:
            break

        causes = {
            m["MessageAttributes"]["ERROR_CODE"]["StringValue"]
            for m in _drain_dlq(sqs, dlq_url)
            if "ERROR_CODE" in m.get("MessageAttributes", {})
        }
        assert not (causes - {"FAILED_TO_ASSUME_ROLE"}), (
            f"delivery failed for a reason other than the measured role-assume propagation race: "
            f"{sorted(causes)!r}"
        )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected {want} records after retrying through {_DELIVERY_BUDGET_S}s of IAM "
                f"role-assume propagation, got {len(mine)} with keys "
                f"{sorted(r['PartitionKey'] for r in mine)!r}; last DLQ causes {sorted(causes)!r}"
            )

    for tenant, probe in probes.items():
        group = [r for r in mine
                 if json.loads(r["Data"])["detail"]["probe"] == probe]
        assert len(group) == 2, (
            f"event {probe!r} must reach the stream once per target; got {len(group)} records "
            f"with keys {sorted(r['PartitionKey'] for r in group)!r}"
        )
        envelope_ids = {json.loads(r["Data"])["id"] for r in group}
        assert len(envelope_ids) == 1, (
            f"the two targets must deliver the SAME envelope for event {probe!r}; got event ids "
            f"{sorted(envelope_ids)!r}"
        )
        envelope_id = envelope_ids.pop()
        keys = sorted(r["PartitionKey"] for r in group)

        # The selected key is the JSON-encoded value (with quotes). The default key is the event
        # id plus `_<uuid>` not found in the envelope, so only that shape is asserted.
        selected_key = json.dumps(tenant)
        assert selected_key in keys, (
            f"for event {probe!r} the target carrying PartitionKeyPath {_PARTITION_KEY_PATH!r} "
            f"must deliver the JSON-encoded tenant {selected_key!r}; got keys {keys!r}"
        )
        other_keys = [k for k in keys if k != selected_key]
        assert len(other_keys) == 1, (
            f"for event {probe!r} expected exactly one other key, from the default target; got "
            f"{keys!r}"
        )
        default_key = other_keys[0]
        # The docs name the bare eventId as the default; AWS appends `_<uuid>`.
        assert default_key.startswith(f"{envelope_id}_") or default_key == envelope_id, (
            f"for event {probe!r} the default target's key {default_key!r} must start with the "
            f"delivered envelope id {envelope_id!r} followed by '_', or be that id"
        )
        suffix = default_key[len(envelope_id) + 1:]
        assert _UUID_RE.fullmatch(suffix) or default_key == envelope_id, (
            f"for event {probe!r} the default target's key suffix {suffix!r} (full key "
            f"{default_key!r}) is not UUID-shaped"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
