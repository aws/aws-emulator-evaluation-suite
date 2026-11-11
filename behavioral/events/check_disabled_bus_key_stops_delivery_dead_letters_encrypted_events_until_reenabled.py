"""disabled-bus-key-stops-delivery-dead-letters-encrypted-events-until-reenabled."""
from __future__ import annotations

import json
import time


from behavioral_harness import tags

# After DisableKey on a CMK bus with a DeadLetterConfig,
# each PutEvents entry either fails with KMSEncryptionException "<key arn> is disabled." or is
# accepted and, instead of reaching the rule's target, lands in the bus dead-letter queue as an
# aws.events "Encrypted Events" envelope whose ERROR_CODE attribute says which decryption failed
# (the rule's or the event's). Either outcome can occur for a given entry. KMS key state
# propagates eventually, so the check first waits for the disable to take effect; after that no
# event reaches the target. After EnableKey, delivery resumes.

CHECK = "disabled-bus-key-stops-delivery-dead-letters-encrypted-events-until-reenabled"
GROUP = "event-bus"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 90.0
_SETTLE_TIMEOUT_S = 180.0
_DISABLED_PUTS = 4
_DRAIN_TIMEOUT_S = 90.0
_RECOVERY_TIMEOUT_S = 240.0
_PUT_INTERVAL_S = 2.0
# The two dead-letter reasons a disabled key produced, each with the message AWS pairs it with.
_DEAD_LETTER_REASONS = {
    "RULE_DECRYPTION_FAILURE": "Unable to decrypt rule using the Kms key.",
    "EVENT_DECRYPTION_FAILURE": "Unable to decrypt events using the Kms key.",
}


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With the bus's customer-managed key disabled, no event reaches the SQS target: each is refused with
    KMSEncryptionException "<key arn> is disabled." or dead-lettered as an aws.events "Encrypted Events"
    envelope naming the bus, the key and its event id; re-enabling the key restores delivery."""
    events = ctx.client("events")
    kms = ctx.client("kms")
    sqs = ctx.client("sqs")

    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = f"arn:aws:events:{ctx.region}:{ctx.account}:event-bus/{bus}"
    key_id, key_arn = _create_bus_key(ctx, kms)
    dlq_url, dlq_arn = _create_queue(ctx, sqs, "sim2real-behav-dlq-", source_arn=bus_arn)

    events.create_event_bus(Name=bus, KmsKeyIdentifier=key_arn, DeadLetterConfig={"Arn": dlq_arn},
                            Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    source = ctx.unique_name("sim2real.cmkoff.")
    rule = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(Name=rule, EventBusName=bus, EventPattern=json.dumps({"source": [source]}))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))
    target_url, target_arn = _create_queue(ctx, sqs, "sim2real-behav-q-", source_arn=rule_arn)
    events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "sim2real-q", "Arn": target_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["sim2real-q"]))

    def put(phase: str, n: int) -> dict:
        resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source, "DetailType": "sim2real-cmk",
                                           "Detail": json.dumps({"phase": phase, "n": n})}])
        return resp["Entries"][0]

    # --- positive control: the encrypted bus delivers while the key is enabled. ---
    control = put("enabled", 0)
    assert "EventId" in control, f"PutEvents with the key enabled must be accepted, got {control!r}"
    delivered = _wait_for_ids(sqs, target_url, {control["EventId"]}, _DELIVERY_TIMEOUT_S)
    assert control["EventId"] in delivered, "positive control: the event put with the key enabled was not delivered"

    # --- the one break: disable the key. KMS state propagates eventually, so first publish until
    # the disable is observable (a refused entry or a dead-lettered event), then measure. ---
    kms.disable_key(KeyId=key_id)
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key_id))
    accepted, refused, dead = set(), [], []

    def publish(phase: str, n: int) -> dict:
        entry = put(phase, n)
        if "EventId" in entry:
            accepted.add(entry["EventId"])
        else:
            refused.append((entry.get("ErrorCode"), entry.get("ErrorMessage")))
        return entry

    disabled_at = time.monotonic()
    deadline = disabled_at + _SETTLE_TIMEOUT_S
    n = 0
    while not (refused or dead):
        assert time.monotonic() < deadline, (
            f"none of the {n} events put in the {_SETTLE_TIMEOUT_S}s after DisableKey was refused or "
            f"dead-lettered — the disabled bus key had no observable effect"
        )
        n += 1
        publish("settling", n)
        time.sleep(_PUT_INTERVAL_S)
        dead += _drain(sqs, dlq_url)
    # The disable reaches EventBridge's hosts unevenly, so the first effect is not the last
    # delivery: keep settling as long again as the disable took to show.
    settle_until = time.monotonic() + (time.monotonic() - disabled_at)
    while time.monotonic() < settle_until:
        n += 1
        publish("settling", n)
        time.sleep(min(_PUT_INTERVAL_S, max(0.0, settle_until - time.monotonic())))
    dead += _drain(sqs, dlq_url)
    _drain(sqs, target_url)  # deliveries from before the disable took effect are not graded

    disabled_ids = set()
    for m in range(1, _DISABLED_PUTS + 1):
        entry = publish("disabled", m)
        if "EventId" in entry:
            disabled_ids.add(entry["EventId"])
        time.sleep(2.0)
    # Wait for every accepted event of the disabled phase to be dead-lettered, not a fixed time.
    deadline = time.monotonic() + _DRAIN_TIMEOUT_S
    while True:
        dead += _drain(sqs, dlq_url)
        if disabled_ids <= {msg["body"]["id"] for msg in dead} or time.monotonic() > deadline:
            break
        time.sleep(5.0)

    for code, message in refused:
        assert (code, message) == ("KMSEncryptionException", f"{key_arn} is disabled."), (
            f"a PutEvents entry refused for the disabled key must carry KMSEncryptionException "
            f"'<key arn> is disabled.', got {code!r} {message!r}"
        )

    leaked = [x for x in _drain(sqs, target_url) if x["body"].get("detail", {}).get("phase") == "disabled"]
    assert leaked == [], (
        f"{len(leaked)} of the {m} event(s) put after the disabled key took effect reached the rule's target"
    )

    for msg in dead:
        body, attrs = msg["body"], msg["attrs"]
        assert body["id"] in accepted, "the bus dead-letter queue received an event this run did not put"
        assert (body["source"], body["detail-type"]) == ("aws.events", "Encrypted Events"), (
            f"a dead-lettered event is wrapped as aws.events/Encrypted Events, got "
            f"{(body['source'], body['detail-type'])!r}"
        )
        assert body["detail"]["event-bus-arn"] == bus_arn, "the dead-letter envelope must name the bus"
        assert body["detail"]["kms-key-arn"] == key_arn, "the dead-letter envelope must name the bus key"
        assert isinstance(body["detail"].get("encrypted-payload"), str) and body["detail"]["encrypted-payload"], (
            "the dead-letter envelope must carry the still-encrypted payload"
        )
        reason = attrs.get("ERROR_CODE")
        assert reason in _DEAD_LETTER_REASONS, f"dead-letter ERROR_CODE {reason!r} is not a key-decryption failure"
        assert attrs.get("ERROR_MESSAGE") == _DEAD_LETTER_REASONS[reason], (
            f"ERROR_MESSAGE {attrs.get('ERROR_MESSAGE')!r} does not match ERROR_CODE {reason!r}"
        )

    # --- restore: re-enable and deliver again. ---
    kms.enable_key(KeyId=key_id)
    recovered = None
    deadline = time.monotonic() + _RECOVERY_TIMEOUT_S
    while time.monotonic() < deadline and recovered is None:
        entry = put("reenabled", 0)
        if "EventId" in entry and entry["EventId"] in _wait_for_ids(sqs, target_url, {entry["EventId"]}, 20.0):
            recovered = entry["EventId"]
    assert recovered is not None, f"delivery did not resume within {_RECOVERY_TIMEOUT_S}s of re-enabling the key"


def _create_bus_key(ctx, kms) -> tuple[str, str]:
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "AccountAdmin", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
         "Action": "kms:*", "Resource": "*"},
        {"Sid": "AllowEventBridge", "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
         "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"], "Resource": "*",
         "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}}},
    ]}
    meta = kms.create_key(Description=f"sim2real {CHECK}", Policy=json.dumps(policy),
                          Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta["KeyId"], meta["Arn"]


def _create_queue(ctx, sqs, prefix: str, *, source_arn: str) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage",
        "Resource": arn, "Condition": {"ArnEquals": {"aws:SourceArn": source_arn}},
    }]}
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _drain(sqs, url: str) -> list[dict]:
    out = []
    while True:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                   MessageAttributeNames=["All"]).get("Messages", [])
        if not msgs:
            return out
        for m in msgs:
            attrs = {k: v.get("StringValue") for k, v in (m.get("MessageAttributes") or {}).items()}
            out.append({"body": json.loads(m["Body"]), "attrs": attrs})
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


def _wait_for_ids(sqs, url: str, ids: set, timeout_s: float) -> set:
    seen: set = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not ids <= seen:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", []):
            seen.add(json.loads(m["Body"]).get("id"))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
