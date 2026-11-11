"""s3-sequencer-is-the-only-total-order-over-one-key."""

from __future__ import annotations

import json
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "s3-sequencer-is-the-only-total-order-over-one-key"

GROUP = "ordering"

SERVICES = ["s3", "sqs"]

_PUTS = 16
_DELETES = 8
_OPS = _PUTS + _DELETES

# One key with both a space and a '+': in a notification body S3 URL-encodes a space as '+'
# and a literal '+' as '%2B'.
#
# Every destination in this check is prefix-scoped, and the prefixes are disjoint by construction.
# That is not cosmetic: S3 refuses two destinations that share an event type with overlapping
# prefixes, with the SAME error code (InvalidArgument) as it uses for an undeliverable destination.
# Overlapping prefixes would therefore have made the negative arm below pass for the wrong reason.
_ORD = "ord/"
_DENY = "deny/"
_CTL = "ctl/"
_KEY = _ORD + "seq test+key.txt"
_KEY_ENCODED = _ORD + "seq+test%2Bkey.txt"

# InvalidArgument also covers overlapping destinations, so the message is asserted:
#   destination not granted sqs:SendMessage -> "Unable to validate the following destination
#                                              configurations"
#   two destinations overlapping            -> "Configuration is ambiguously defined. Cannot have
#                                              overlapping suffixes ..."
_UNDELIVERABLE = "Unable to validate the following destination configurations"

_HEX = re.compile(r"^[0-9A-F]+$")

# Fixed seed: the interleaving of PUTs and DELETEs in the submitted plan is the same every run.
_PLAN_SEED = 20240917
# The silence window is a fixed length sampled by several short long-polls.
_SILENCE_WINDOW_S = 10.0
_SILENCE_POLL_S = 3


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error(fn) -> dict:
    """Return the AWS error (code, message) raised by fn(); raise if fn() succeeds.

    S3 answers InvalidArgument for both an undeliverable and an overlapping destination, so the
    message is what distinguishes them.
    """
    try:
        fn()
    except ClientError as exc:
        return {
            "code": exc.response["Error"]["Code"],
            "message": exc.response["Error"].get("Message", ""),
        }
    raise AssertionError(
        "the call was expected to be rejected by the service but it SUCCEEDED -- a target that "
        "accepts this input is more broken than one that returns the wrong error code"
    )


def _seq_key(sequencer: str, width: int) -> str:
    """The documented comparison rule: right-zero-pad to equal length, then compare as strings.

    Not `int(sequencer, 16)`: a shorter sequencer is a coarser position, not a smaller number.
    """
    return sequencer.ljust(width, "0")


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """For 24 concurrent operations on one key, the notification `sequencer` is a total order that
    matches ListObjectVersions and whose maximum is the key's final state; a destination S3 cannot
    deliver to is refused synchronously, with no partial effect.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-seq-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    bucket_arn = f"arn:aws:s3:::{bucket}"

    s3.put_bucket_versioning(
        Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
    )

    good = _create_queue(ctx, sqs)
    # The negative arm's destination: created now and left WITHOUT an S3-granting policy for the
    # whole run. It doubles as the effect-absent probe for the refused configuration.
    ungranted = _create_queue(ctx, sqs)
    # The control's destination: granted now, wired in only at the end, because an SQS policy
    # change can take over 90s to become visible to S3's destination validator.
    control = _create_queue(ctx, sqs)

    for q in (good, control):
        sqs.set_queue_attributes(
            QueueUrl=q["url"],
            Attributes={
                "Policy": json.dumps(_allow_s3_send(q["arn"], bucket_arn, account))
            },
        )

    def _dest(qid: str, arn: str, prefix: str, events: list[str]) -> dict:
        return {
            "Id": qid,
            "QueueArn": arn,
            "Events": events,
            "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": prefix}]}},
        }

    ord_dest = _dest(
        "ord", good["arn"], _ORD, ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
    )
    notify = {"QueueConfigurations": [ord_dest]}
    # The queue policy has to become effective before S3 will accept a destination that uses it,
    # and no API reports that it has. Retry THE OPERATION inside a bounded deadline -- never sleep
    # a guessed interval and hope.
    _retry_until_accepted(
        lambda: s3.put_bucket_notification_configuration(
            Bucket=bucket, NotificationConfiguration=notify
        ),
        timeout_s=_budget_s(ctx, 90.0),
        description="PutBucketNotificationConfiguration accepting the S3-granted queue",
        ctx=ctx,
    )

    # PutBucketNotificationConfiguration sends one s3:TestEvent to every new destination, so an
    # unfiltered drain would count it as data. Wait for it explicitly, then discard it.
    _drain_test_event(sqs, good["url"], timeout_s=_budget_s(ctx, 60.0), ctx=ctx)

    # ---- act: 24 concurrent operations on ONE key ------------------------------------------
    plan = [("PUT", i) for i in range(_PUTS)] + [("DEL", i) for i in range(_DELETES)]
    random.Random(_PLAN_SEED).shuffle(plan)

    def _op(spec):
        kind, i = spec
        if kind == "PUT":
            body = (b"p%03d" % i) * 10
            resp = s3.put_object(Bucket=bucket, Key=_KEY, Body=body)
            return {
                "kind": "PUT",
                "version": resp["VersionId"],
                "etag": resp["ETag"].strip('"'),
                "size": len(body),
            }
        resp = s3.delete_object(Bucket=bucket, Key=_KEY)
        return {"kind": "DEL", "version": resp["VersionId"], "etag": None, "size": None}

    with ThreadPoolExecutor(max_workers=_OPS) as pool:
        issued = [f.result() for f in [pool.submit(_op, p) for p in plan]]

    assert len(issued) == _OPS, f"only {len(issued)} of {_OPS} operations returned"
    by_version = {o["version"]: o for o in issued}
    assert len(by_version) == _OPS, (
        f"{_OPS} operations on a versioned key produced only {len(by_version)} distinct version "
        f"ids -- every PUT and every DELETE on a versioning-enabled bucket mints its own version"
    )

    # ---- the version history, as S3 reports it ---------------------------------------------
    versions: list[str] = []
    markers: list[str] = []
    listed: dict[str, dict] = {}
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        for v in page.get("Versions", []):
            versions.append(v["VersionId"])
            listed[v["VersionId"]] = v
        for v in page.get("DeleteMarkers", []):
            markers.append(v["VersionId"])
            listed[v["VersionId"]] = v

    # ---- drain the notifications, deduping -- delivery is AT-LEAST-ONCE --------------------
    events: dict[tuple[str, str, str], list[dict]] = {}
    drain_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + drain_s
    while time.monotonic() < deadline and len(events) < _OPS:
        wait = min(10, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=good["url"], MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            for rec in json.loads(msg["Body"]).get("Records", []):
                obj = rec["s3"]["object"]
                key = (rec["eventName"], obj.get("versionId"), obj["sequencer"])
                events.setdefault(key, []).append(rec)
            sqs.delete_message(
                QueueUrl=good["url"], ReceiptHandle=msg["ReceiptHandle"]
            )

    if len(events) < _OPS and _budget_spent(ctx):
        raise TimeoutError(f"{_OPS} distinct notifications: the run budget ended first; not graded")
    assert len(events) == _OPS, (
        f"only {len(events)} of {_OPS} distinct notifications arrived within {drain_s:.0f}s (S3 documents "
        f"event delivery as typically within seconds, so this window separates BROKEN from SLOW). The "
        f"version ids that produced no event were "
        f"{sorted(set(by_version) - {k[1] for k in events})!r}. This is not a coalescing "
        f"allowance: real AWS was measured to emit one event per operation for exactly this "
        f"workload."
    )

    # ---- assert: the sequencer is well-formed and a TOTAL order ----------------------------
    seqs = [k[2] for k in events]
    malformed = [s for s in seqs if not s or not _HEX.match(s)]
    assert not malformed, (
        f"{len(malformed)} notification(s) carried a sequencer that is not uppercase hexadecimal: "
        f"{malformed[:5]!r}. A timestamp, a UUID or a decimal counter is not a sequencer."
    )
    width = max(len(s) for s in seqs)
    padded = [_seq_key(s, width) for s in seqs]
    assert len(set(padded)) == _OPS, (
        f"the {_OPS} sequencers collapse to {len(set(padded))} distinct positions once "
        f"right-padded to width {width} -- a sequencer that collides across concurrent operations "
        f"on the same key is not a total order, and every consumer that uses it to reject stale "
        f"events will drop a live one. Sequencers: {sorted(seqs)!r}"
    )

    ordered = sorted(events, key=lambda k: _seq_key(k[2], width))

    # ---- assert: that order IS the version history, per family -----------------------------
    # ListObjectVersions returns each family newest-first, so oldest-first is the reversal.
    seq_puts = [k[1] for k in ordered if k[0].startswith("ObjectCreated")]
    seq_dels = [k[1] for k in ordered if k[0].startswith("ObjectRemoved")]
    assert seq_puts == list(reversed(versions)), (
        f"the sequencer order of the {len(seq_puts)} ObjectCreated events disagrees with the "
        f"object-version history. sequencer order (oldest first): {seq_puts!r}; "
        f"ListObjectVersions reversed: {list(reversed(versions))!r}. The sequencer must encode the "
        f"STORAGE commit order, so these are two witnesses of one fact."
    )
    assert seq_dels == list(reversed(markers)), (
        f"the sequencer order of the {len(seq_dels)} ObjectRemoved events disagrees with the "
        f"delete-marker history. sequencer order (oldest first): {seq_dels!r}; DeleteMarkers "
        f"reversed: {list(reversed(markers))!r}"
    )

    # ---- assert: the negative space -- no phantom event, no missing event -------------------
    assert {k[1] for k in events} == set(listed) == set(by_version), (
        f"the notification stream and the version history describe different sets of operations. "
        f"events-only: {sorted({k[1] for k in events} - set(listed))!r}; "
        f"history-only: {sorted(set(listed) - {k[1] for k in events})!r}; "
        f"never-issued: {sorted({k[1] for k in events} - set(by_version))!r}"
    )

    # ---- assert: the greatest sequencer is the operation the key actually ended at ----------
    # This is the only assertion that binds the two event families into ONE order, and it binds
    # that order to observable object state rather than to another list.
    last = ordered[-1]
    if last[0].startswith("ObjectRemoved"):
        head_err = _error(lambda: s3.head_object(Bucket=bucket, Key=_KEY))
        assert (head_err["code"], head_err["message"]) == ("404", "Not Found"), (
            f"the greatest sequencer belongs to {last[0]!r} (version {last[1]!r}), so the key's "
            f"current version must be a delete marker and HeadObject must be a 404 'Not Found'; "
            f"it raised {head_err!r}"
        )
        cur = s3.list_object_versions(Bucket=bucket, Prefix=_KEY)
        latest = [m for m in cur.get("DeleteMarkers", []) if m.get("IsLatest")]
        assert [m["VersionId"] for m in latest] == [last[1]], (
            f"the greatest sequencer is version {last[1]!r} but IsLatest points at "
            f"{[m['VersionId'] for m in latest]!r} -- the sequencer order and the current version "
            f"must be the same order"
        )
    else:
        head = s3.head_object(Bucket=bucket, Key=_KEY)
        assert head["VersionId"] == last[1], (
            f"the greatest sequencer belongs to PUT version {last[1]!r} but the key's current "
            f"version is {head['VersionId']!r} -- the sequencer total order must agree with which "
            f"write won"
        )

    # ---- assert: each event describes ITS OWN operation -------------------------------------
    for name, version, sequencer in ordered:
        rec = events[(name, version, sequencer)][0]
        obj = rec["s3"]["object"]
        origin = by_version[version]
        assert obj["key"] == _KEY_ENCODED, (
            f"event for {version!r} reported key {obj['key']!r}, expected the URL-encoded form "
            f"{_KEY_ENCODED!r} (a space encodes as '+' and a literal '+' as '%2B')"
        )
        assert rec["s3"]["bucket"]["arn"] == bucket_arn, (
            f"event for {version!r} reported bucket arn {rec['s3']['bucket']['arn']!r}, expected "
            f"{bucket_arn!r}"
        )
        if origin["kind"] == "PUT":
            assert obj.get("size") == origin["size"], (
                f"event for PUT {version!r} reported size {obj.get('size')!r}, but "
                f"{origin['size']!r} bytes were written"
            )
            assert obj.get("eTag") == origin["etag"], (
                f"event for PUT {version!r} reported eTag {obj.get('eTag')!r}, but the PutObject "
                f"response returned {origin['etag']!r} -- the event must describe THAT write"
            )
            assert name.startswith("ObjectCreated"), (
                f"version {version!r} was created by PutObject but its event is {name!r}"
            )
        else:
            assert name == "ObjectRemoved:DeleteMarkerCreated", (
                f"version {version!r} is a delete marker but its event is {name!r}"
            )

    # ---- assert: eventTime is an ISO-8601 UTC timestamp ---------------------------------------
    # S3 documents `sequencer` as the ordering key but guarantees nothing about eventTime skew,
    # so eventTimes that happen to be distinct and monotone are accepted when well-formed.
    times = [events[k][0]["eventTime"] for k in ordered]
    monotone_and_distinct = len(set(times)) == len(times) and times == sorted(times)
    assert not monotone_and_distinct or all(
        isinstance(t, str) and len(t) >= 20 and t[10] == "T" and t.endswith("Z") for t in times
    ), f"eventTime values are not ISO-8601 UTC timestamps: {times!r}"

    # ---- assert: duplicates are duplicates, not colliding distinct events -------------------
    by_seq: dict[str, set[tuple[str, str]]] = {}
    for name, version, sequencer in events:
        by_seq.setdefault(_seq_key(sequencer, width), set()).add((name, version))
    colliding = {s: v for s, v in by_seq.items() if len(v) > 1}
    assert not colliding, (
        f"sequencer(s) shared by DIFFERENT (eventName, versionId) pairs: {colliding!r}. A repeated "
        f"sequencer may only ever be an at-least-once redelivery of the SAME event."
    )

    # ---- negative: S3 refuses a destination it cannot deliver to, synchronously -------------
    # Chosen deliberately over "revoke the queue policy and assert silence": an SQS policy change
    # takes an unbounded time to become effective, so an assertion of NON-delivery after a revoke
    # is a race. Configuration-time validation is synchronous, so this arm is deterministic.
    bad_notify = {
        "QueueConfigurations": [
            ord_dest,
            _dest("deny", ungranted["arn"], _DENY, ["s3:ObjectCreated:*"]),
        ]
    }
    refusal = _error(
        lambda: s3.put_bucket_notification_configuration(
            Bucket=bucket, NotificationConfiguration=bad_notify
        )
    )
    assert refusal["code"] == "InvalidArgument", (
        f"configuring a queue destination whose resource policy does not grant "
        f"sqs:SendMessage to s3.amazonaws.com was rejected with {refusal['code']!r}, expected "
        f"'InvalidArgument'. S3 validates delivery permission when the configuration is written, "
        f"not when the first event fires."
    )
    assert refusal["message"] == _UNDELIVERABLE, (
        f"the refusal message was {refusal['message']!r}, which does not name the destination as "
        f"unvalidatable. S3 reuses InvalidArgument for an overlapping-prefix configuration too, so "
        f"the code alone does not establish WHY this was refused -- and a check that accepted any "
        f"InvalidArgument here would pass while proving something else entirely. Expected "
        f"{_UNDELIVERABLE!r}."
    )

    # effect-absent: the refused configuration did not partially apply
    live = s3.get_bucket_notification_configuration(Bucket=bucket)
    live_arns = [q["QueueArn"] for q in live.get("QueueConfigurations", [])]
    assert live_arns == [good["arn"]], (
        f"after the refused PutBucketNotificationConfiguration the live configuration lists "
        f"{live_arns!r}; a rejected configuration must leave the previous one exactly as it was, "
        f"and must never install the destination it just refused"
    )

    # effect-absent, observed at the destination: the ungranted queue received nothing at all.
    s3.put_object(Bucket=bucket, Key=_DENY + "probe.txt", Body=b"after-refusal")
    silent = _collect(sqs, ungranted["url"], window_s=_SILENCE_WINDOW_S)
    assert silent == [], (
        f"the queue whose configuration S3 REFUSED received {len(silent)} message(s): "
        f"{[m['Body'][:200] for m in silent]!r}. This is meaningful only because the granted queue "
        f"demonstrably received all {_OPS} events above, which proves the pipeline was live."
    )

    # control: the SAME two-destination shape is accepted when the second destination's policy does
    # grant S3 -- so the refusal above was about the missing permission, and not about the ARN, the
    # event list, or configuring a second destination at all.
    control_notify = {
        "QueueConfigurations": [
            ord_dest,
            _dest("ctl", control["arn"], _CTL, ["s3:ObjectCreated:*"]),
        ]
    }
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration=control_notify
    )
    accepted = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert sorted(q["QueueArn"] for q in accepted["QueueConfigurations"]) == sorted(
        [good["arn"], control["arn"]]
    ), (
        f"the control configuration reported "
        f"{[q['QueueArn'] for q in accepted['QueueConfigurations']]!r}, expected the granted queue "
        f"and the control queue"
    )


def _allow_s3_send(queue_arn: str, bucket_arn: str, account: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Send",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {
                    "ArnLike": {"aws:SourceArn": bucket_arn},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }
        ],
    }


def _create_queue(ctx, sqs) -> dict[str, str]:
    name = ctx.unique_name("sim2real-behav-seq-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _retry_until_accepted(fn, *, timeout_s: float, description: str, ctx=None) -> None:
    """Retry the operation until the service accepts it, within a bounded deadline.

    Used for a propagation window that exposes no condition to poll: the operation is its own probe.
    """
    deadline = time.monotonic() + timeout_s
    attempts: list[str] = []
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            attempts.append(exc.response["Error"]["Code"])
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"{description}: the run budget ended first; not graded") from exc
                raise AssertionError(
                    f"{description} never succeeded within {timeout_s}s over "
                    f"{len(attempts)} attempts; codes seen: {attempts!r}"
                ) from exc
            time.sleep(1.0)


def _drain_test_event(sqs, url: str, *, timeout_s: float, ctx=None) -> None:
    """Wait for the s3:TestEvent every new destination receives, then discard it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        seen_test = False
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except ValueError:
                body = {}
            if body.get("Event") == "s3:TestEvent":
                seen_test = True
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if seen_test:
            return
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the s3:TestEvent: the run budget ended first; not graded")
    raise AssertionError(
        "the s3:TestEvent that PutBucketNotificationConfiguration sends to every new destination "
        f"never arrived within {timeout_s:.0f}s -- the notification pipeline is not wired, so nothing measured "
        "afterwards would mean anything"
    )


def _collect(sqs, url: str, *, window_s: float) -> list[dict]:
    """Every message seen over a bounded window; emptiness counts only beside a positive control."""
    seen: list[dict] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait = min(_SILENCE_POLL_S, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_object_versions")
    targets = []
    for page in paginator.paginate(Bucket=bucket):
        targets += [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
    for i in range(0, len(targets), 1000):
        s3.delete_objects(Bucket=bucket, Delete={"Objects": targets[i : i + 1000]})
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
