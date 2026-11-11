"""xsvc-s3-2-notification-config-to-a-kms-encrypted-queue-is-rejected-until-the-key-policy-grants-this-bucket."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-s3-2-notification-config-to-a-kms-encrypted-queue-is-rejected-until-the-key-policy-grants-this-bucket"
GROUP = "event-propagation"
SERVICES = ["kms", "s3", "sqs"]

_SUBJECT_KEY = "kms/subject.txt"
_SUBJECT_BODY = b"sim2real kms-encrypted-queue notification subject\n"
_GRANT_SID = "AllowS3NotificationsFromOneBucket"
_KMS_REASON = "The message to the SSE queue could not be encrypted using KMS"
_VALIDATION_MESSAGE = "Unable to validate the following destination configurations"

_DELIVERY_TIMEOUT_S = 120
_ACCEPT_TIMEOUT_S = 120
_FIX_DELIVERY_TIMEOUT_S = 540

# Revoking the grant after acceptance is not asserted: SQS reuses a data key for
# KmsDataKeyReusePeriodSeconds, so delivery may continue for that period.


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c7",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """S3 rejects a notification to an SSE-KMS queue whose CMK does not grant this bucket (or grants
    another bucket's aws:SourceArn), atomically; once the key policy grants this bucket the identical
    configuration is accepted and the TestEvent and an ObjectCreated record reach the queue."""
    sts = ctx.client("sts")
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ident = sts.get_caller_identity()
    account = ident["Account"]
    partition = ident["Arn"].split(":")[1]

    # --- the CMK: this account administers it; S3 is granted NOTHING ---
    root_stmt = {
        "Sid": "AccountAdministersThisKey",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }
    key_name = _xname(ctx, "cmk")
    key = kms.create_key(
        Description=key_name,
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Policy=json.dumps({"Version": "2012-10-17", "Statement": [root_stmt]}),
        Tags=[{"TagKey": "sim2real", "TagValue": "xsvc-s3-2"}],
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # --- queues: subject is SSE-KMS under the CMK; the control is unencrypted ---
    kms_q = _create_queue(ctx, "kmsq", KmsMasterKeyId=key_arn)
    ctl_q = _create_queue(ctx, "ctlq", SqsManagedSseEnabled="false")
    stored_key = sqs.get_queue_attributes(
        QueueUrl=kms_q["url"], AttributeNames=["KmsMasterKeyId"]
    )["Attributes"].get("KmsMasterKeyId")
    assert stored_key == key_arn, (
        f"subject queue's KmsMasterKeyId is {stored_key!r}, expected the CMK {key_arn!r}"
    )

    bucket = _create_bucket(ctx, partition)
    # The SQS resource policy is correct for BOTH queues from the start: the KMS key policy is
    # the only variable under test.
    for q in (kms_q, ctl_q):
        _allow_s3_send(sqs, q, bucket["arn"], account)

    ctl_cfg = {
        "Id": "control",
        "QueueArn": ctl_q["arn"],
        "Events": ["s3:ObjectCreated:*"],
        "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "ctl/"}]}},
    }
    kms_cfg = {
        "Id": "kms-subject",
        "QueueArn": kms_q["arn"],
        "Events": ["s3:ObjectCreated:*"],
        "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "kms/"}]}},
    }

    # --- positive control: the unencrypted queue alone is accepted, so wiring/policy are sound ---
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"], NotificationConfiguration={"QueueConfigurations": [ctl_cfg]}
    )
    assert _config_ids(s3, bucket["name"]) == ["control"], (
        f"control-only configuration reads back {_config_ids(s3, bucket['name'])!r}"
    )

    full = {"QueueConfigurations": [ctl_cfg, kms_cfg]}

    # --- NEGATIVE 1: CMK grants S3 nothing -> the whole configuration call is rejected ---
    err = _config_error(s3, bucket["name"], full)
    assert err.get("Code") == "InvalidArgument", (
        f"configuring an SSE-KMS queue whose CMK grants S3 nothing returned {err!r}, expected "
        f"InvalidArgument"
    )
    assert err.get("Message") == _VALIDATION_MESSAGE, (
        f"rejection message is {err.get('Message')!r}, expected {_VALIDATION_MESSAGE!r}: {err!r}"
    )
    assert err.get("ArgumentName1") == kms_q["arn"], (
        f"rejection names destination {err.get('ArgumentName1')!r}, expected the KMS queue "
        f"{kms_q['arn']!r} (and not the control queue): {err!r}"
    )
    assert err.get("ArgumentValue1") == _KMS_REASON, (
        f"rejection reason is {err.get('ArgumentValue1')!r}, expected {_KMS_REASON!r} — a "
        f"queue-policy failure would read differently: {err!r}"
    )
    # Unchanged state: the failed call did not partially apply, nor drop the control config.
    after_reject = _config_ids(s3, bucket["name"])
    assert after_reject == ["control"], (
        f"after the rejected call the bucket configuration is {after_reject!r}, expected exactly "
        f"the prior ['control'] — the rejection must be atomic"
    )

    # Effect absent on the data plane, behind a differential barrier: subject and control are
    # written in the same instant; the control must deliver before the KMS queue is read.
    s3.put_object(Bucket=bucket["name"], Key=_SUBJECT_KEY, Body=_SUBJECT_BODY)
    s3.put_object(Bucket=bucket["name"], Key="ctl/barrier-1.txt", Body=b"1")
    t0 = time.monotonic()
    _wait_for_key(ctx, ctl_q["url"], "ctl/barrier-1.txt", timeout_s=_DELIVERY_TIMEOUT_S,
                  what="the control queue delivering the barrier written beside the subject")
    hold = max(2 * (time.monotonic() - t0), 15.0)
    leaked = _drain_records(ctx, kms_q["url"], seconds=hold)
    assert leaked == [], (
        f"the SSE-KMS queue received {len(leaked)} S3 record(s) although its configuration was "
        f"rejected: {leaked!r}"
    )

    # --- NEGATIVE 2: a grant scoped to a DIFFERENT bucket's ARN must not satisfy the condition ---
    other_bucket_arn = f"arn:{partition}:s3:::{_xname(ctx, 'other')}"
    _put_key_policy(kms, key_id, root_stmt, _grant(other_bucket_arn))
    # Asserted on every attempt for at least 10 s: one rejection could be key-policy propagation lag.
    hold_until = time.monotonic() + 10.0
    attempt = 0
    while True:
        attempt += 1
        err = _config_error(s3, bucket["name"], full)
        got = (err.get("Code"), err.get("Message"), err.get("ArgumentValue1"))
        assert got == ("InvalidArgument", _VALIDATION_MESSAGE, _KMS_REASON), (
            f"attempt {attempt}: with the S3 grant scoped to aws:SourceArn="
            f"{other_bucket_arn!r} (not this bucket), configuring the KMS queue returned {err!r}, "
            f"expected InvalidArgument / {_VALIDATION_MESSAGE!r} / {_KMS_REASON!r} — the "
            f"condition was not evaluated"
        )
        if time.monotonic() >= hold_until:
            break
        time.sleep(2)
    assert _config_ids(s3, bucket["name"]) == ["control"], (
        f"configuration changed under a wrongly-scoped grant: {_config_ids(s3, bucket['name'])!r}"
    )

    # --- FIX exactly one thing: the grant is re-scoped to THIS bucket's ARN ---
    _put_key_policy(kms, key_id, root_stmt, _grant(bucket["arn"]))
    deadline = time.monotonic() + _ACCEPT_TIMEOUT_S
    last: Any = None
    accepted = False
    while time.monotonic() < deadline and not accepted:
        try:
            s3.put_bucket_notification_configuration(
                Bucket=bucket["name"], NotificationConfiguration=full
            )
            accepted = True
        except ClientError as exc:
            last = exc.response.get("Error")
            time.sleep(2)
    assert accepted, (
        f"the identical configuration was still refused {_ACCEPT_TIMEOUT_S}s after granting "
        f"s3.amazonaws.com GenerateDataKey+Decrypt scoped to {bucket['arn']!r}: {last!r}"
    )
    assert _config_ids(s3, bucket["name"]) == ["control", "kms-subject"], (
        f"accepted configuration reads back {_config_ids(s3, bucket['name'])!r}"
    )

    # Data plane: S3's validation message was encrypted into the queue, then a real object event.
    test_events = _wait_for_test_event(ctx, kms_q["url"], bucket["name"],
                                       timeout_s=_DELIVERY_TIMEOUT_S)
    assert test_events >= 1, f"no s3:TestEvent reached the SSE-KMS queue ({test_events!r})"
    # The IDENTICAL PutObject, repeated until it is delivered: after the grant changes, S3 can drop
    # ObjectCreated events to the SSE-KMS queue for minutes, a window AWS does not bound, so only
    # eventual delivery is asserted.
    deadline = time.monotonic() + _FIX_DELIVERY_TIMEOUT_S
    rec: dict[str, Any] = {}
    writes = 0
    while time.monotonic() < deadline and not rec:
        s3.put_object(Bucket=bucket["name"], Key=_SUBJECT_KEY, Body=_SUBJECT_BODY)
        writes += 1
        rec = next((r for r in _drain_records(ctx, kms_q["url"], seconds=20)
                    if r.get("s3", {}).get("object", {}).get("key") == _SUBJECT_KEY), {})
    assert rec, (
        f"{writes} identical PutObject(s) of {_SUBJECT_KEY!r} over {_FIX_DELIVERY_TIMEOUT_S}s after "
        f"the key policy was fixed and the configuration accepted never reached the SSE-KMS queue"
    )
    assert rec.get("eventName") == "ObjectCreated:Put", (
        f"delivered record eventName {rec.get('eventName')!r}, expected 'ObjectCreated:Put'"
    )
    assert rec["s3"]["bucket"]["name"] == bucket["name"], (
        f"delivered record names bucket {rec['s3']['bucket']['name']!r}, expected {bucket['name']!r}"
    )
    assert rec["s3"]["configurationId"] == "kms-subject", (
        f"delivered via configuration {rec['s3']['configurationId']!r}, expected 'kms-subject'"
    )
    assert rec["s3"]["object"]["size"] == len(_SUBJECT_BODY), (
        f"delivered record object size {rec['s3']['object']['size']!r}, expected {len(_SUBJECT_BODY)}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _grant(source_arn: str) -> dict[str, Any]:
    return {
        "Sid": _GRANT_SID,
        "Effect": "Allow",
        "Principal": {"Service": "s3.amazonaws.com"},
        "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
        "Resource": "*",
        "Condition": {"ArnEquals": {"aws:SourceArn": source_arn}},
    }


def _put_key_policy(kms: Any, key_id: str, *stmts: dict[str, Any]) -> None:
    kms.put_key_policy(
        KeyId=key_id,
        PolicyName="default",
        Policy=json.dumps({"Version": "2012-10-17", "Statement": list(stmts)}),
    )
    stored = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    got = {s.get("Sid"): s.get("Condition") for s in stored["Statement"]}
    want = {s["Sid"]: s.get("Condition") for s in stmts}
    assert got == want, f"key policy reads back {got!r} (Sid -> Condition), expected {want!r}"


def _config_error(s3: Any, bucket: str, cfg: dict[str, Any]) -> dict[str, Any]:
    """The Error dict of a configuration call that MUST fail. Success raises: an accepted
    configuration is the strongest possible fidelity signal and must not read as a code mismatch."""
    try:
        s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration=cfg)
    except ClientError as exc:
        return dict(exc.response.get("Error", {}))
    raise AssertionError(
        f"PutBucketNotificationConfiguration ACCEPTED {[c['Id'] for c in cfg['QueueConfigurations']]!r} "
        f"although S3 cannot encrypt for the SSE-KMS queue under the current key policy"
    )


def _config_ids(s3: Any, bucket: str) -> list[str]:
    cfg = s3.get_bucket_notification_configuration(Bucket=bucket)
    return sorted(c.get("Id") for c in cfg.get("QueueConfigurations", []))


def _create_queue(ctx: Any, kind: str, **attrs: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, kind)
    url = sqs.create_queue(
        QueueName=name, Attributes=dict(attrs), tags={"sim2real": "xsvc-s3-2"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _allow_s3_send(sqs: Any, q: dict[str, str], bucket_arn: str, account: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3FromThisBucket",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": q["arn"],
                "Condition": {
                    "ArnEquals": {"aws:SourceArn": bucket_arn},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=q["url"], Attributes={"Policy": json.dumps(policy)})


def _create_bucket(ctx: Any, partition: str) -> dict[str, str]:
    s3 = ctx.client("s3")
    name = _xname(ctx, "b")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "xsvc-s3-2"}]}
    )
    return {"name": name, "arn": f"arn:{partition}:s3:::{name}"}


def _empty_and_delete_bucket(s3: Any, name: str) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchBucket",):
            raise RuntimeError(f"bucket {name}: {exc}") from exc


def _drain_bodies(ctx: Any, url: str, *, seconds: float) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        wait = max(1, min(5, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            out.append(json.loads(msg["Body"]))
    return out


def _drain_records(ctx: Any, url: str, *, seconds: float) -> list[dict[str, Any]]:
    """S3 event Records only; s3:TestEvent bodies carry none and drop out here."""
    out: list[dict[str, Any]] = []
    for body in _drain_bodies(ctx, url, seconds=seconds):
        out.extend(body.get("Records", []))
    return out


def _wait_for_key(ctx: Any, url: str, key: str, *, timeout_s: float, what: str) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    seen: list[Any] = []
    while time.monotonic() < deadline:
        for rec in _drain_records(ctx, url, seconds=5):
            k = rec.get("s3", {}).get("object", {}).get("key")
            seen.append(k)
            if k == key:
                return rec
    raise AssertionError(f"{what}: {key!r} not delivered within {timeout_s}s (saw keys {seen!r})")


def _wait_for_test_event(ctx: Any, url: str, bucket: str, *, timeout_s: float) -> int:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = [b for b in _drain_bodies(ctx, url, seconds=5)
                 if b.get("Event") == "s3:TestEvent" and b.get("Bucket") == bucket]
        if found:
            return len(found)
    raise AssertionError(
        f"no s3:TestEvent for bucket {bucket!r} reached the SSE-KMS queue within {timeout_s}s of "
        f"the configuration being accepted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
