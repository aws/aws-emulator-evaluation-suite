"""s3-notification-without-topic-policy-rejected."""

from __future__ import annotations

import time
import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-notification-without-topic-policy-rejected"

GROUP = "errors"

SERVICES = ["s3", "sns", "sqs"]


def _set_topic_policy(ctx, topic: dict[str, str], bucket_arn: str, *, s3_may_publish: bool) -> None:
    """Set the topic's policy to owner-only, optionally adding the statement that lets
    s3.amazonaws.com publish to it for this specific bucket."""
    account = topic["arn"].split(":")[4]
    statements = [
        {
            "Sid": "OwnerOnly",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "sns:Publish",
            "Resource": topic["arn"],
        }
    ]
    if s3_may_publish:
        statements.append(
            {
                "Sid": "AllowS3",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": topic["arn"],
                "Condition": {
                    "ArnLike": {"aws:SourceArn": bucket_arn},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }
        )
    policy = {"Version": "2012-10-17", "Statement": statements}
    ctx.client("sns").set_topic_attributes(
        TopicArn=topic["arn"], AttributeName="Policy", AttributeValue=json.dumps(policy)
    )


def _configured_topic_arns(ctx, bucket: str) -> list[str]:
    """Independent read of the bucket's live notification configuration (never the mutating
    call's own response)."""
    got = ctx.client("s3").get_bucket_notification_configuration(Bucket=bucket)
    return [c["TopicArn"] for c in got.get("TopicConfigurations", [])]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """S3 validates the destination at configuration time: a bucket notification to a topic whose
    policy denies s3.amazonaws.com publish is refused with InvalidArgument and not applied, while
    the identical call succeeds before revoking and after restoring the permission."""
    bucket = _create_bucket(ctx)
    topic = _create_topic(ctx)
    s3 = ctx.client("s3")
    notif_config = {
        "TopicConfigurations": [{"TopicArn": topic["arn"], "Events": ["s3:ObjectCreated:*"]}]
    }

    # Positive control: with a permitting policy, the identical call is accepted.
    _set_topic_policy(ctx, topic, bucket["arn"], s3_may_publish=True)
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"], NotificationConfiguration=notif_config
    )
    configured = _configured_topic_arns(ctx, bucket["name"])
    assert configured == [topic["arn"]], (
        f"positive control failed: expected [{topic['arn']}] configured, got {configured}"
    )

    # Break exactly one thing: revoke s3.amazonaws.com's publish permission on the topic, and
    # clear the bucket's config first so any later presence can only come from the broken call.
    s3.put_bucket_notification_configuration(Bucket=bucket["name"], NotificationConfiguration={})
    _set_topic_policy(ctx, topic, bucket["arn"], s3_may_publish=False)

    try:
        s3.put_bucket_notification_configuration(
            Bucket=bucket["name"], NotificationConfiguration=notif_config
        )
    except ClientError as e:
        err = e.response.get("Error", {})
        status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert err.get("Code") == "InvalidArgument" and status == 400, (
            f"expected InvalidArgument HTTP 400, got {err.get('Code')!r} HTTP {status!r}"
        )
        expected_message = "Unable to validate the following destination configurations"
        assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'
        # S3 names the refused destination in ArgumentName1, not in the message text.
        assert err.get("ArgumentName1") == topic["arn"], (
            f"the rejection names destination {err.get('ArgumentName1')!r}, expected {topic['arn']!r}"
        )
        assert (err.get("ArgumentValue1") or "").strip(), f"expected a non-empty per-destination reason: {err!r}"
    else:
        raise AssertionError(
            "S3 accepted a notification to a topic S3 cannot publish to (over-permissive)"
        )

    # Effect absent, via an independent read: the rejected call must not have taken effect.
    configured = _configured_topic_arns(ctx, bucket["name"])
    assert configured == [], (
        f"rejected notification config was applied anyway: topics={configured}"
    )

    # Restore: re-permit, and the identical call now succeeds.
    _set_topic_policy(ctx, topic, bucket["arn"], s3_may_publish=True)
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"], NotificationConfiguration=notif_config
    )
    configured = _configured_topic_arns(ctx, bucket["name"])
    assert configured == [topic["arn"]], (
        f"restore failed: expected [{topic['arn']}] configured after re-permitting, got {configured}"
    )
    # Tear down in reverse dependency order and prove each resource gone.
    _gone_bucket(ctx, bucket["name"])
    _gone_topic(ctx, topic["arn"])


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Purge all objects, versions and delete markers, then delete the bucket; a non-empty bucket
    fails with BucketNotEmpty."""
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        targets = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if targets:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": targets})
    s3.delete_bucket(Bucket=bucket)


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(_tolerant(lambda: sns.delete_topic(TopicArn=arn), "NotFound"))
    return {"name": name, "arn": arn}


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the one region that rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(_tolerant(lambda: _empty_and_delete_bucket(ctx, name), "NoSuchBucket"))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message is {msg[:200]!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_topic(ctx, arn: str) -> None:
    sns = ctx.client("sns")
    sns.delete_topic(TopicArn=arn)
    nf = ("NotFound",)
    _poll_refused(lambda: sns.get_topic_attributes(TopicArn=arn), nf, 404, "GetTopicAttributes", "Topic does not exist")
    listed = {t["TopicArn"] for t in _paged(sns, "list_topics", "Topics")}
    assert arn not in listed, "ListTopics still lists the deleted topic"
    _refused(lambda: sns.publish(TopicArn=arn, Message="gone"), nf, 404, "Publish to deleted topic", "Topic does not exist")


def _empty_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})


def _gone_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    _empty_bucket(s3, bucket)
    s3.delete_bucket(Bucket=bucket)
    # HeadBucket has no body: the code is the bare status.
    _poll_refused(lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket", "NotFound"), 404, f"HeadBucket {bucket}", "Not Found")
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    _refused(lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x"), ("NoSuchBucket",), 404, f"PutObject {bucket}",
             "The specified bucket does not exist")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
