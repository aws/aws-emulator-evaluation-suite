"""lifecycle-expiration-ttl."""

from __future__ import annotations

import datetime
import email.utils

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "lifecycle-expiration-ttl"
GROUP = 'lifecycle_rules'
SERVICES = ['s3']


def _expiry_date(expiration_header: str) -> datetime.datetime:
    """Parse the expiry-date component out of an x-amz-expiration header value, e.g.
    'expiry-date="Fri, 21 Dec 2012 00:00:00 GMT", rule-id="sim2real-ttl-expire-rule"'."""
    marker = 'expiry-date="'
    start = expiration_header.index(marker) + len(marker)
    end = expiration_header.index('"', start)
    return email.utils.parsedate_to_datetime(expiration_header[start:end])


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An object matched by an Expiration lifecycle rule carries an x-amz-expiration header naming the
    rule with an expiry date in the expected window on HeadObject and GetObject, while an object outside
    the rule's filter carries none."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "sim2real-ttl-expire-rule",
                    "Filter": {"Prefix": "ttl-"},
                    "Status": "Enabled",
                    "Expiration": {"Days": 5},
                }
            ]
        },
    )

    cfg = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    rule_ids = {r["ID"] for r in cfg.get("Rules", [])}
    assert "sim2real-ttl-expire-rule" in rule_ids, f"expected the rule reflected in GetBucketLifecycleConfiguration, got {rule_ids}"

    key = "ttl-expiring-object.txt"
    before_put = datetime.datetime.now(datetime.timezone.utc)
    s3.put_object(Bucket=bucket, Key=key, Body=b"lifecycle-ttl-payload")

    head = s3.head_object(Bucket=bucket, Key=key)
    expiration = head.get("Expiration")
    assert expiration is not None, "expected an x-amz-expiration header on an object matched by an Expiration rule"
    assert "sim2real-ttl-expire-rule" in expiration, f"expected the matching rule-id in the Expiration header, got {expiration!r}"

    # S3 rounds the expiration to midnight UTC on the day the Days period elapses, so the
    # earliest it can land is Days after creation and the latest is Days+1 (the rounding-up slop).
    expiry = _expiry_date(expiration)
    earliest = before_put + datetime.timedelta(days=5)
    latest = before_put + datetime.timedelta(days=6)
    assert earliest <= expiry <= latest, (
        f"expected the expiry-date to fall {5}-6 days after object creation ({before_put!r}), got {expiry!r}"
    )

    got = s3.get_object(Bucket=bucket, Key=key)
    assert got.get("Expiration") is not None, "expected the Expiration header on GetObject too"
    assert got["Body"].read() == b"lifecycle-ttl-payload"

    # An object that does NOT match the rule's prefix filter is the control: it must carry no
    # Expiration header at all, proving the target applies the filter rather than stamping every
    # object in a bucket that merely has a lifecycle rule enabled.
    other_key = "no-match-object.txt"
    s3.put_object(Bucket=bucket, Key=other_key, Body=b"unrelated-payload")
    other_head = s3.head_object(Bucket=bucket, Key=other_key)
    assert other_head.get("Expiration") is None, (
        f"expected no Expiration header on an object outside the rule's prefix filter, got {other_head.get('Expiration')!r}"
    )
    other_got = s3.get_object(Bucket=bucket, Key=other_key)
    assert other_got.get("Expiration") is None, (
        f"expected no Expiration header on GetObject for an object outside the rule's prefix filter, got {other_got.get('Expiration')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
