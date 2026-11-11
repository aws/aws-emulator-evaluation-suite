"""firehose-s3-prefix-timestamp-namespace-and-buffering."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-s3-prefix-timestamp-namespace-and-buffering"

GROUP = "data-delivery"

SERVICES = ["firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Firehose buffers three PutRecord calls into ONE S3 object holding exactly those records,
    keyed <Prefix>YYYY/MM/DD/HH/<stream>-<UTC stamp>... in UTC.
    """
    s3 = ctx.client("s3")
    fh = ctx.client("firehose")
    bucket = _create_bucket(ctx)
    prefix = "ep-layout/"

    fh_role = _create_role(
        ctx,
        "firehose.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:AbortMultipartUpload",
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:PutObject",
                    ],
                    "Resource": [bucket["arn"], bucket["arn"] + "/*"],
                }
            ],
        },
    )

    # 60s / 1MiB are the documented minimums for an S3 destination; smaller is rejected. The
    # 60s interval is what makes the aggregation assertion meaningful AND bounded.
    buffering = {"SizeInMBs": 1, "IntervalInSeconds": 60}
    stream = _create_delivery_stream(
        ctx,
        bucket_arn=bucket["arn"],
        role_arn=fh_role["arn"],
        prefix=prefix,
        buffering=buffering,
    )
    described = fh.describe_delivery_stream(DeliveryStreamName=stream["name"])[
        "DeliveryStreamDescription"
    ]["Destinations"][0]["ExtendedS3DestinationDescription"]
    assert described["Prefix"] == prefix, (
        f"custom Prefix not stored: {described.get('Prefix')!r} != {prefix!r}"
    )
    assert described["BufferingHints"]["IntervalInSeconds"] == 60, (
        f"BufferingHints not stored: {described.get('BufferingHints')!r}"
    )

    markers = [_xname(ctx, f"rec{i}") for i in range(3)]
    put_at = datetime.now(timezone.utc)
    for marker in markers:
        # Firehose concatenates record bytes verbatim; the producer supplies the delimiter.
        fh.put_record(
            DeliveryStreamName=stream["name"],
            Record={"Data": (json.dumps({"marker": marker}) + "\n").encode()},
        )

    def _keys():
        resp = s3.list_objects_v2(Bucket=bucket["name"], Prefix=prefix)
        return [o["Key"] for o in resp.get("Contents", [])]

    # 420s: the 60s buffer window is a MINIMUM, and Firehose's first flush on a brand-new stream
    # routinely takes several minutes. Matches the deadline the existing firehose__s3 checks use.
    keys = _wait_for_effect(
        _keys,
        lambda ks: len(ks) >= 1,
        timeout_s=420,
        interval_s=15.0,
        description=f"Firehose object under {prefix}",
    )

    # Buffering, asserted as aggregation: three small records inside one 60s window are one
    # object, not three.
    assert len(keys) == 1, (
        f"BufferingHints(IntervalInSeconds=60, SizeInMBs=1) must aggregate 3 small records into "
        f"one S3 object; got {len(keys)}: {keys}"
    )
    key = keys[0]
    suffix = key[len(prefix) :]

    # Firehose appends the mandatory UTC time namespace AFTER a custom prefix that contains no
    # !{...} expressions.
    match = re.match(r"^(\d{4})/(\d{2})/(\d{2})/(\d{2})/(.+)$", suffix)
    assert match, (
        f"key must be <Prefix>YYYY/MM/DD/HH/<name>, got {key!r} (suffix {suffix!r})"
    )
    namespace = "/".join(match.groups()[:4])
    # UTC, not local time: allow the put hour and the next hour for a flush across the boundary.
    allowed = {
        (put_at + timedelta(hours=h)).strftime("%Y/%m/%d/%H") for h in (0, 1)
    }
    assert namespace in allowed, (
        f"timestamp namespace {namespace!r} is not a UTC hour of the write "
        f"(expected one of {sorted(allowed)}); key={key!r}"
    )
    filename = match.group(5)
    assert filename.startswith(stream["name"] + "-"), (
        f"object filename must start with the delivery stream name: {filename!r}"
    )
    assert re.search(r"-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-", filename), (
        f"object filename must embed the UTC yyyy-MM-dd-HH-mm-ss stamp: {filename!r}"
    )

    body = s3.get_object(Bucket=bucket["name"], Key=key)["Body"].read().decode("utf-8")
    lines = [json.loads(line) for line in body.splitlines() if line.strip()]
    # Firehose documents neither record order across PutRecord calls nor exactly-once delivery
    # (https://aws.amazon.com/firehose/faqs/), so markers compare as a set.
    assert {rec["marker"] for rec in lines} == set(markers), (
        f"the aggregated object must hold all 3 records as written; got {lines!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    # No blind sleep for IAM trust/permission propagation: _create_delivery_stream's own
    # create-time retry loop already bounds that race by catching "unable to assume role"
    # and retrying, so a second unconditional wait here would only hide the same race twice.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Delete every object under a bucket, then the bucket (S3 refuses a non-empty delete)."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is region-pinned here: S3 CreateBucket rejects an explicit
        # LocationConstraint for that region and requires omitting the field instead.
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _create_delivery_stream(ctx, *, bucket_arn, role_arn, prefix, buffering) -> dict[str, str]:
    """Create a DirectPut Firehose stream to S3 and wait for ACTIVE (registers delete).

    The create-time retry loop exists because
    Firehose validates the role by assuming it, so a freshly-created role loses the IAM
    propagation race with "unable to assume role".
    """
    fh = ctx.client("firehose")
    name = _xname(ctx, "fh")
    config: dict[str, Any] = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "Prefix": prefix,
        "ErrorOutputPrefix": prefix.rstrip("/") + "-errors/",
        "BufferingHints": buffering,
        "CompressionFormat": "UNCOMPRESSED",
    }
    last_err = None
    for _ in range(10):
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
                Tags=_xsvc_tags_kv(),
            )
            break
        except ClientError as exc:
            msg = str(exc)
            if "unable to assume role" in msg or "not authorized" in msg:
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create delivery stream {name}: {last_err}")
    ctx.on_cleanup(
        lambda: ctx.client("firehose").delete_delivery_stream(DeliveryStreamName=name)
    )
    _poll_until(
        lambda: fh.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=300,
        interval_s=10.0,
        description=f"delivery stream {name} ACTIVE",
    )
    return {"name": name}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
