"""s3-buffering-hint-controls-delivery-latency."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "s3-buffering-hint-controls-delivery-latency"
GROUP = "visibility-timeout-ttl"
SERVICES = ["firehose"]

_FAST_INTERVAL_S = 0
_SLOW_INTERVAL_S = 300
# Real delivery to S3 carries overhead well past the configured interval (measured up to
# ~85s for interval=0s; a sibling check measured up to 246s for interval=60s), so the gap
# between the two intervals -- not an absolute checkpoint near either one -- is what makes
# the slow stream's absence a structural guarantee rather than a timing coincidence.
_CHECKPOINT_S = 280


# timing:real-time — buffer: 300 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A short buffering interval delivers to S3 measurably sooner than a long one."""
    setup = _create_firehose_role_and_bucket(ctx)
    fh = ctx.client("firehose")

    fast_name = ctx.unique_name("sim2real-fh-fast-")
    slow_name = ctx.unique_name("sim2real-fh-slow-")
    fast_prefix = "fast/"
    slow_prefix = "slow/"

    fast_config = {
        "RoleARN": setup["role_arn"],
        "BucketARN": f"arn:aws:s3:::{setup['bucket']}",
        "Prefix": fast_prefix,
        # SizeInMBs kept high so the size threshold never fires first; only the
        # (minimum-allowed) time interval gates delivery of our single small record.
        "BufferingHints": {"IntervalInSeconds": _FAST_INTERVAL_S, "SizeInMBs": 64},
    }
    slow_config = {
        "RoleARN": setup["role_arn"],
        "BucketARN": f"arn:aws:s3:::{setup['bucket']}",
        "Prefix": slow_prefix,
        "BufferingHints": {"IntervalInSeconds": _SLOW_INTERVAL_S, "SizeInMBs": 64},
    }

    _create_delivery_stream_with_retry(ctx, fh, fast_name, fast_config)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=fast_name))
    _create_delivery_stream_with_retry(ctx, fh, slow_name, slow_config)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=slow_name))

    _wait_both_active(ctx, fh, fast_name, slow_name)

    t0 = time.monotonic()
    fh.put_record(DeliveryStreamName=fast_name, Record={"Data": b"fast-buffer-record\n"})
    fh.put_record(DeliveryStreamName=slow_name, Record={"Data": b"slow-buffer-record\n"})

    # Poll until the fast stream delivers, but never past the slow stream's own
    # trigger window -- so a positive result here proves the fast stream really
    # is faster, not just "eventually both arrive".
    fast_objects: list = []
    while time.monotonic() - t0 < _CHECKPOINT_S:
        fast_objects = _list_objects(ctx, setup["bucket"], prefix=fast_prefix)
        if fast_objects:
            break
        time.sleep(2)
    elapsed_fast = time.monotonic() - t0
    assert fast_objects, (
        f"fast stream (interval={_FAST_INTERVAL_S}s) had not delivered to S3 after "
        f"{elapsed_fast:.0f}s"
    )

    # At this same checkpoint -- strictly before the slow stream's own interval could have
    # elapsed -- the slow stream must NOT have delivered: this is a structural guarantee
    # (the interval trigger cannot fire before its own duration passes), not a race against
    # measured latency, so it holds regardless of delivery-pipeline overhead.
    slow_objects_at_checkpoint = _list_objects(ctx, setup["bucket"], prefix=slow_prefix)
    assert not slow_objects_at_checkpoint, (
        f"slow stream (interval={_SLOW_INTERVAL_S}s) delivered to S3 within "
        f"{elapsed_fast:.0f}s, before its own interval could have elapsed -- "
        "buffering interval had no effect"
    )

    # Confirm the slow stream isn't simply broken: it does eventually deliver.
    slow_objects = _poll_for_objects(
        ctx, setup["bucket"], prefix=slow_prefix, min_count=1, timeout_s=320
    )
    assert slow_objects, (
        f"slow stream (interval={_SLOW_INTERVAL_S}s) never delivered to S3 -- "
        "it isn't merely slower, it's broken"
    )


def _capped(ctx, budget_s: float) -> float:
    """The wait bound, capped by the run's remaining time so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, left)


def _role_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "firehose.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_firehose_role_and_bucket(ctx) -> dict:
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-").lower().replace("_", "-")
    region = ctx.region
    # us-east-1 is not a resource pin: S3's CreateBucket rejects an explicit
    # LocationConstraint of "us-east-1" and requires the parameter be omitted instead.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    role_name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_role_trust_policy(),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = json.dumps(
        {
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
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        }
    )
    policy_name = ctx.unique_name("sim2real-fh-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return {"bucket": bucket, "role_arn": role["Arn"]}


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_delivery_stream_with_retry(
    ctx, fh, name: str, s3_config: dict, delivery_stream_type: str = "DirectPut"
) -> None:
    from botocore.exceptions import ClientError

    kwargs = {
        "DeliveryStreamName": name,
        "DeliveryStreamType": delivery_stream_type,
        "ExtendedS3DestinationConfiguration": s3_config,
        "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
    }
    deadline = time.monotonic() + _capped(ctx, 90.0)
    last_err = None
    while time.monotonic() < deadline:
        try:
            fh.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                time.sleep(2)
                continue
            raise
    raise last_err


def _wait_active(ctx, fh, name: str, timeout_s: int = 180) -> dict:
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status.endswith("FAILED"):
            raise AssertionError(f"stream entered failed state: {status}")
        time.sleep(2)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s")


def _wait_both_active(ctx, fh, name1: str, name2: str, timeout_s: int = 120) -> None:
    """Poll both streams concurrently per-iteration so total wait is bounded by the
    slower of the two, not the sum of two sequential waits."""
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    pending = {name1, name2}
    while time.monotonic() < deadline and pending:
        for name in list(pending):
            desc = fh.describe_delivery_stream(DeliveryStreamName=name)[
                "DeliveryStreamDescription"
            ]
            status = desc["DeliveryStreamStatus"]
            if status == "ACTIVE":
                pending.discard(name)
            elif status.endswith("FAILED"):
                raise AssertionError(f"stream {name} entered failed state: {status}")
        if pending:
            time.sleep(2)
    if pending:
        raise AssertionError(
            f"stream(s) {pending} did not become ACTIVE within {timeout_s}s"
        )



def _list_objects(ctx, bucket: str, prefix: str = "") -> list:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return resp.get("Contents", [])


def _poll_for_objects(
    ctx,
    bucket: str,
    prefix: str = "",
    min_count: int = 1,
    timeout_s: int = 240,
    interval_s: int = 2,
) -> list:
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    objs: list = []
    while time.monotonic() < deadline:
        objs = _list_objects(ctx, bucket, prefix=prefix)
        if len(objs) >= min_count:
            return objs
        time.sleep(interval_s)
    raise AssertionError(
        f"expected >= {min_count} objects under {prefix!r} in {bucket} within "
        f"{timeout_s}s, got {len(objs)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
