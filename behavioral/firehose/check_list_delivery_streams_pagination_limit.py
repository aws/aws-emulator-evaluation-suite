"""list-delivery-streams-pagination-limit."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-delivery-streams-pagination-limit"
GROUP = "state-machine"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeliveryStreams paged by Limit from an ExclusiveStartDeliveryStreamName anchor returns
    the next N names in order; HasMoreDeliveryStreams is true while more remain, and once this
    run's names are exhausted it is false or the names that follow belong to other streams."""
    role_arn, bucket_arn = _setup_role_and_bucket(ctx)
    fh = ctx.client("firehose")

    prefix = ctx.unique_name("sim2real-fh-page-")
    names = [f"{prefix}-1", f"{prefix}-2", f"{prefix}-3"]
    anchor0 = f"{prefix}-0"  # lexicographically before names[0], never created

    for n in names:
        _create_stream_with_retry(ctx, n, role_arn, bucket_arn)
        ctx.on_cleanup(lambda n=n: _safe_delete_stream(ctx, n))

    page1 = fh.list_delivery_streams(Limit=1, ExclusiveStartDeliveryStreamName=anchor0)
    assert page1["DeliveryStreamNames"] == [names[0]], \
        f"expected [{names[0]!r}], got {page1['DeliveryStreamNames']!r}"
    assert page1["HasMoreDeliveryStreams"] is True, \
        f"expected HasMoreDeliveryStreams=True with 2 streams still past the page, got {page1['HasMoreDeliveryStreams']!r}"

    page2 = fh.list_delivery_streams(Limit=2, ExclusiveStartDeliveryStreamName=names[0])
    assert page2["DeliveryStreamNames"] == [names[1], names[2]], \
        f"expected [{names[1]!r}, {names[2]!r}], got {page2['DeliveryStreamNames']!r}"
    _assert_none_of_ours_follow(fh, page2, names[2], prefix)

    page3 = fh.list_delivery_streams(Limit=1, ExclusiveStartDeliveryStreamName=names[1])
    assert page3["DeliveryStreamNames"] == [names[2]], \
        f"expected [{names[2]!r}], got {page3['DeliveryStreamNames']!r}"
    _assert_none_of_ours_follow(fh, page3, names[2], prefix)


def _assert_none_of_ours_follow(fh, page, last, prefix):
    """A page ending at this run's last name reports no more streams, or more that are not ours:
    a read anchored one name earlier lists exactly ``last`` among this run's names.
    """
    if page["HasMoreDeliveryStreams"] is False:
        return
    assert page["HasMoreDeliveryStreams"] is True, page["HasMoreDeliveryStreams"]
    before_last = f"{prefix}-{int(last.rsplit('-', 1)[1]) - 1}"
    following = fh.list_delivery_streams(Limit=10, ExclusiveStartDeliveryStreamName=before_last)
    ours = [n for n in following["DeliveryStreamNames"] if n.startswith(f"{prefix}-")]
    assert ours == [last], f"expected only {last!r} of this run after {before_last!r}, got {ours!r}"


def _setup_role_and_bucket(ctx):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-fh-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3 rejects an explicit LocationConstraint of "us-east-1" on CreateBucket;
        # that region is the only one that must omit the field entirely.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_name = "sim2real-fh-s3-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                       "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"],
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup_role():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return role_arn, bucket_arn


def _s3_dest_config(role_arn, bucket_arn, extra=None):
    cfg = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 5},
    }
    if extra:
        cfg.update(extra)
    return cfg


def _create_stream_with_retry(ctx, name, role_arn, bucket_arn, extra=None, attempts=4, delay_s=15.0):
    fh = ctx.client("firehose")
    cfg = _s3_dest_config(role_arn, bucket_arn, extra)
    last_err = None
    for i in range(attempts):
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                ExtendedS3DestinationConfiguration=cfg,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            return
        except ClientError as e:
            # IAM propagation is eventually consistent; Firehose reports an unassumable role
            # as InvalidArgumentException until it propagates.
            if e.response["Error"]["Code"] == "InvalidArgumentException" and i < attempts - 1:
                last_err = e
                time.sleep(delay_s)
                continue
            raise
    raise last_err  # pragma: no cover


def _safe_delete_stream(ctx, name, timeout_s=300.0):
    """Teardown: delete a stream, retrying while it is still CREATING (ResourceInUseException);
    a stream already gone is fine."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fh.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
