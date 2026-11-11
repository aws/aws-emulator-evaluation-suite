"""server-side-role-permission-removal-blocks-delivery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-role-permission-removal-blocks-delivery"
GROUP = "server-side"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Revoking the delivery role's S3 permissions blocks subsequent delivery; enforced at delivery time.
    The blocked record is kept and redelivered once the permissions are restored."""
    bucket = _create_bucket(ctx)
    role_arn, role_name, policy_name, policy_doc = _create_firehose_role(ctx, bucket)
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")
    stream_name = ctx.unique_name("sim2real-fh-perm-")
    _create_s3_delivery_stream(
        ctx, firehose, stream_name, role_arn, bucket,
        buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 60},
    )
    s3 = ctx.client("s3")

    def _lines():
        data = _download_all(s3, bucket)
        return {ln for ln in data.decode().splitlines() if ln.strip()}

    # Positive control: with the role's S3 permissions intact, a record is delivered.
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": b"before-revoke\n"})
    seen = _poll_until(_lines, lambda s: "before-revoke" in s, timeout_s=150, interval_s=5)
    assert "before-revoke" in seen, "baseline delivery with a valid role never happened"

    # Break exactly one thing: remove the role's only S3 permissions.
    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)

    # New records submitted after the permission removal must never reach S3: the delivery
    # role is enforced live at delivery time, not only when the stream/destination is created.
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": b"after-revoke\n"})
    seen = _poll_until(_lines, lambda s: "after-revoke" in s, timeout_s=120, interval_s=5)

    assert "after-revoke" not in seen, "record was delivered to S3 despite the role losing all S3 permissions"
    assert "before-revoke" in seen, "positive-control record disappeared after the permission was revoked"

    # Restore the identical permissions and demand the identical call now succeeds: enforcement
    # is live, not a one-way trip -- a role that regains its S3 permissions must resume delivery.
    # Firehose retries a failed S3 delivery, so the blocked record is redelivered, not dropped.
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": b"after-restore\n"})
    seen = _poll_until(
        _lines, lambda s: "after-restore" in s and "after-revoke" in s, timeout_s=150, interval_s=5
    )
    assert "after-restore" in seen, "record was not delivered to S3 after the role's S3 permissions were restored"
    assert "after-revoke" in seen, "the blocked record was dropped instead of being redelivered after the restore"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _safe_delete_role_policy(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_firehose_role(ctx, bucket_name):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "s3-delivery-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject",
            ],
            "Resource": [
                f"arn:aws:s3:::{bucket_name}",
                f"arn:aws:s3:::{bucket_name}/*",
            ],
        }],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: _safe_delete_role_policy(iam, role_name, policy_name))
    return role_arn, role_name, policy_name, policy_doc


def _wait_for_active(firehose, name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream {name} entered CREATING_FAILED")
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never became ACTIVE: {desc}")


def _create_s3_delivery_stream(ctx, firehose, name, role_arn, bucket_name, buffering_hints):
    dest_config = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket_name}",
        "BufferingHints": buffering_hints,
    }
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = exc
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    )
    _wait_for_active(firehose, name)
    return name


def _list_bucket_keys(s3, bucket):
    resp = s3.list_objects_v2(Bucket=bucket)
    return sorted(obj["Key"] for obj in resp.get("Contents", []))


def _download_all(s3, bucket):
    data = b""
    for key in _list_bucket_keys(s3, bucket):
        data += s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    return data


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
