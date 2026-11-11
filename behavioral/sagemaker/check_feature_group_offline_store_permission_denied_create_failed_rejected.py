"""feature-group-offline-store-permission-denied-create-failed-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feature-group-offline-store-permission-denied-create-failed-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFeatureGroup with an offline-store role lacking S3 access is rejected synchronously
    with ValidationException and creates nothing; granting that role S3 access lets the identical
    call reach Created, and an online-store-only group also creates."""
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-fg-offline-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))

    # An IAM role that SageMaker can assume but that carries zero permissions: it
    # cannot read/write the S3 bucket, so offline-store setup must fail.
    role_name = ctx.unique_name("sim2real-fg-no-perms-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)

    name = ctx.unique_name("sim2real-fg-noperm-")
    # IAM role creation is eventually consistent: SageMaker's own role-existence check can
    # still 404/ValidationException briefly after get_role already sees the role. Retry the
    # create call on that specific transient message, but the permission-denied rejection
    # (a *different* ValidationException, naming S3 AccessDenied) is the terminal, expected
    # outcome and must propagate immediately.
    create_deadline = time.monotonic() + 60
    code = None
    message = ""
    while True:
        try:
            sm.create_feature_group(
                FeatureGroupName=name,
                RecordIdentifierFeatureName="record_id",
                EventTimeFeatureName="event_time",
                FeatureDefinitions=[
                    {"FeatureName": "record_id", "FeatureType": "String"},
                    {"FeatureName": "event_time", "FeatureType": "String"},
                ],
                OfflineStoreConfig={"S3StorageConfig": {"S3Uri": f"s3://{bucket_name}/offline-store"}},
                RoleArn=role_arn,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            code = None
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            transient_role_propagation = (
                code == "ValidationException"
                and "role" in message.lower()
                and "AccessDenied" not in message
                and "not authorized" not in message.lower()
            )
            if transient_role_propagation and time.monotonic() < create_deadline:
                time.sleep(5)
                continue
            break

    # SageMaker probes the bucket with the role up front, so there is no CreateFailed to poll.
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message})"
    # message varies: it embeds the per-call assumed-role session name and the S3 request ids
    assert "AccessDenied" in message or "not authorized" in message, (
        f"expected an S3 access-denied cause in the message, got: {message}"
    )
    not_found_code, not_found_message = _error(lambda: sm.describe_feature_group(FeatureGroupName=name))
    assert not_found_code == "ResourceNotFound", (
        f"expected the rejected feature group to never exist, got {not_found_code}"
    )
    assert not_found_message == f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {name}", (
        f"unexpected DescribeFeatureGroup message for the rejected name: {not_found_message!r}"
    )

    # Grant the same role S3 access and retry the identical call; the rejected name was never
    # claimed.
    policy_name = ctx.unique_name("sim2real-fg-noperm-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:DeleteObject",
                            "s3:GetBucketAcl",
                            "s3:PutObjectAcl",
                            "s3:AbortMultipartUpload",
                        ],
                        "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_feature_group(FeatureGroupName=name)))

    # IAM policy attachment is itself eventually consistent, so SageMaker's own probe of
    # the role can keep seeing the pre-grant (denied) state for a while after put_role_policy
    # returns. Retry on that exact ValidationException/AccessDenied shape until it clears or
    # the deadline passes -- only THEN is it the terminal, asserted outcome.
    restore_deadline = time.monotonic() + 120
    restored_code = "pending"
    restored_message = ""
    while True:
        try:
            sm.create_feature_group(
                FeatureGroupName=name,
                RecordIdentifierFeatureName="record_id",
                EventTimeFeatureName="event_time",
                FeatureDefinitions=[
                    {"FeatureName": "record_id", "FeatureType": "String"},
                    {"FeatureName": "event_time", "FeatureType": "String"},
                ],
                OfflineStoreConfig={"S3StorageConfig": {"S3Uri": f"s3://{bucket_name}/offline-store"}},
                RoleArn=role_arn,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            restored_code = None
            break
        except ClientError as e:
            restored_code = e.response["Error"]["Code"]
            restored_message = e.response["Error"].get("Message", "")
            if restored_code == "ValidationException" and time.monotonic() < restore_deadline:
                time.sleep(2)
                continue
            break
    assert restored_code is None, (
        f"expected the identical create call to succeed once the role gained S3 access, "
        f"got {restored_code!r} ({restored_message})"
    )
    restored_status = _poll_until(
        lambda: sm.describe_feature_group(FeatureGroupName=name)["FeatureGroupStatus"],
        lambda s: s in ("Created", "CreateFailed"),
        timeout_s=180,
        interval_s=5,
    )
    assert restored_status == "Created", (
        f"expected the restored (now-permissioned) offline-store feature group to reach "
        f"Created, got {restored_status}"
    )

    control_name = ctx.unique_name("sim2real-fg-ctrl-")
    sm.create_feature_group(
        FeatureGroupName=control_name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=[
            {"FeatureName": "record_id", "FeatureType": "String"},
            {"FeatureName": "event_time", "FeatureType": "String"},
        ],
        OnlineStoreConfig={"EnableOnlineStore": True},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_feature_group(FeatureGroupName=control_name)))
    control_status = _poll_until(
        lambda: sm.describe_feature_group(FeatureGroupName=control_name)["FeatureGroupStatus"],
        lambda s: s in ("Created", "CreateFailed"),
        timeout_s=180,
        interval_s=5,
    )
    assert control_status == "Created", f"positive control feature group failed: {control_status}"


def _error(fn):
    """The AWS (code, message) raised by fn(); an unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket",
            "NoSuchEntity",
            "ResourceNotFound",
        ):
            raise


def _empty_and_delete_bucket(s3, bucket: str, timeout_s: float = 60.0) -> None:
    """The offline store writes objects under the prefix; empty the bucket, and re-empty on the
    BucketNotEmpty a late write causes every 2 s up to 60 s, before deleting it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
