"""enable-logging-insufficient-bucket-policy-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-logging-insufficient-bucket-policy-denied"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableLogging to a bucket without the Redshift log-delivery policy fails with
    InsufficientS3BucketPolicyFault; adding that policy to the same bucket lets the same call succeed.
    """
    redshift = ctx.client("redshift")
    s3 = ctx.client("s3")
    cluster_id = _create_available_cluster(ctx)

    bucket = ctx.unique_name("sim2real-logbucket-")
    _create_bucket(ctx, s3, bucket)
    # Deliberately no bucket policy granting Redshift log-delivery permissions.

    code, message = _error(
        lambda: redshift.enable_logging(ClusterIdentifier=cluster_id, BucketName=bucket)
    )
    assert code == "InsufficientS3BucketPolicyFault", code
    expected = (
        f"Cannot read ACLs of bucket {bucket}. "
        "Please ensure that your IAM permissions are set up correctly."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: logging must still be disabled on the cluster.
    status = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
    assert status["LoggingEnabled"] is False, status

    # Restore: attach the documented log-delivery policy to the SAME bucket and retry the
    # identical call, so the rejection is tied to the missing policy.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    cluster_arn = f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRedshiftAuditLogging",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:GetBucketAcl"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": cluster_arn},
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    enabled = _wait_enable_logging_succeeds(redshift, cluster_id, bucket)
    ctx.on_cleanup(lambda: _disable_logging(redshift, cluster_id))
    assert enabled["LoggingEnabled"] is True, enabled
    assert enabled["BucketName"] == bucket, enabled

    status_after = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
    assert status_after["LoggingEnabled"] is True, status_after
    assert status_after["BucketName"] == bucket, status_after


def _error(fn):
    """Call fn(); return (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_enable_logging_succeeds(redshift, cluster_id: str, bucket: str, timeout_s: float = 60.0, interval_s: float = 5.0):
    """S3 bucket policy propagation can lag briefly; poll EnableLogging until it
    accepts the now-correctly-policied bucket."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return redshift.enable_logging(ClusterIdentifier=cluster_id, BucketName=bucket)
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "InsufficientS3BucketPolicyFault":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"EnableLogging never succeeded after policy fix, last error: {last_code}")


def _create_bucket(ctx, s3, name: str) -> None:
    # us-east-1 is the one region where CreateBucketConfiguration must be omitted;
    # every other region requires an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behavioral", "Value": "true"}]}
    )


def _empty_and_delete_bucket(s3, name: str) -> None:
    """Delete the bucket after removing every object in it (Redshift writes a
    delivery-test object once logging is enabled); a bucket already gone is fine."""
    from botocore.exceptions import ClientError

    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            for obj in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=name, Key=obj["Key"], VersionId=obj["VersionId"])
        s3.delete_bucket(Bucket=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _disable_logging(redshift, cluster_id: str) -> None:
    """DisableLogging, waiting out the window in which the cluster is still applying
    the EnableLogging (it answers InvalidClusterState until then)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 600
    while True:
        try:
            redshift.disable_logging(ClusterIdentifier=cluster_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() > deadline:
                raise
            time.sleep(15)


def _create_available_cluster(ctx) -> str:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-enlog-cl-")
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        # dc2.large can be rejected with InvalidParameterValue; ra3.xlplus is orderable.
        NodeType="ra3.xlplus",
        MasterUsername="sim2realadmin",
        ManageMasterPassword=True,
        ClusterType="single-node",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id))
    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    return cluster_id


def _wait_for_cluster_status(ctx, cluster_id: str, targets: set, timeout_s: float) -> None:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if cluster["ClusterStatus"] in targets:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached {targets} within {timeout_s}s")


def _delete_cluster(ctx, cluster_id: str) -> None:
    redshift = ctx.client("redshift")
    try:
        _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFound":
            raise
    deadline = time.monotonic() + 600
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() > deadline:
                raise
            time.sleep(15)
    while time.monotonic() < deadline:
        try:
            redshift.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ClusterNotFound":
                return
            raise
        time.sleep(15)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
