"""enable-logging-bucket-and-policy-errors."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-logging-bucket-and-policy-errors"
GROUP = "error-semantics"
SERVICES = ["redshift"]

MSG_NO_BUCKET = "Could not find bucket with name {bucket}"
MSG_NO_POLICY = (
    "Cannot read ACLs of bucket {bucket}. Please ensure that your IAM permissions are set up correctly."
)

_CLUSTER_KWARGS = dict(
    NodeType="ra3.xlplus",
    ClusterType="single-node",
    MasterUsername="s2radmin",
    MasterUserPassword="Sim2Real-Passw0rd1",
    Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableLogging returns BucketNotFoundFault for a bucket that doesn't exist, and
    InsufficientS3BucketPolicyFault for a bucket that exists but lacks the required Redshift
    log-delivery permissions -- and succeeds once that policy is actually attached.
    """
    redshift = ctx.client("redshift")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    cluster_id = ctx.unique_name("sim2real-behav-logcl-")
    redshift.create_cluster(ClusterIdentifier=cluster_id, **_CLUSTER_KWARGS)

    def _cleanup_cluster() -> None:
        try:
            redshift.disable_logging(ClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFound":
                raise
        _delete_cluster_retrying(redshift, cluster_id)

    ctx.on_cleanup(_cleanup_cluster)
    _wait_cluster_available(redshift, cluster_id)

    # 1. Bucket doesn't exist -> BucketNotFoundFault.
    missing_bucket = ctx.unique_name("sim2real-behav-logbkt-missing-").lower()
    code, message = _refusal(
        lambda: redshift.enable_logging(ClusterIdentifier=cluster_id, BucketName=missing_bucket)
    )
    assert code == "BucketNotFoundFault", f"expected BucketNotFoundFault, got {code}"
    expected = MSG_NO_BUCKET.format(bucket=missing_bucket)
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # 2. Bucket exists but has no policy granting Redshift log-delivery permissions ->
    #    InsufficientS3BucketPolicyFault, and logging must remain disabled.
    bucket_name = ctx.unique_name("sim2real-behav-logbkt-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real-behavioral", "Value": CHECK}]},
    )

    code, message = _refusal(
        lambda: redshift.enable_logging(ClusterIdentifier=cluster_id, BucketName=bucket_name)
    )
    assert code == "InsufficientS3BucketPolicyFault", f"expected InsufficientS3BucketPolicyFault, got {code}"
    expected = MSG_NO_POLICY.format(bucket=bucket_name)
    assert message == expected, f"expected {expected!r}, got {message!r}"
    status = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
    assert status["LoggingEnabled"] is False, "logging must remain disabled after the rejected call"

    # Positive control: attach the required bucket policy and confirm EnableLogging now succeeds.
    cluster_arn = f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRedshiftAuditLogging",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:GetBucketAcl"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": cluster_arn},
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    resp = _wait_enable_logging_succeeds(redshift, cluster_id, bucket_name)
    assert resp["LoggingEnabled"] is True, f"expected LoggingEnabled=True after policy fix, got {resp!r}"
    assert resp["BucketName"] == bucket_name, f"expected BucketName={bucket_name!r}, got {resp.get('BucketName')!r}"


# ===== helpers =====
def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _delete_cluster_retrying(redshift, cluster_id: str, timeout_s: float = 780.0) -> None:
    """DeleteCluster, retried while the cluster is mid-modification (InvalidClusterState);
    any other refusal raises so a leak is reported, not swallowed."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _empty_and_delete_bucket(s3, bucket_name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait_cluster_available(redshift, cluster_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"]
        if status == "available":
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not become available within {timeout_s}s")


def _wait_enable_logging_succeeds(redshift, cluster_id: str, bucket_name: str, timeout_s: float = 60.0, interval_s: float = 5.0):
    """S3 bucket policy propagation can lag briefly; poll EnableLogging until it accepts
    the now-correctly-policied bucket."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return redshift.enable_logging(ClusterIdentifier=cluster_id, BucketName=bucket_name)
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "InsufficientS3BucketPolicyFault":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"EnableLogging never succeeded after policy fix, last error: {last_code}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
