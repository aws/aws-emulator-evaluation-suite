"""enable-logging-bucket-policy-validation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-logging-bucket-policy-validation"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableLogging to a nonexistent bucket fails with BucketNotFoundFault and logging stays disabled; a
    real bucket with the documented log-delivery policy is accepted (positive control).
    """
    redshift = ctx.client("redshift")
    s3 = ctx.client("s3")

    cluster_id = ctx.unique_name("sim2real-enablelog-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        MasterUsername="sim2realadmin",
        MasterUserPassword="Sim2RealTest1234!",
        ClusterType="single-node",
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))
    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=900)

    nonexistent_bucket = ctx.unique_name("sim2real-enablelog-missing-")
    code, message = _error(
        lambda: redshift.enable_logging(
            ClusterIdentifier=cluster_id, BucketName=nonexistent_bucket
        )
    )
    assert code == "BucketNotFoundFault", f"expected BucketNotFoundFault, got {code!r}"
    expected = f"Could not find bucket with name {nonexistent_bucket}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: logging is still disabled after the rejected attempt.
    status = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
    assert status["LoggingEnabled"] is False, (
        f"expected LoggingEnabled=False after a rejected EnableLogging, got {status['LoggingEnabled']!r}"
    )

    # positive control: a real bucket with the documented log-delivery policy lets it succeed.
    bucket_name = ctx.unique_name("sim2real-enablelog-real-")
    _create_bucket(ctx, s3, bucket_name)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Put bucket policy needed for audit logging",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:GetBucketAcl"],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*",
                ],
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    redshift.enable_logging(ClusterIdentifier=cluster_id, BucketName=bucket_name)
    ctx.on_cleanup(lambda: _disable_logging(redshift, cluster_id))
    control_status = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
    assert control_status["LoggingEnabled"] is True, (
        f"expected LoggingEnabled=True against a bucket carrying the documented log-delivery "
        f"policy, got {control_status['LoggingEnabled']!r}"
    )
    assert control_status["BucketName"] == bucket_name, (
        f"expected BucketName={bucket_name!r}, got {control_status['BucketName']!r}"
    )


def _error(fn):
    """Call fn(); return (error code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_bucket(ctx, s3, bucket_name):
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-behavioral", "Value": "true"}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))


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


def _wait_for_status(ctx, redshift, cluster_id, target_status, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if last["ClusterStatus"] == target_status:
            return last
        time.sleep(2)
    raise AssertionError(f"cluster never reached {target_status!r} (last seen: {last})")


def _delete_cluster(redshift, cluster_id):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code == "InvalidClusterState":
                time.sleep(15)
                continue
            raise
    raise AssertionError(f"could not delete cluster {cluster_id} within retry budget")


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
