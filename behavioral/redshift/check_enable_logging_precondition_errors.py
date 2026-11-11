"""enable-logging-precondition-errors."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-logging-precondition-errors"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableLogging fails with BucketNotFoundFault for a missing bucket and
    InsufficientS3BucketPolicyFault for one without a log-delivery policy, leaving logging off;
    after attaching that policy the same call succeeds.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    redshift = ctx.client("redshift")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    cluster_id = ctx.unique_name("sim2real-logcfg-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_orderable_node_type(redshift),
        MasterUsername="sim2readmin",
        MasterUserPassword=_cluster_password(),
        ClusterType="single-node",
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))
    _wait_for_cluster_status(ctx, cluster_id, "available", timeout_s=900.0)

    bogus_bucket = ctx.unique_name("sim2real-nolog-bucket-")
    not_found_code, not_found_message = _error(
        lambda: redshift.enable_logging(ClusterIdentifier=cluster_id, BucketName=bogus_bucket)
    )
    assert not_found_code == "BucketNotFoundFault", f"expected BucketNotFoundFault, got {not_found_code}"
    expected = f"Could not find bucket with name {bogus_bucket}"
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"
    status = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
    assert status["LoggingEnabled"] is False, "logging must remain disabled after a nonexistent-bucket rejection"

    # A fresh bucket has no policy, so it lacks Redshift log-delivery permissions.
    real_bucket = ctx.unique_name("sim2real-log-bucket-")
    _create_bucket(ctx, s3, real_bucket)
    policy_code, policy_message = _error(
        lambda: redshift.enable_logging(ClusterIdentifier=cluster_id, BucketName=real_bucket)
    )
    assert policy_code == "InsufficientS3BucketPolicyFault", (
        f"expected InsufficientS3BucketPolicyFault, got {policy_code}"
    )
    expected = (
        f"Cannot read ACLs of bucket {real_bucket}. "
        "Please ensure that your IAM permissions are set up correctly."
    )
    assert policy_message == expected, f"expected message {expected!r}, got {policy_message!r}"
    status = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
    assert status["LoggingEnabled"] is False, "logging must remain disabled after an insufficient-policy rejection"

    # Positive control: the documented log-delivery policy on the same bucket makes it succeed.
    cluster_arn = f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRedshiftAuditLogging",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:GetBucketAcl"],
                "Resource": [f"arn:aws:s3:::{real_bucket}", f"arn:aws:s3:::{real_bucket}/*"],
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": cluster_arn},
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=real_bucket, Policy=json.dumps(policy))
    resp = _wait_enable_logging_succeeds(redshift, cluster_id, real_bucket)
    ctx.on_cleanup(
        lambda: _best_effort(ctx, lambda: redshift.disable_logging(ClusterIdentifier=cluster_id), teardown_deadline)
    )
    assert resp["LoggingEnabled"] is True, f"expected EnableLogging to report enabled, got {resp!r}"
    assert resp["BucketName"] == real_bucket, f"expected bucket {real_bucket}, got {resp.get('BucketName')!r}"
    status = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
    assert status["LoggingEnabled"] is True, "logging must be enabled after the policy fix"
    assert status["BucketName"] == real_bucket, f"expected bucket {real_bucket}, got {status.get('BucketName')!r}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected EnableLogging to be rejected, but it succeeded")


# budget.cleanup_timeout for behavioral/redshift, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 1800.0


def _teardown_deadline(teardown_deadline) -> float:
    """The one deadline this run's teardowns share, started by the first to ask, with a margin
    inside the budget so a teardown raises its own error before the runner gives up."""
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)


def _best_effort(ctx, fn, teardown_deadline) -> None:
    """Teardown: retry InvalidClusterState (an operation still running on the cluster) every 2 s
    to the shared cleanup deadline; ClusterNotFound means gone; raise everything else."""
    deadline = _teardown_deadline(teardown_deadline)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _cluster_password() -> str:
    return "Sim2Real" + uuid.uuid4().hex[:12] + "9!"


_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")


def _orderable_node_type(redshift, cluster_type: str = "single-node") -> str:
    """Pick an orderable node type: availability varies by account and region (dc2 vs ra3),
    so a hardcoded type can be rejected with InvalidParameterValue."""
    available: list[str] = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = redshift.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in _NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type!r} node types in this account/region")
        chosen = sorted(available)[0]
    return chosen


def _create_bucket(ctx, s3, name: str) -> None:
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region that rejects an explicit LocationConstraint.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behavioral", "Value": "true"}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    """Redshift writes a log-delivery object once logging is enabled, so empty the bucket first."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
        keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _delete_cluster(redshift, cluster_id: str, timeout_s: float = 600.0) -> None:
    """DisableLogging leaves an operation running on the cluster for a while; retry the delete
    on InvalidClusterState within a bounded window and treat ClusterNotFound as done."""
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
        time.sleep(15)


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


def _wait_for_cluster_status(ctx, cluster_id: str, target_status: str, timeout_s: float, interval_s: float = 15.0):
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = redshift.describe_clusters(ClusterIdentifier=cluster_id)
        cluster = resp["Clusters"][0]
        last = cluster.get("ClusterStatus")
        if last == target_status:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not reach status {target_status!r} within {timeout_s}s (last={last!r})")


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
