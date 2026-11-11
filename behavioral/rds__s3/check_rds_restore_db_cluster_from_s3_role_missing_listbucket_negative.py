"""rds-restore-db-cluster-from-s3-role-missing-listbucket-negative."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-restore-db-cluster-from-s3-role-missing-listbucket-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreDBClusterFromS3 with an ingestion role lacking s3:ListBucket/s3:GetObject on the
    bucket fails synchronously with InvalidParameterValue (bucket files cannot be listed) and
    creates no cluster, while the same call with a role holding those permissions is accepted."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx, s3)
    s3.put_object(
        Bucket=bucket, Key="backup/placeholder.txt", Body=b"not-a-real-backup"
    )

    weak_role_arn = _create_ingestion_role(ctx, iam, bucket, grant_access=False)
    broken_cluster_id = ctx.unique_name("sim2real-rds-noperm-").lower()
    # If the target is over-permissive and actually creates the cluster despite the
    # missing permissions, it must still be torn down — register cleanup before the
    # attempt, not after the (expected) failure.
    ctx.on_cleanup(lambda: _cleanup_cluster(rds, broken_cluster_id))

    def _attempt():
        rds.restore_db_cluster_from_s3(
            DBClusterIdentifier=broken_cluster_id,
            Engine="aurora-mysql",
            MasterUsername="admin",
            MasterUserPassword="Sim2RealTest12345!",
            S3BucketName=bucket,
            S3IngestionRoleArn=weak_role_arn,
            SourceEngine="mysql",
            SourceEngineVersion="8.0.32",
            DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
        )

    error = _client_error_after_role_propagation(_attempt)
    assert error["Code"] == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {error['Code']}: {error.get('Message', '')}"
    )
    assert error.get("Message", "") == (
        "Files from the specified Amazon S3 bucket cannot be listed. Make sure that you have "
        "created an AWS Identity and Access Management (IAM) role that lets Amazon RDS access "
        "Amazon S3 for you."
    ), f"unexpected message: {error.get('Message', '')!r}"

    # effect absent: no cluster was created under that identifier
    not_found = _client_error(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=broken_cluster_id)
    )
    assert not_found["Code"] == "DBClusterNotFoundFault", (
        f"unexpected code: {not_found['Code']}: {not_found.get('Message', '')}"
    )
    assert not_found.get("Message", "") == f"DBCluster {broken_cluster_id} not found.", (
        f"unexpected message: {not_found.get('Message', '')!r}"
    )

    # positive control: same bucket, a role that IS permitted, call is accepted
    good_role_arn = _create_ingestion_role(ctx, iam, bucket, grant_access=True)
    control_cluster_id = ctx.unique_name("sim2real-rds-control-").lower()
    ctx.on_cleanup(lambda: _cleanup_cluster(rds, control_cluster_id))
    _restore_expect_success_eventually(
        rds,
        timeout_s=90.0,
        DBClusterIdentifier=control_cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword="Sim2RealTest12345!",
        S3BucketName=bucket,
        S3IngestionRoleArn=good_role_arn,
        SourceEngine="mysql",
        SourceEngineVersion="8.0.32",
    )
    resp = rds.describe_db_clusters(DBClusterIdentifier=control_cluster_id)
    status = resp["DBClusters"][0]["Status"]
    assert status in ("creating", "available"), (
        f"unexpected control cluster status: {status}"
    )


# ===== helpers =====


def _client_error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises, because
    accepting a call AWS refuses must be reported as such, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
    )


_ROLE_PROPAGATING_MESSAGE = (
    "IAM role ARN value is invalid or does not include the required permissions for: "
    "S3_SNAPSHOT_INGESTION"
)


def _client_error_after_role_propagation(fn, timeout_s: float = 90.0):
    """Like _client_error, but a role created moments ago is first reported with the
    S3_SNAPSHOT_INGESTION permissions message until IAM propagates it; retry only that
    message, bounded, and return the Error dict RDS settles on."""
    deadline = time.monotonic() + timeout_s
    while True:
        error = _client_error(fn)
        if error.get("Message", "") == _ROLE_PROPAGATING_MESSAGE and time.monotonic() < deadline:
            time.sleep(5.0)
            continue
        return error


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-rds-s3-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_ingestion_role(ctx, iam, bucket: str, grant_access: bool) -> str:
    role_name = ctx.unique_name("sim2real-rds-s3-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    # Both roles may locate the bucket; only the permitted one may list and read it.
    actions = ["s3:GetBucketLocation"]
    if grant_access:
        actions += ["s3:GetObject", "s3:ListBucket"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-ingestion", PolicyDocument=json.dumps(policy)
    )
    return role_arn


def _delete_role(iam, role_name: str) -> None:
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _restore_expect_success_eventually(rds, timeout_s: float = 90.0, **kwargs):
    # A freshly created IAM role/policy can take a while to become visible to RDS (documented
    # IAM eventual consistency for new principals/policies); during that window RDS reports
    # InvalidS3BucketFault, or InvalidParameterValue with a message naming the IAM role it
    # cannot yet validate. Retry on that family for a bounded window.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.restore_db_cluster_from_s3(**kwargs)
        except ClientError as err:
            error = err.response["Error"]
            transient = error["Code"] == "InvalidS3BucketFault" or (
                error["Code"] == "InvalidParameterValue" and "IAM" in error.get("Message", "")
            )
            if transient and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _cleanup_cluster(rds, cluster_id: str) -> None:
    # Issue the delete once the cluster is deletable: retry while it is creating or busy
    # (InvalidDBClusterStateFault), raise the rest.
    deadline = time.monotonic() + 900.0
    while True:
        try:
            status = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]["Status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        if status != "creating":
            try:
                rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
                return
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code == "DBClusterNotFoundFault":
                    return
                if code != "InvalidDBClusterStateFault":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {cluster_id} still {status!r}, not deletable after 900s")
        time.sleep(2.0)

def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
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
