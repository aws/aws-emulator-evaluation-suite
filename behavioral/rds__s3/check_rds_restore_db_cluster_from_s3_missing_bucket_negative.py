"""rds-restore-db-cluster-from-s3-missing-bucket-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
import secrets

CHECK = "rds-restore-db-cluster-from-s3-missing-bucket-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreDBClusterFromS3 pointed at an S3 bucket that does not exist fails synchronously
    with InvalidParameterValue ("the specified Amazon S3 bucket cannot be found"), not
    InvalidS3BucketFault, and never creates a DB cluster."""
    rds = ctx.client("rds")
    subnet_group = _network_db_subnet_group(ctx, rds)
    iam = ctx.client("iam")

    missing_bucket = ctx.unique_name("sim2real-rds-s3-missing-").lower()
    # Grant the role access to the bucket ARN it names, even though that bucket is never
    # created, so the negative attempt below breaks exactly one thing (the bucket not
    # existing) rather than confounding it with a role/permission mismatch: real AWS validates
    # S3IngestionRoleArn permissions against the named S3BucketName and returns
    # InvalidParameterValue -- not InvalidS3BucketFault -- when the role has no grant on that
    # exact bucket name, even before checking whether the bucket exists.
    role_arn = _create_ingestion_role(ctx, iam, missing_bucket)

    broken_cluster_id = ctx.unique_name("sim2real-rds-nobucket-").lower()

    def _attempt_missing_bucket():
        rds.restore_db_cluster_from_s3(
            DBClusterIdentifier=broken_cluster_id,
            Engine="aurora-mysql",
            MasterUsername="admin",
            MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
            S3BucketName=missing_bucket,
            S3IngestionRoleArn=role_arn,
            SourceEngine="mysql",
            SourceEngineVersion="8.0.32",
            DBSubnetGroupName=subnet_group,
        )

    code, message = _error_detail_after_iam_propagation(_attempt_missing_bucket)
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == (
        "The specified Amazon S3 bucket cannot be found. Make sure that you have created an "
        "AWS Identity and Access Management (IAM) role that lets Amazon RDS access Amazon S3 "
        "for you."
    ), f"expected the bucket-not-found message, got {message!r}"

    # effect absent: no cluster was created under that identifier
    not_found_code, not_found_message = _error_detail(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=broken_cluster_id)
    )
    assert not_found_code == "DBClusterNotFoundFault", f"unexpected code: {not_found_code}"
    assert not_found_message == f"DBCluster {broken_cluster_id} not found.", not_found_message

    # Positive control: a plain (non-S3) Aurora cluster creation, using the same account, region and
    # IAM setup, proves the wiring is otherwise healthy and that only the missing bucket caused the
    # rejection above. It is not "the identical call against a real bucket" because
    # RestoreDBClusterFromS3 succeeding requires a real XtraBackup-format backup in that bucket, and
    # AWS reports an empty-but-real bucket with the same "S3 bucket cannot be found" message used
    # above, so an empty bucket cannot serve as this check's positive control either.
    control_cluster_id = ctx.unique_name("sim2real-rds-control-").lower()
    ctx.on_cleanup(lambda: _cleanup_cluster(rds, control_cluster_id))
    rds.create_db_cluster(
        DBClusterIdentifier=control_cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    control_status = _poll_cluster_status(rds, control_cluster_id, timeout_s=1800.0)
    assert control_status == "available", (
        f"expected the control cluster to reach available, last saw {control_status!r}"
    )


# ===== helpers =====


def _error_detail(fn) -> tuple[str, str]:
    """Call fn() and return its botocore (code, message). An unexpected success raises, because
    accepting a call AWS refuses must be reported as such, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _error_detail_after_iam_propagation(fn, timeout_s: float = 90.0) -> tuple[str, str]:
    """RDS validates the ingestion role's S3 permissions before it validates bucket
    existence. A role/policy created moments ago can still be invisible to that validation
    path (documented IAM eventual consistency), in which case it reports the same
    InvalidParameterValue code but with a role/permission message rather than the terminal
    bucket-not-found one. Retry only that transient message shape, bounded, and return the
    (code, message) actually settled on."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if (
                code == "InvalidParameterValue"
                and "IAM role" in message
                and "S3 bucket cannot be found" not in message
                and time.monotonic() < deadline
            ):
                time.sleep(5.0)
                continue
            return code, message
        raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_ingestion_role(ctx, iam, bucket: str) -> str:
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
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


def _poll_cluster_status(rds, cluster_id: str, timeout_s: float, interval_s: float = 20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
            last = resp["DBClusters"][0]["Status"]
        except ClientError:
            last = None
        if last in ("available", "failed", "incompatible-restore"):
            return last
        time.sleep(interval_s)
    return last


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
    """Delete a subnet group, retrying while a resource that is being deleted still uses it.

    The 1500 s window fits this suite's 1800 s teardown budget: SimParityProbe verify passes
    budget.cleanup_timeout (rds and elasticache: 1800 s) to the engine as cleanup_timeout_s, in
    place of DEFAULT_CLEANUP_TIMEOUT_S.
    """
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
