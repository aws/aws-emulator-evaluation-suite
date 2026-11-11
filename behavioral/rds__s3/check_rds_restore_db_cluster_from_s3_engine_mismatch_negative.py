"""rds-restore-db-cluster-from-s3-engine-mismatch-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-restore-db-cluster-from-s3-engine-mismatch-negative"
GROUP = "data-format"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreDBClusterFromS3 rejects a SourceEngine other than 'mysql' with
    InvalidParameterCombination and creates no cluster, while the same request with 'mysql' is
    accepted."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="backup/placeholder.txt", Body=b"placeholder")
    role_arn = _create_ingestion_role(ctx, iam, bucket)

    bad_cluster_id = ctx.unique_name("sim2real-rds-badengine-").lower()

    def _attempt():
        rds.restore_db_cluster_from_s3(
            DBClusterIdentifier=bad_cluster_id,
            Engine="aurora-mysql",
            MasterUsername="admin",
            MasterUserPassword="Sim2RealTest12345!",
            S3BucketName=bucket,
            S3IngestionRoleArn=role_arn,
            SourceEngine="postgres",  # the only documented valid SourceEngine is "mysql"
            SourceEngineVersion="8.0.32",
            DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
        )

    code, message = _error_detail(_attempt)
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code}"
    assert message == "You can't restore to aurora-mysql from an S3 backup of postgres.", message

    # effect absent: no cluster was created under that identifier
    not_found_code, not_found_message = _error_detail(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=bad_cluster_id)
    )
    assert not_found_code == "DBClusterNotFoundFault", f"unexpected code: {not_found_code}"
    assert not_found_message == f"DBCluster {bad_cluster_id} not found.", not_found_message

    # positive control: identical request with the one valid SourceEngine value is accepted
    control_cluster_id = ctx.unique_name("sim2real-rds-goodengine-").lower()
    ctx.on_cleanup(lambda: _cleanup_cluster(rds, control_cluster_id))
    _restore_expect_success_eventually(
        rds,
        timeout_s=150.0,
        DBClusterIdentifier=control_cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword="Sim2RealTest12345!",
        S3BucketName=bucket,
        S3IngestionRoleArn=role_arn,
        SourceEngine="mysql",
        SourceEngineVersion="8.0.32",
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    resp = rds.describe_db_clusters(DBClusterIdentifier=control_cluster_id)
    status = resp["DBClusters"][0]["Status"]
    assert status in ("creating", "available"), (
        f"expected control cluster with valid SourceEngine='mysql' to be creating/available, "
        f"got status={status!r}"
    )




def _error_detail(fn) -> tuple[str, str]:
    """Call fn() and return its botocore (code, message). An unexpected SUCCESS raises, so a
    target accepting a call real AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-rds-s3-").lower()
    if ctx.region == "us-east-1":
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
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


def _restore_expect_success_eventually(rds, timeout_s: float = 150.0, **kwargs):
    # New IAM roles/policies are eventually consistent: until RDS can see them it reports
    # InvalidS3BucketFault or an InvalidParameterValue naming the role/bucket (wording varies),
    # so retry that family for a bounded window.
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
