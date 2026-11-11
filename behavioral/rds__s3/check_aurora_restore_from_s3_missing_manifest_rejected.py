"""aurora-restore-from-s3-missing-manifest-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aurora-restore-from-s3-missing-manifest-rejected"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreDBInstanceFromS3 with a valid bucket and role but no Percona XtraBackup files is
    rejected synchronously with InvalidS3BucketFault, and no DB instance is created."""
    bucket = _create_bucket(ctx)  # left empty: no backup files, no manifest
    role_arn = _create_import_role(ctx, bucket)

    rds = ctx.client("rds")
    bad_id = ctx.unique_name("sim2real-rds-s3import-bad-")
    password = "Sim2Real9!Import"
    code, message = _client_error(
        lambda: _restore_instance_with_retry(
            rds,
            DBInstanceIdentifier=bad_id,
            DBInstanceClass="db.t3.small",
            Engine="mysql",
            MasterUsername="sim2root",
            MasterUserPassword=password,
            AllocatedStorage=20,
            S3BucketName=bucket,
            S3IngestionRoleArn=role_arn,
            SourceEngine="mysql",
            SourceEngineVersion="5.7.40",
        )
    )
    assert code == "InvalidS3BucketFault", f"expected InvalidS3BucketFault, got {code!r}"
    assert message == (
        "No backup files were found in the specified Amazon S3 bucket. "
        "Check the bucket name or create backup files and try again."
    ), f"unexpected InvalidS3BucketFault message: {message!r}"

    # Effect absent: the instance was never created.
    missing_code, missing_message = _client_error(lambda: rds.describe_db_instances(DBInstanceIdentifier=bad_id))
    assert missing_code == "DBInstanceNotFound", (
        f"instance should never have been created after rejection, got code={missing_code!r}"
    )
    assert missing_message == f"DBInstance {bad_id} not found.", (
        f"unexpected DBInstanceNotFound message: {missing_message!r}"
    )

    # Positive control: a plain (non-S3) instance creation succeeds, so the rejection is not
    # an inability to create instances at all. A valid manifest needs real XtraBackup output,
    # so the S3-import happy path is a separate check.
    good_id = ctx.unique_name("sim2real-rds-s3import-good-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=good_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2root",
        MasterUserPassword=password,
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(DBInstanceIdentifier=good_id, SkipFinalSnapshot=True))

    def good_probe():
        return rds.describe_db_instances(DBInstanceIdentifier=good_id)["DBInstances"][0]

    _poll_until(good_probe, lambda i: i["DBInstanceStatus"] == "available", timeout_s=1800.0, interval_s=20.0)

    # Independent list-read at the destination: the available instance must be
    # discoverable by listing, not only by a targeted describe-by-id.
    listed_ids = {
        inst["DBInstanceIdentifier"]
        for page in rds.get_paginator("describe_db_instances").paginate()
        for inst in page["DBInstances"]
    }
    assert good_id in listed_ids, f"{good_id!r} not found via describe_db_instances() list, got {listed_ids!r}"


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, name) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _create_import_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-rds-import-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    pol_name = ctx.unique_name("sim2real-rds-import-policy-")
    iam.put_role_policy(RoleName=name, PolicyName=pol_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=pol_name))
    return role["Arn"]


def _restore_instance_with_retry(rds, **kwargs) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    while True:
        try:
            rds.restore_db_instance_from_s3(**kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidParameterValue",) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    Cleanups run LIFO, so this runs after the instance delete."""
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
